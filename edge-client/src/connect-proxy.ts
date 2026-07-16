import { createServer, type IncomingMessage, type Server } from "node:http";
import type { Duplex } from "node:stream";

import {
  DestinationValidationError,
  type AllowedDestination,
  type ResourceLimits,
  type ValidatedDestination,
  validateDestination
} from "@remote-codex/shared";

export const LOOPBACK_LISTEN_HOST = "127.0.0.1" as const;

const CONNECT_SUCCESS_RESPONSE = "HTTP/1.1 200 Connection Established\r\n\r\n";
const CONNECT_BAD_REQUEST_RESPONSE = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const CONNECT_DESTINATION_DENIED_RESPONSE = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const CONNECT_GATEWAY_FAILED_RESPONSE = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const CONNECT_OPEN_TIMEOUT_RESPONSE = "HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

export type EdgeStreamEvent =
  | { readonly type: "opened" }
  | { readonly type: "rejected" }
  | { readonly type: "error" }
  | { readonly type: "close" }
  | { readonly type: "data"; readonly payload: Uint8Array }
  | { readonly type: "writable" };

export type EdgeStreamEventListener = (event: EdgeStreamEvent) => void;

/**
 * 这是 edge 本地代理与后续 WSS 会话之间唯一的边界。stream 由 gateway 所有；
 * 代理既不接触 capability，也不解释任何隧道 payload。
 */
export interface EdgeStreamControl {
  /** 向已 opened 的隧道写入不透明字节；返回 false 时暂停本地读取，直到 writable。 */
  send(payload: Uint8Array): boolean;
  /** 停止接收 server/agent 下行字节，供本地 socket 背压使用。 */
  pauseIncoming(): void;
  /** 本地 socket drain 后恢复接收下行字节。 */
  resumeIncoming(): void;
  /** 幂等释放 stream；实现必须在本地 socket 先关闭时调用它。 */
  close(): void;
}

export interface EdgeStreamGateway {
  /**
   * 返回时监听器已经注册。gateway 只可通过 listener 报告 opened、rejected、
   * error、close、data 与 writable，绝不能把其他 stream 的事件交给该监听器。
   */
  open(destination: ValidatedDestination, listener: EdgeStreamEventListener): EdgeStreamControl;
}

export interface LoopbackConnectProxyOptions {
  readonly allowedDestination: AllowedDestination;
  readonly limits: Pick<ResourceLimits, "maxConcurrentStreams" | "openTimeoutMs">;
  readonly streamGateway: EdgeStreamGateway;
  /** 仅测试可使用 0 请求临时端口；生产配置必须使用 `EdgeClientConfig.listenPort`。 */
  readonly listenPort?: number;
}

export interface LoopbackConnectProxyAddress {
  readonly host: typeof LOOPBACK_LISTEN_HOST;
  readonly port: number;
}

type ActivePhase = "opening" | "open" | "closed";

interface ActiveConnect {
  readonly socket: Duplex;
  readonly stream: EdgeStreamControl;
  readonly onSocketData: (payload: Buffer) => void;
  readonly onSocketDrain: () => void;
  readonly onSocketReadable: () => void;
  readonly onSocketEnd: () => void;
  readonly onSocketClose: () => void;
  readonly onSocketError: () => void;
  phase: ActivePhase;
  openTimer: NodeJS.Timeout | undefined;
  streamIncomingPaused: boolean;
  socketReadPaused: boolean;
}

function isLoopbackRemoteAddress(socket: Duplex): boolean {
  const remoteAddress = "remoteAddress" in socket ? socket.remoteAddress : undefined;
  return remoteAddress === LOOPBACK_LISTEN_HOST;
}

function isSafePort(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= 65_535;
}

function hasForbiddenConnectHeaders(request: IncomingMessage): boolean {
  const forbiddenHeaders = new Set([
    "authorization",
    "proxy-authorization",
    "proxy-connection",
    "content-length",
    "transfer-encoding",
    "upgrade",
    "expect"
  ]);

  for (const [name, value] of Object.entries(request.headers)) {
    if (value !== undefined && forbiddenHeaders.has(name)) {
      return true;
    }
  }

  const connection = request.headers.connection;
  return typeof connection === "string" && connection.toLowerCase().split(",").some((value) => value.trim() === "upgrade");
}

function parseConnectDestination(request: IncomingMessage, allowedDestination: AllowedDestination): ValidatedDestination | undefined {
  if (request.method !== "CONNECT" || request.httpVersion !== "1.1" || hasForbiddenConnectHeaders(request)) {
    return undefined;
  }

  const authority = request.url;
  const authorityMatch = /^([^\s/:?#@\\]+):(443)$/u.exec(authority ?? "");

  if (authorityMatch === null) {
    return undefined;
  }

  try {
    return validateDestination(authorityMatch[1], 443, allowedDestination);
  } catch (error: unknown) {
    if (error instanceof DestinationValidationError) {
      return undefined;
    }

    throw error;
  }
}

function endWithFixedResponse(socket: Duplex, response: string): void {
  if (socket.destroyed) {
    return;
  }

  try {
    socket.end(response);
  } catch {
    socket.destroy();
  }
}

/**
 * 只提供 HTTP CONNECT 的 IPv4 loopback 代理。该类始终用固定 host listen，
 * 即使调用方给出其他 host 也没有配置入口可改变这个边界。
 */
export class LoopbackConnectProxy {
  private readonly allowedDestination: AllowedDestination;
  private readonly limits: Pick<ResourceLimits, "maxConcurrentStreams" | "openTimeoutMs">;
  private readonly streamGateway: EdgeStreamGateway;
  private readonly listenPort: number;
  private readonly server: Server;
  private readonly activeConnects = new Set<ActiveConnect>();
  private readonly acceptedSockets = new Set<Duplex>();
  private started = false;

  public constructor(options: LoopbackConnectProxyOptions) {
    if (!isSafePort(options.listenPort ?? 8_787)) {
      throw new TypeError("listenPort must be an integer between 0 and 65535");
    }

    if (
      !Number.isSafeInteger(options.limits.maxConcurrentStreams) ||
      options.limits.maxConcurrentStreams < 1 ||
      !Number.isSafeInteger(options.limits.openTimeoutMs) ||
      options.limits.openTimeoutMs < 1
    ) {
      throw new TypeError("loopback proxy limits are invalid");
    }

    this.allowedDestination = options.allowedDestination;
    this.limits = options.limits;
    this.streamGateway = options.streamGateway;
    this.listenPort = options.listenPort ?? 8_787;
    this.server = createServer();
    this.server.headersTimeout = Math.max(1_000, this.limits.openTimeoutMs);
    this.server.requestTimeout = this.server.headersTimeout;
    this.server.on("connection", (socket) => this.handleConnection(socket));
    this.server.on("connect", (request, socket, head) => this.handleConnect(request, socket, head));
    this.server.on("request", (_request, response) => {
      response.writeHead(405, { Connection: "close", "Content-Length": "0" });
      response.end();
    });
    this.server.on("upgrade", (_request, socket) => endWithFixedResponse(socket, CONNECT_BAD_REQUEST_RESPONSE));
    this.server.on("checkContinue", (_request, response) => {
      response.writeHead(400, { Connection: "close", "Content-Length": "0" });
      response.end();
    });
    this.server.on("clientError", (_error, socket) => endWithFixedResponse(socket, CONNECT_BAD_REQUEST_RESPONSE));
  }

  public async start(): Promise<LoopbackConnectProxyAddress> {
    if (this.started) {
      return this.address();
    }

    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => {
        this.server.off("listening", onListening);
        reject(error);
      };
      const onListening = (): void => {
        this.server.off("error", onError);
        resolve();
      };

      this.server.once("error", onError);
      this.server.once("listening", onListening);
      this.server.listen({ host: LOOPBACK_LISTEN_HOST, port: this.listenPort, ipv6Only: false });
    });
    this.started = true;
    return this.address();
  }

  public async stop(): Promise<void> {
    for (const active of [...this.activeConnects]) {
      this.finish(active, true);
      active.socket.destroy();
    }
    for (const socket of this.acceptedSockets) {
      socket.destroy();
    }

    if (!this.started) {
      return;
    }

    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
    this.started = false;
  }

  public address(): LoopbackConnectProxyAddress {
    const address = this.server.address();

    if (address === null || typeof address === "string") {
      throw new Error("loopback proxy is not listening");
    }

    return { host: LOOPBACK_LISTEN_HOST, port: address.port };
  }

  private handleConnection(socket: Duplex): void {
    if (!isLoopbackRemoteAddress(socket)) {
      socket.destroy();
      return;
    }

    this.acceptedSockets.add(socket);
    socket.once("close", () => this.acceptedSockets.delete(socket));
  }

  private handleConnect(request: IncomingMessage, socket: Duplex, head: Buffer): void {
    if (!isLoopbackRemoteAddress(socket)) {
      socket.destroy();
      return;
    }

    if (head.byteLength > 0) {
      endWithFixedResponse(socket, CONNECT_BAD_REQUEST_RESPONSE);
      return;
    }

    const destination = parseConnectDestination(request, this.allowedDestination);

    if (destination === undefined) {
      endWithFixedResponse(socket, CONNECT_DESTINATION_DENIED_RESPONSE);
      return;
    }

    if (this.activeConnects.size >= this.limits.maxConcurrentStreams) {
      endWithFixedResponse(socket, CONNECT_GATEWAY_FAILED_RESPONSE);
      return;
    }

    socket.pause();
    const activeRef: { value: ActiveConnect | undefined } = { value: undefined };
    const initialEvents: EdgeStreamEvent[] = [];
    const listener: EdgeStreamEventListener = (event) => {
      const current = activeRef.value;
      if (current === undefined) {
        initialEvents.push(event);
        return;
      }

      this.handleStreamEvent(current, event);
    };

    let stream: EdgeStreamControl;
    try {
      stream = this.streamGateway.open(destination, listener);
    } catch {
      endWithFixedResponse(socket, CONNECT_GATEWAY_FAILED_RESPONSE);
      return;
    }

    const active = this.createActiveConnect(socket, stream);
    activeRef.value = active;
    this.activeConnects.add(active);
    active.openTimer = setTimeout(() => this.handleOpenTimeout(active), this.limits.openTimeoutMs);

    for (const event of initialEvents) {
      this.handleStreamEvent(active, event);
    }
  }

  private createActiveConnect(socket: Duplex, stream: EdgeStreamControl): ActiveConnect {
    const active = {
      socket,
      stream,
      phase: "opening" as const,
      openTimer: undefined,
      streamIncomingPaused: false,
      socketReadPaused: true,
      onSocketData: (payload: Buffer): void => this.handleSocketData(active, payload),
      onSocketDrain: (): void => this.handleSocketDrain(active),
      onSocketReadable: (): void => this.handleSocketReadable(active),
      onSocketEnd: (): void => this.handleSocketEnd(active),
      onSocketClose: (): void => this.finish(active, true),
      onSocketError: (): void => this.finish(active, true)
    } satisfies ActiveConnect;

    socket.on("data", active.onSocketData);
    socket.on("drain", active.onSocketDrain);
    socket.on("readable", active.onSocketReadable);
    socket.on("end", active.onSocketEnd);
    socket.on("close", active.onSocketClose);
    socket.on("error", active.onSocketError);
    return active;
  }

  private handleStreamEvent(active: ActiveConnect, event: EdgeStreamEvent): void {
    if (active.phase === "closed") {
      return;
    }

    switch (event.type) {
      case "opened":
        this.handleStreamOpened(active);
        return;
      case "data":
        this.handleStreamData(active, event.payload);
        return;
      case "writable":
        this.handleStreamWritable(active);
        return;
      case "rejected":
      case "error":
        this.handleStreamFailure(active, CONNECT_GATEWAY_FAILED_RESPONSE);
        return;
      case "close":
        this.handleStreamClose(active);
    }
  }

  private handleStreamOpened(active: ActiveConnect): void {
    if (active.phase !== "opening" || active.socket.destroyed) {
      this.finish(active, true);
      return;
    }

    this.clearOpenTimer(active);
    active.phase = "open";
    try {
      active.socket.off("readable", active.onSocketReadable);
      active.socket.write(CONNECT_SUCCESS_RESPONSE);
      active.socket.resume();
      active.socketReadPaused = false;
    } catch {
      this.finish(active, true);
    }
  }

  private handleStreamData(active: ActiveConnect, payload: Uint8Array): void {
    if (active.phase !== "open" || payload.byteLength === 0) {
      this.handleStreamFailure(active, CONNECT_GATEWAY_FAILED_RESPONSE);
      return;
    }

    try {
      if (active.socket.write(payload)) {
        return;
      }

      active.stream.pauseIncoming();
      active.streamIncomingPaused = true;
    } catch {
      this.finish(active, true);
    }
  }

  private handleStreamWritable(active: ActiveConnect): void {
    if (active.phase !== "open" || !active.socketReadPaused) {
      return;
    }

    try {
      active.socket.resume();
      active.socketReadPaused = false;
    } catch {
      this.finish(active, true);
    }
  }

  private handleStreamClose(active: ActiveConnect): void {
    if (active.phase === "opening") {
      this.handleStreamFailure(active, CONNECT_GATEWAY_FAILED_RESPONSE);
      return;
    }

    this.finish(active, false);
    if (!active.socket.destroyed) {
      active.socket.end();
    }
  }

  private handleStreamFailure(active: ActiveConnect, response: string): void {
    if (active.phase === "opening") {
      this.finish(active, true);
      endWithFixedResponse(active.socket, response);
      return;
    }

    this.finish(active, true);
    active.socket.destroy();
  }

  private handleOpenTimeout(active: ActiveConnect): void {
    if (active.phase === "opening") {
      this.finish(active, true);
      endWithFixedResponse(active.socket, CONNECT_OPEN_TIMEOUT_RESPONSE);
    }
  }

  private handleSocketData(active: ActiveConnect, payload: Buffer): void {
    if (active.phase !== "open" || payload.byteLength === 0) {
      this.handleStreamFailure(active, CONNECT_BAD_REQUEST_RESPONSE);
      return;
    }

    try {
      if (active.stream.send(Uint8Array.from(payload))) {
        return;
      }

      active.socket.pause();
      active.socketReadPaused = true;
    } catch {
      this.finish(active, true);
    }
  }

  private handleSocketDrain(active: ActiveConnect): void {
    if (active.phase !== "open" || !active.streamIncomingPaused) {
      return;
    }

    try {
      active.stream.resumeIncoming();
      active.streamIncomingPaused = false;
    } catch {
      this.finish(active, true);
    }
  }

  /** CONNECT 成功前到达的独立 TCP 字节同样不是合法请求内容。 */
  private handleSocketReadable(active: ActiveConnect): void {
    if (active.phase === "opening" && active.socket.readableLength > 0) {
      this.handleStreamFailure(active, CONNECT_BAD_REQUEST_RESPONSE);
    }
  }

  private handleSocketEnd(active: ActiveConnect): void {
    this.finish(active, true);
    // CONNECT 不保留可在后续 WSS 会话重用的半关闭 socket；客户端 EOF 后立即
    // 回收本地 TCP 端，避免 server.stop() 被遗留可写连接阻塞。
    active.socket.destroy();
  }

  private finish(active: ActiveConnect, closeStream: boolean): void {
    if (active.phase === "closed") {
      return;
    }

    active.phase = "closed";
    this.clearOpenTimer(active);
    this.activeConnects.delete(active);
    active.socket.off("data", active.onSocketData);
    active.socket.off("drain", active.onSocketDrain);
    active.socket.off("readable", active.onSocketReadable);
    active.socket.off("end", active.onSocketEnd);
    active.socket.off("close", active.onSocketClose);
    active.socket.off("error", active.onSocketError);

    if (closeStream) {
      try {
        active.stream.close();
      } catch {
        // stream 实现异常时，本地映射已经先清理，不能残留可复用的 socket。
      }
    }
  }

  private clearOpenTimer(active: ActiveConnect): void {
    if (active.openTimer !== undefined) {
      clearTimeout(active.openTimer);
      active.openTimer = undefined;
    }
  }
}
