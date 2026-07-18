import { randomBytes as nodeRandomBytes } from "node:crypto";

import {
  assertTlsVerificationEnabled,
  connectionFrame,
  createStreamId,
  decodeChallengePayload,
  decodeFrame,
  decodeFramePayload,
  encodeAuthenticatePayload,
  encodeFrame,
  encodeHeartbeatPayload,
  encodeRegisterPayload,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
  encodeStreamOpenPayload,
  FrameType,
  IdentityKeyRole,
  parseEdgeClientConfig,
  signAuthenticationChallenge,
  StreamBufferBudget,
  StreamCloseCode,
  StreamLifecycle,
  streamFrame,
  validateDestination,
  type EdgeClientConfig,
  type EdgeDeviceIdentity,
  type IdentityPrivateKey,
  type RegisterPayload,
  type TunnelFrame,
  type ValidatedDestination
} from "@remote-codex/shared";
import WebSocket from "ws";
import type { RawData } from "ws";

import type { EdgeStreamControl, EdgeStreamEvent, EdgeStreamEventListener, EdgeStreamGateway } from "./connect-proxy.js";

const WEBSOCKET_CLOSE_CODE_PROTOCOL = 1002;
const AUTHENTICATION_FAILURE_CODES = new Set(["AUTH_FAILED", "AUTH_EXPIRED", "AUTH_REPLAYED", "AUTH_UNAUTHORIZED"]);
// 固定、非空且故意短于 capability 最小编码长度的无授权哨兵。它不从 edge 身份或
// 配置派生，无法通过 `verifyCapability`，也不会被记录；server 会丢弃并重签发。
const EDGE_STREAM_OPEN_PLACEHOLDER_CAPABILITY = Uint8Array.of(0);

export type EdgeClientState = "offline" | "connecting" | "authenticating" | "online" | "closing" | "backoff" | "stopped";

export interface EdgeClientStatusSnapshot {
  readonly state: EdgeClientState;
  readonly reconnectAttempts: number;
  readonly lastErrorCode?: string;
}

export type EdgeClientStatusListener = (status: EdgeClientStatusSnapshot) => void;

/** WSS 的最小受控表面，不向本地 CONNECT 前端暴露认证材料或连接对象。 */
export interface EdgeSocket {
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  onOpen(listener: () => void): void;
  onMessage(listener: (data: Uint8Array | undefined, isBinary: boolean) => void): void;
  onClose(listener: (code: number, reason: string) => void): void;
  onError(listener: () => void): void;
  getSendBufferedBytes?(): number;
  onSendAvailability?(listener: () => void): () => void;
}

export interface EdgeSocketFactory {
  connect(serverUrl: URL, origin: string): EdgeSocket;
}

export interface EdgeClientRuntimeOptions {
  /** 本地部署加载并严格解析的配置，不能由服务端帧或 CONNECT 请求修改。 */
  readonly config: EdgeClientConfig;
  /** 与本地 user/device 配置精确匹配的 edge 身份。 */
  readonly authenticationIdentity: EdgeDeviceIdentity;
  /** 仅用于服务端 challenge 签名的私钥，永不写入 URL、日志或代理接口。 */
  readonly authenticationKey: IdentityPrivateKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
  /**
   * 由已验证 WSS endpoint 确定的 HTTPS Origin。它只参与 server 握手来源策略，
   * 不能替代 edge user/device 的 challenge 签名认证。
   */
  readonly origin?: string;
  readonly socketFactory?: EdgeSocketFactory;
  readonly now?: () => number;
  readonly random?: () => number;
  readonly randomBytes?: (size: number) => Uint8Array;
}

interface ConnectionFailure {
  readonly code: string;
  readonly terminal: boolean;
}

type ConnectionPhase = "connecting" | "awaiting-challenge" | "awaiting-confirmation" | "online" | "closing";

interface EdgeConnection {
  readonly socket: EdgeSocket;
  phase: ConnectionPhase;
  registration: RegisterPayload | undefined;
  failure: ConnectionFailure | undefined;
  finalized: boolean;
  authenticationTimer: ReturnType<typeof setTimeout> | undefined;
  unsubscribeSendAvailability: (() => void) | undefined;
}

interface ActiveEdgeStream {
  readonly key: string;
  readonly streamId: Uint8Array;
  readonly connection: EdgeConnection;
  readonly lifecycle: StreamLifecycle;
  readonly listener: EdgeStreamEventListener;
  readonly pendingOutboundData: TunnelFrame[];
  pendingOutboundDataBytes: number;
  pendingReceiveCreditBytes: number;
  incomingPaused: boolean;
  active: boolean;
}

export class EdgeClientRuntimeError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "EdgeClientRuntimeError";
  }
}

function fail(code: string): never {
  throw new EdgeClientRuntimeError(code);
}

function rawDataToBytes(data: RawData): Uint8Array | undefined {
  if (data instanceof Buffer) {
    return Uint8Array.from(data);
  }

  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data.slice(0));
  }

  if (Array.isArray(data)) {
    return Uint8Array.from(Buffer.concat(data));
  }

  return undefined;
}

function safeCloseReason(reason: Buffer): string {
  const decoded = reason.toString("utf8");
  return /^[A-Z_]{1,64}$/u.test(decoded) ? decoded : "WSS_DISCONNECTED";
}

function streamKey(streamId: Uint8Array): string {
  if (streamId.byteLength !== 16) {
    return fail("EDGE_STREAM_ID_INVALID");
  }

  return Buffer.from(streamId).toString("hex");
}

function normalizedConfig(config: EdgeClientConfig): EdgeClientConfig {
  return parseEdgeClientConfig({
    component: config.component,
    edgeUserId: config.edgeUserId,
    edgeDeviceId: config.edgeDeviceId,
    serverUrl: config.serverUrl.href,
    listenHost: config.listenHost,
    listenPort: config.listenPort,
    allowedDestination: {
      hostname: config.allowedDestination.hostname,
      port: config.allowedDestination.port
    },
    limits: { ...config.limits }
  });
}

function closeCodeIsAuthenticationFailure(code: string): boolean {
  return AUTHENTICATION_FAILURE_CODES.has(code);
}

function timerUnref(timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>): void {
  if (typeof timer === "object" && "unref" in timer && typeof timer.unref === "function") {
    timer.unref();
  }
}

/** 计算上限受配置约束的指数退避，抖动范围为基数的 [50%, 100%]。 */
export function calculateEdgeReconnectDelayMs(
  reconnectAttempt: number,
  limits: Pick<EdgeClientConfig["limits"], "reconnectInitialMs" | "reconnectMaxMs">,
  random: () => number = Math.random
): number {
  if (!Number.isSafeInteger(reconnectAttempt) || reconnectAttempt < 1) {
    return fail("EDGE_RECONNECT_ATTEMPT_INVALID");
  }

  const randomValue = random();
  if (!Number.isFinite(randomValue) || randomValue < 0 || randomValue > 1) {
    return fail("EDGE_RECONNECT_JITTER_INVALID");
  }

  const exponent = reconnectAttempt - 1;
  const uncappedDelay = exponent > 52 ? Number.MAX_SAFE_INTEGER : limits.reconnectInitialMs * 2 ** exponent;
  const cappedDelay = Math.min(limits.reconnectMaxMs, uncappedDelay);
  return Math.max(1, Math.floor(cappedDelay * (0.5 + randomValue * 0.5)));
}

/** 从本地配置文本加载 edge 配置；设备认证私钥必须由独立受控接口提供。 */
export function loadEdgeClientConfig(serializedConfig: string): EdgeClientConfig {
  try {
    return parseEdgeClientConfig(JSON.parse(serializedConfig) as unknown);
  } catch (error: unknown) {
    if (error instanceof EdgeClientRuntimeError) {
      throw error;
    }

    return fail("EDGE_CONFIG_LOAD_FAILED");
  }
}

class WsEdgeSocket implements EdgeSocket {
  private readonly sendAvailabilityListeners = new Set<() => void>();

  public constructor(private readonly socket: WebSocket) {}

  public send(data: Uint8Array): void {
    this.socket.send(data, { binary: true }, () => this.notifySendAvailability());
  }

  public close(code?: number, reason?: string): void {
    this.socket.close(code, reason);
  }

  public onOpen(listener: () => void): void {
    this.socket.once("open", listener);
  }

  public onMessage(listener: (data: Uint8Array | undefined, isBinary: boolean) => void): void {
    this.socket.on("message", (data: RawData, isBinary: boolean) => listener(rawDataToBytes(data), isBinary));
  }

  public onClose(listener: (code: number, reason: string) => void): void {
    this.socket.once("close", (code: number, reason: Buffer) => listener(code, safeCloseReason(reason)));
  }

  public onError(listener: () => void): void {
    this.socket.once("error", listener);
  }

  public getSendBufferedBytes(): number {
    return this.socket.bufferedAmount;
  }

  public onSendAvailability(listener: () => void): () => void {
    this.sendAvailabilityListeners.add(listener);
    return (): void => {
      this.sendAvailabilityListeners.delete(listener);
    };
  }

  private notifySendAvailability(): void {
    for (const listener of this.sendAvailabilityListeners) {
      try {
        listener();
      } catch {
        // 本地 stream 调度不能影响认证 WSS 的关闭与重连状态机。
      }
    }
  }
}

class DefaultEdgeSocketFactory implements EdgeSocketFactory {
  public connect(serverUrl: URL, origin: string): EdgeSocket {
    return new WsEdgeSocket(new WebSocket(serverUrl, { origin, perMessageDeflate: false }));
  }
}

function parseOrigin(origin: string): string {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return fail("EDGE_ORIGIN_INVALID");
  }

  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== origin ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.search.length > 0 ||
    parsed.hash.length > 0
  ) {
    return fail("EDGE_ORIGIN_INVALID");
  }
  return origin;
}

/** 非浏览器 WSS 客户端固定发送与唯一 server endpoint 对应的 HTTPS Origin。 */
export function edgeOriginForServerUrl(serverUrl: URL): string {
  if (serverUrl.protocol !== "wss:") {
    return fail("EDGE_ORIGIN_INVALID");
  }
  return parseOrigin(`https://${serverUrl.host}`);
}

/**
 * edge WSS 会话和 CONNECT stream 的唯一实现。所有本地连接均与当前连接对象
 * 绑定；会话失效时无条件关闭它们，绝不把旧 stream 或服务端 capability 留给重连。
 */
export class EdgeClientRuntime implements EdgeStreamGateway {
  private readonly config: EdgeClientConfig;
  private readonly authenticationIdentity: EdgeDeviceIdentity;
  private readonly authenticationKey: IdentityPrivateKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
  private readonly origin: string;
  private readonly socketFactory: EdgeSocketFactory;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly randomBytes: (size: number) => Uint8Array;
  private readonly statusListeners = new Set<EdgeClientStatusListener>();
  private readonly streams = new Map<string, ActiveEdgeStream>();
  private readonly bufferBudget: StreamBufferBudget;
  private readonly pendingQueueBudget: StreamBufferBudget;
  private activeConnection: EdgeConnection | undefined;
  private heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  private reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  private state: EdgeClientState = "offline";
  private reconnectAttempts = 0;
  private lastErrorCode: string | undefined;
  private heartbeatSequence = 0;
  private stopped = false;

  public constructor(options: EdgeClientRuntimeOptions) {
    this.config = normalizedConfig(options.config);
    this.authenticationIdentity = options.authenticationIdentity;
    this.authenticationKey = options.authenticationKey;
    this.origin = parseOrigin(options.origin ?? edgeOriginForServerUrl(this.config.serverUrl));
    this.socketFactory = options.socketFactory ?? new DefaultEdgeSocketFactory();
    this.now = options.now ?? Date.now;
    this.random = options.random ?? Math.random;
    this.randomBytes = options.randomBytes ?? ((size: number) => Uint8Array.from(nodeRandomBytes(size)));
    this.bufferBudget = new StreamBufferBudget(this.config.limits);
    this.pendingQueueBudget = new StreamBufferBudget(this.config.limits);

    if (
      this.authenticationIdentity.kind !== "edge-device" ||
      this.authenticationIdentity.edgeUserId !== this.config.edgeUserId ||
      this.authenticationIdentity.edgeDeviceId !== this.config.edgeDeviceId ||
      this.authenticationKey.role !== IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION
    ) {
      fail("EDGE_DEVICE_IDENTITY_INVALID");
    }
  }

  /** 启动幂等；TLS 证书验证被显式禁用时在建立 WSS 前拒绝启动。 */
  public start(): void {
    if (this.stopped) {
      fail("EDGE_RUNTIME_STOPPED");
    }

    if (this.activeConnection !== undefined || this.reconnectTimer !== undefined) {
      return;
    }

    assertTlsVerificationEnabled(process.env);
    this.connect();
  }

  /** 停止后实例不能复用；所有待建立和已建立的 CONNECT 映射均立即无效。 */
  public stop(): void {
    if (this.stopped) {
      return;
    }

    this.stopped = true;
    this.clearReconnectTimer();
    this.clearHeartbeatTimer();
    const connection = this.activeConnection;
    this.activeConnection = undefined;

    if (connection !== undefined) {
      connection.finalized = true;
      this.clearAuthenticationTimer(connection);
      connection.unsubscribeSendAvailability?.();
      try {
        connection.socket.close();
      } catch {
        // socket 已经关闭时仍须继续释放所有本地 stream。
      }
    }

    this.closeAllStreams("error");
    this.transition("stopped");
  }

  public getStatus(): EdgeClientStatusSnapshot {
    return Object.freeze({
      state: this.state,
      reconnectAttempts: this.reconnectAttempts,
      ...(this.lastErrorCode === undefined ? {} : { lastErrorCode: this.lastErrorCode })
    });
  }

  public get activeStreamCount(): number {
    return this.streams.size;
  }

  public getLocalPolicy(): Readonly<{
    edgeUserId: string;
    edgeDeviceId: string;
    maxConcurrentStreams: number;
    allowedDestination: Readonly<{ hostname: string; port: 443 }>;
  }> {
    return Object.freeze({
      edgeUserId: this.config.edgeUserId,
      edgeDeviceId: this.config.edgeDeviceId,
      maxConcurrentStreams: this.config.limits.maxConcurrentStreams,
      allowedDestination: Object.freeze({ ...this.config.allowedDestination })
    });
  }

  public subscribeStatus(listener: EdgeClientStatusListener): () => void {
    this.statusListeners.add(listener);
    try {
      listener(this.getStatus());
    } catch {
      // 状态观察者无权影响认证或本地 stream 的释放。
    }

    return (): void => {
      this.statusListeners.delete(listener);
    };
  }

  /**
   * CONNECT 前端调用的唯一开流入口。离线、超额或目标不匹配都以确定性本地
   * 失败结束，不生成可在之后 WSS 会话上重用的 pending stream。
   */
  public open(destination: ValidatedDestination, listener: EdgeStreamEventListener): EdgeStreamControl {
    const connection = this.activeConnection;
    if (connection === undefined || connection.phase !== "online" || this.stopped) {
      listener({ type: "error" });
      return this.rejectedControl();
    }

    try {
      validateDestination(destination.hostname, destination.port, this.config.allowedDestination);
    } catch {
      listener({ type: "rejected" });
      return this.rejectedControl();
    }

    if (this.streams.size >= this.config.limits.maxConcurrentStreams) {
      listener({ type: "rejected" });
      return this.rejectedControl();
    }

    const streamId = this.allocateStreamId();
    const key = streamKey(streamId);
    const lifecycle = new StreamLifecycle({
      streamId,
      sessionId: `edge:${key}`,
      limits: this.config.limits,
      bufferBudget: this.bufferBudget,
      now: this.now
    });
    const openFrame = streamFrame(
      FrameType.STREAM_OPEN,
      streamId,
      // edge 不持有 server capability；此固定无授权哨兵只满足统一 wire schema，
      // server 在转给 agent 前会以其签发且绑定当前 session 的 capability 完整替换。
      encodeStreamOpenPayload({
        hostname: destination.hostname,
        port: 443,
        capability: EDGE_STREAM_OPEN_PLACEHOLDER_CAPABILITY
      })
    );
    const opened = lifecycle.handleOutbound(openFrame, lifecycle.sessionId, this.now());
    const authorized = opened.accepted ? lifecycle.authorize(this.now()) : undefined;
    const connecting = authorized?.accepted ? lifecycle.beginConnecting(this.now()) : undefined;

    if (!opened.accepted || !authorized?.accepted || !connecting?.accepted) {
      listener({ type: "error" });
      return this.rejectedControl();
    }

    const active: ActiveEdgeStream = {
      key,
      streamId: Uint8Array.from(streamId),
      connection,
      lifecycle,
      listener,
      pendingOutboundData: [],
      pendingOutboundDataBytes: 0,
      pendingReceiveCreditBytes: 0,
      incomingPaused: false,
      active: true
    };
    this.streams.set(key, active);

    if (!this.sendFrame(connection, openFrame)) {
      this.closeConnection(connection, { code: "WSS_CONNECTION_FAILED", terminal: false });
      return this.rejectedControl();
    }

    return this.controlFor(active);
  }

  private connect(): void {
    if (this.stopped || this.activeConnection !== undefined) {
      return;
    }

    this.transition("connecting");
    let socket: EdgeSocket;
    try {
      socket = this.socketFactory.connect(this.config.serverUrl, this.origin);
    } catch {
      this.scheduleReconnect({ code: "WSS_CONNECTION_FAILED", terminal: false });
      return;
    }

    const connection: EdgeConnection = {
      socket,
      phase: "connecting",
      registration: undefined,
      failure: undefined,
      finalized: false,
      authenticationTimer: undefined,
      unsubscribeSendAvailability: undefined
    };
    this.activeConnection = connection;
    this.startAuthenticationTimer(connection);
    socket.onOpen(() => this.handleOpen(connection));
    socket.onMessage((data, isBinary) => this.handleMessage(connection, data, isBinary));
    socket.onClose((code, reason) => this.handleClose(connection, code, reason));
    socket.onError(() => this.handleError(connection));
  }

  private handleOpen(connection: EdgeConnection): void {
    if (!this.isActiveConnection(connection) || connection.phase !== "connecting") {
      return;
    }

    try {
      const registration: RegisterPayload = Object.freeze({
        role: "edge-client",
        peerId: this.config.edgeDeviceId,
        nonce: Uint8Array.from(this.randomBytes(32))
      });
      if (!this.sendFrame(connection, connectionFrame(FrameType.REGISTER, encodeRegisterPayload(registration)))) {
        throw new EdgeClientRuntimeError("WSS_CONNECTION_FAILED");
      }
      connection.registration = registration;
      connection.phase = "awaiting-challenge";
      this.transition("authenticating");
    } catch (error: unknown) {
      const code = error instanceof EdgeClientRuntimeError ? error.code : "AUTH_FAILED";
      this.closeConnection(connection, { code, terminal: closeCodeIsAuthenticationFailure(code) });
    }
  }

  private handleMessage(connection: EdgeConnection, data: Uint8Array | undefined, isBinary: boolean): void {
    if (!this.isActiveConnection(connection)) {
      return;
    }

    if (!isBinary || data === undefined) {
      this.closeConnection(connection, { code: "PROTOCOL_VIOLATION", terminal: false });
      return;
    }

    try {
      const frame = decodeFrame(data);
      const payload = decodeFramePayload(frame);

      if (frame.type === FrameType.CHALLENGE && connection.phase === "awaiting-challenge") {
        const challenge = decodeChallengePayload(frame.payload);
        if (challenge.issuedAtMs > this.now() || challenge.expiresAtMs <= this.now()) {
          throw new EdgeClientRuntimeError("AUTH_EXPIRED");
        }

        if (connection.registration === undefined) {
          throw new EdgeClientRuntimeError("AUTH_FAILED");
        }

        const proof = signAuthenticationChallenge({
          identity: this.authenticationIdentity,
          signingKey: this.authenticationKey,
          registration: connection.registration,
          challenge: { issuedAtMs: challenge.issuedAtMs, payload: challenge }
        });
        if (!this.sendFrame(connection, connectionFrame(FrameType.AUTHENTICATE, encodeAuthenticatePayload(proof)))) {
          throw new EdgeClientRuntimeError("WSS_CONNECTION_FAILED");
        }
        connection.phase = "awaiting-confirmation";
        return;
      }

      if (frame.type === FrameType.HEARTBEAT && connection.phase === "awaiting-confirmation") {
        if (payload === undefined || !("sequence" in payload)) {
          throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
        }

        connection.phase = "online";
        this.heartbeatSequence = payload.sequence;
        this.clearAuthenticationTimer(connection);
        try {
          connection.unsubscribeSendAvailability = connection.socket.onSendAvailability?.(() => this.flushStreams(connection));
        } catch {
          // 可选的 WSS 水位通知不可用时，仍由 credit 与本地预算维持安全上限。
          connection.unsubscribeSendAvailability = undefined;
        }
        this.transition("online");
        this.startHeartbeatTimer(connection);
        return;
      }

      if (frame.type === FrameType.HEARTBEAT && connection.phase === "online") {
        if (payload === undefined || !("sequence" in payload)) {
          throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
        }
        return;
      }

      if (connection.phase === "online" && frame.type >= FrameType.STREAM_OPEN) {
        this.handleStreamFrame(connection, frame);
        return;
      }

      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    } catch (error: unknown) {
      const code = error instanceof EdgeClientRuntimeError ? error.code : "PROTOCOL_VIOLATION";
      this.closeConnection(connection, { code, terminal: closeCodeIsAuthenticationFailure(code) });
    }
  }

  private handleStreamFrame(connection: EdgeConnection, frame: TunnelFrame): void {
    const active = this.streams.get(streamKey(frame.streamId));
    if (active === undefined || !active.active || active.connection !== connection) {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    switch (frame.type) {
      case FrameType.STREAM_OPENED:
        this.handleStreamOpened(active, frame);
        return;
      case FrameType.STREAM_REJECTED:
        this.handleStreamRejected(active, frame);
        return;
      case FrameType.STREAM_ERROR:
        this.handleStreamError(active, frame);
        return;
      case FrameType.STREAM_DATA:
        this.handleStreamData(active, frame);
        return;
      case FrameType.STREAM_CREDIT:
        this.handleStreamCredit(active, frame);
        return;
      case FrameType.STREAM_CLOSE:
        this.handleStreamClose(active, frame);
        return;
      default:
        throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }
  }

  private handleStreamOpened(active: ActiveEdgeStream, frame: TunnelFrame): void {
    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());
    if (!result.accepted || active.lifecycle.state !== "open") {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    this.notify(active, { type: "opened" });
    if (!this.isActiveStream(active)) {
      return;
    }

    active.pendingReceiveCreditBytes = active.lifecycle.pendingReceiveCreditBytes;
    this.flushStream(active);
  }

  private handleStreamRejected(active: ActiveEdgeStream, frame: TunnelFrame): void {
    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());
    if (!result.accepted) {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    this.removeStream(active, "rejected");
  }

  private handleStreamError(active: ActiveEdgeStream, frame: TunnelFrame): void {
    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());
    if (!result.accepted) {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    this.removeStream(active, "error");
  }

  private handleStreamData(active: ActiveEdgeStream, frame: TunnelFrame): void {
    const payload = decodeFramePayload(frame);
    if (!(payload instanceof Uint8Array) || payload.byteLength === 0 || !this.canBufferBytes(active, payload.byteLength)) {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());
    if (!result.accepted) {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    this.notify(active, { type: "data", payload });
    if (!this.isActiveStream(active)) {
      return;
    }

    const queued = active.lifecycle.queueReceiveCredit(payload.byteLength, this.now());
    if (!queued.accepted) {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    active.pendingReceiveCreditBytes += payload.byteLength;
    this.flushStream(active);
  }

  private handleStreamCredit(active: ActiveEdgeStream, frame: TunnelFrame): void {
    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());
    if (!result.accepted) {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    this.flushStream(active);
    if (this.isActiveStream(active) && this.canReadFromLocal(active)) {
      this.notify(active, { type: "writable" });
    }
  }

  private handleStreamClose(active: ActiveEdgeStream, frame: TunnelFrame): void {
    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());
    if (!result.accepted) {
      throw new EdgeClientRuntimeError("PROTOCOL_VIOLATION");
    }

    this.removeStream(active, "close");
  }

  private controlFor(active: ActiveEdgeStream): EdgeStreamControl {
    return Object.freeze({
      send: (payload: Uint8Array): boolean => this.sendFromLocal(active, payload),
      pauseIncoming: (): void => {
        if (this.isActiveStream(active)) {
          active.incomingPaused = true;
        }
      },
      resumeIncoming: (): void => {
        if (this.isActiveStream(active)) {
          active.incomingPaused = false;
          this.flushStream(active);
        }
      },
      close: (): void => this.closeFromLocal(active)
    });
  }

  private rejectedControl(): EdgeStreamControl {
    return Object.freeze({
      send: () => false,
      pauseIncoming: () => undefined,
      resumeIncoming: () => undefined,
      close: () => undefined
    });
  }

  private sendFromLocal(active: ActiveEdgeStream, payload: Uint8Array): boolean {
    if (!this.isActiveStream(active) || active.lifecycle.state !== "open" || payload.byteLength === 0) {
      this.closeFromLocal(active, StreamCloseCode.PROTOCOL_ERROR, "error");
      return false;
    }

    if (!this.canBufferBytes(active, payload.byteLength)) {
      this.closeFromLocal(active, StreamCloseCode.RESOURCE_LIMIT, "error");
      return false;
    }

    for (let offset = 0; offset < payload.byteLength; offset += this.config.limits.maxFramePayloadBytes) {
      const data = payload.subarray(offset, Math.min(offset + this.config.limits.maxFramePayloadBytes, payload.byteLength));
      if (!this.pendingQueueBudget.reserve(active.key, data.byteLength)) {
        this.closeFromLocal(active, StreamCloseCode.RESOURCE_LIMIT, "error");
        return false;
      }

      active.pendingOutboundData.push(streamFrame(FrameType.STREAM_DATA, active.streamId, data));
      active.pendingOutboundDataBytes += data.byteLength;
    }

    this.flushStream(active);
    return this.canReadFromLocal(active);
  }

  private closeFromLocal(
    active: ActiveEdgeStream,
    code: typeof StreamCloseCode[keyof typeof StreamCloseCode] = StreamCloseCode.NORMAL,
    event?: "error" | "close"
  ): void {
    if (!this.isActiveStream(active)) {
      return;
    }

    const requested = active.lifecycle.requestClose(code, this.now());
    if (requested.accepted) {
      const closeFrame = streamFrame(FrameType.STREAM_CLOSE, active.streamId, encodeStreamClosePayload({ code }));
      const sent = active.lifecycle.handleOutbound(closeFrame, active.lifecycle.sessionId, this.now());
      if (sent.accepted) {
        if (!this.sendFrame(active.connection, closeFrame)) {
          // 本地 close 期间的 WSS 发送失败表明当前会话已不可用。必须让同一
          // 会话的所有 pending/open stream 一起失效，不能只移除当前映射。
          this.closeConnection(active.connection, { code: "WSS_CONNECTION_FAILED", terminal: false });
          return;
        }
      }
    }

    this.removeStream(active, event);
  }

  private flushStreams(connection: EdgeConnection): void {
    if (!this.isActiveConnection(connection) || connection.phase !== "online") {
      return;
    }

    for (const active of [...this.streams.values()]) {
      if (active.connection === connection) {
        this.flushStream(active);
        if (this.isActiveStream(active) && this.canReadFromLocal(active)) {
          this.notify(active, { type: "writable" });
        }
      }
    }
  }

  /** 在单一事件循环轮次尽量清空当前流，避免 credit 仅发送一帧后永久停滞。 */
  private flushStream(active: ActiveEdgeStream): void {
    let remainingFrames = 1_024;
    while (remainingFrames > 0 && this.isActiveStream(active) && active.connection.phase === "online") {
      remainingFrames -= 1;

      if (active.pendingReceiveCreditBytes > 0 && !active.incomingPaused) {
        const credit = streamFrame(
          FrameType.STREAM_CREDIT,
          active.streamId,
          encodeStreamCreditPayload({ bytes: active.pendingReceiveCreditBytes })
        );
        if (this.shouldDelayForWss(active, credit.payload.byteLength)) {
          return;
        }

        const result = active.lifecycle.handleOutbound(credit, active.lifecycle.sessionId, this.now());
        if (!result.accepted || !this.sendFrame(active.connection, credit)) {
          this.closeConnection(active.connection, { code: "WSS_CONNECTION_FAILED", terminal: false });
          return;
        }

        active.pendingReceiveCreditBytes = 0;
        continue;
      }

      const frame = active.pendingOutboundData[0];
      if (frame === undefined || this.shouldDelayForWss(active, frame.payload.byteLength)) {
        return;
      }

      if (active.lifecycle.availableSendCreditBytes < frame.payload.byteLength) {
        return;
      }

      active.pendingOutboundData.shift();
      active.pendingOutboundDataBytes -= frame.payload.byteLength;
      this.pendingQueueBudget.release(active.key, frame.payload.byteLength);
      const result = active.lifecycle.handleOutbound(frame, active.lifecycle.sessionId, this.now());
      if (!result.accepted || !this.sendFrame(active.connection, frame)) {
        this.closeConnection(active.connection, { code: "WSS_CONNECTION_FAILED", terminal: false });
        return;
      }
    }
  }

  private canReadFromLocal(active: ActiveEdgeStream): boolean {
    return (
      this.isActiveStream(active) &&
      active.lifecycle.state === "open" &&
      active.pendingOutboundData.length === 0 &&
      active.lifecycle.canReadFromProducer &&
      !this.shouldDelayForWss(active, 1)
    );
  }

  private shouldDelayForWss(active: ActiveEdgeStream, nextPayloadBytes = 0): boolean {
    const bufferedBytes = this.getSendBufferedBytes(active.connection);
    return (
      bufferedBytes !== undefined &&
      (!Number.isSafeInteger(bufferedBytes) ||
        bufferedBytes < 0 ||
        bufferedBytes > this.config.limits.maxBufferedBytesPerStream - nextPayloadBytes)
    );
  }

  /** shared 生命周期与 edge 本地队列的总占用共同受同一份显式上限约束。 */
  private canBufferBytes(active: ActiveEdgeStream, bytes: number): boolean {
    if (!Number.isSafeInteger(bytes) || bytes <= 0) {
      return false;
    }

    const streamBufferedBytes = active.lifecycle.bufferedBytes + active.pendingOutboundDataBytes;
    const aggregateBufferedBytes = this.bufferBudget.totalBufferedBytes + this.pendingQueueBudget.totalBufferedBytes;
    return (
      bytes <= this.config.limits.maxBufferedBytesPerStream - streamBufferedBytes &&
      bytes <= this.config.limits.maxAggregateBufferedBytes - aggregateBufferedBytes
    );
  }

  private removeStream(active: ActiveEdgeStream, event?: "rejected" | "error" | "close"): void {
    // 断线收尾发生在 connection 已标记失效之后，此处只能按 stream 映射所有权
    // 判断；若仍依赖 isActiveConnection，会遗留 pending/open 本地 CONNECT。
    if (!active.active || this.streams.get(active.key) !== active) {
      return;
    }

    active.active = false;
    this.streams.delete(active.key);
    this.pendingQueueBudget.releaseAll(active.key);
    active.pendingOutboundData.length = 0;
    active.pendingOutboundDataBytes = 0;
    active.pendingReceiveCreditBytes = 0;
    active.lifecycle.onSessionDisconnected(active.lifecycle.sessionId, this.now());

    if (event !== undefined) {
      this.notify(active, { type: event });
    }
  }

  private closeAllStreams(event: "error" | "close"): void {
    for (const active of [...this.streams.values()]) {
      this.removeStream(active, event);
    }
  }

  private notify(active: ActiveEdgeStream, event: EdgeStreamEvent): void {
    try {
      active.listener(event);
    } catch {
      // CONNECT listener 异常仅影响它自己的 stream，不得暴露跨连接写入面。
      this.closeFromLocal(active, StreamCloseCode.PROTOCOL_ERROR);
    }
  }

  private allocateStreamId(): Uint8Array {
    let streamId: Uint8Array;
    do {
      streamId = createStreamId();
    } while (this.streams.has(streamKey(streamId)));
    return streamId;
  }

  private handleError(connection: EdgeConnection): void {
    if (this.isActiveConnection(connection)) {
      this.closeConnection(connection, { code: "WSS_CONNECTION_FAILED", terminal: false });
    }
  }

  private handleClose(connection: EdgeConnection, _closeCode: number, reason: string): void {
    if (!this.isActiveConnection(connection)) {
      return;
    }

    const failure = connection.failure ?? {
      code: closeCodeIsAuthenticationFailure(reason) ? reason : "WSS_DISCONNECTED",
      terminal: closeCodeIsAuthenticationFailure(reason)
    };
    this.finalizeConnection(connection, failure);
  }

  private closeConnection(connection: EdgeConnection, failure: ConnectionFailure): void {
    if (!this.isActiveConnection(connection) || connection.phase === "closing") {
      return;
    }

    connection.failure = failure;
    // `ws.close()` 的 close 回调可能异步到达。进入 closing 后立即撤销本地可用性，
    // 不能在等待回调的窗口内接受新的 CONNECT 或保留旧 stream 可写映射。
    connection.phase = "closing";
    this.clearHeartbeatTimer();
    this.clearAuthenticationTimer(connection);
    connection.unsubscribeSendAvailability?.();
    connection.unsubscribeSendAvailability = undefined;
    this.closeAllStreams("error");
    this.transition("closing", failure.code);
    try {
      connection.socket.close(WEBSOCKET_CLOSE_CODE_PROTOCOL, failure.code);
    } catch {
      this.finalizeConnection(connection, failure);
    }
  }

  private finalizeConnection(connection: EdgeConnection, failure: ConnectionFailure): void {
    if (!this.isActiveConnection(connection)) {
      return;
    }

    connection.finalized = true;
    this.activeConnection = undefined;
    this.clearHeartbeatTimer();
    this.clearAuthenticationTimer(connection);
    connection.unsubscribeSendAvailability?.();
    this.closeAllStreams("error");

    if (this.stopped) {
      this.transition("stopped");
      return;
    }

    this.scheduleReconnect(failure);
  }

  private scheduleReconnect(failure: ConnectionFailure): void {
    if (this.stopped || failure.terminal) {
      this.transition("offline", failure.code);
      return;
    }

    if (this.reconnectAttempts >= this.config.limits.maxReconnectAttempts) {
      this.transition("offline", "RECONNECT_LIMIT_EXCEEDED");
      return;
    }

    this.reconnectAttempts += 1;
    let delayMs: number;
    try {
      delayMs = calculateEdgeReconnectDelayMs(this.reconnectAttempts, this.config.limits, this.random);
    } catch {
      this.transition("offline", "EDGE_RECONNECT_JITTER_INVALID");
      return;
    }

    this.transition("backoff", failure.code);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect();
    }, delayMs);
    timerUnref(this.reconnectTimer);
  }

  private startHeartbeatTimer(connection: EdgeConnection): void {
    this.clearHeartbeatTimer();
    this.heartbeatTimer = setInterval(() => {
      if (!this.isActiveConnection(connection) || connection.phase !== "online") {
        return;
      }

      this.heartbeatSequence = (this.heartbeatSequence + 1) >>> 0;
      if (!this.sendFrame(connection, connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: this.heartbeatSequence })))) {
        this.closeConnection(connection, { code: "WSS_CONNECTION_FAILED", terminal: false });
      }
    }, this.config.limits.heartbeatIntervalMs);
    timerUnref(this.heartbeatTimer);
  }

  private startAuthenticationTimer(connection: EdgeConnection): void {
    connection.authenticationTimer = setTimeout(() => {
      if (this.isActiveConnection(connection) && connection.phase !== "online") {
        this.closeConnection(connection, { code: "AUTH_TIMEOUT", terminal: false });
      }
    }, this.config.limits.openTimeoutMs);
    timerUnref(connection.authenticationTimer);
  }

  private sendFrame(connection: EdgeConnection, frame: TunnelFrame): boolean {
    if (!this.isActiveConnection(connection)) {
      return false;
    }

    try {
      connection.socket.send(encodeFrame(frame));
      return true;
    } catch {
      return false;
    }
  }

  private getSendBufferedBytes(connection: EdgeConnection): number | undefined {
    if (!this.isActiveConnection(connection)) {
      return undefined;
    }

    try {
      const bufferedBytes = connection.socket.getSendBufferedBytes?.();
      return bufferedBytes === undefined || (Number.isSafeInteger(bufferedBytes) && bufferedBytes >= 0)
        ? bufferedBytes
        : undefined;
    } catch {
      return undefined;
    }
  }

  private clearHeartbeatTimer(): void {
    if (this.heartbeatTimer !== undefined) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
  }

  private clearAuthenticationTimer(connection: EdgeConnection): void {
    if (connection.authenticationTimer !== undefined) {
      clearTimeout(connection.authenticationTimer);
      connection.authenticationTimer = undefined;
    }
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== undefined) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
  }

  private isActiveConnection(connection: EdgeConnection): boolean {
    return !connection.finalized && this.activeConnection === connection;
  }

  private isActiveStream(active: ActiveEdgeStream): boolean {
    return active.active && this.streams.get(active.key) === active && this.isActiveConnection(active.connection);
  }

  private transition(state: EdgeClientState, lastErrorCode?: string): void {
    this.state = state;
    this.lastErrorCode = lastErrorCode;
    const status = this.getStatus();
    for (const listener of this.statusListeners) {
      try {
        listener(status);
      } catch {
        // 状态订阅者无权改变本地连接或 stream 生命周期。
      }
    }
  }
}
