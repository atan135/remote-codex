import { connect as connectTcp } from "node:net";
import type { Socket } from "node:net";

import {
  CapabilityReplayProtector,
  createServerSigningIdentity,
  decodeFramePayload,
  encodeStreamClosePayload,
  encodeStreamErrorPayload,
  FrameType,
  StreamBufferBudget,
  StreamCloseCode,
  StreamLifecycle,
  streamFrame,
  TunnelErrorCode,
  validateDestination,
  verifyCapabilityForAgent,
  type EgressAgentConfig,
  type ServerSigningIdentity,
  type TunnelFrame
} from "@remote-codex/shared";

/** 由 runtime 为当前已认证 WSS 连接创建的不可重用 stream 上下文。 */
export interface EgressAgentStreamSession {
  readonly id: object;
  readonly nowMs: number;
  send(frame: TunnelFrame): boolean;
}

/** 阶段 1 runtime 断开或停止时统一关闭的本地 stream 资源。 */
export interface EgressAgentStreamResources {
  closeAll(): void;
  handleFrame?(session: EgressAgentStreamSession, frame: TunnelFrame): void;
}

/**
 * 这是对 node:net.Socket 的最小受控表面。connector 只会收到已验证的本地目标，
 * 因此测试不需要也不能通过该接口请求任意 hostname 或 port。
 */
export interface AgentTcpSocket {
  end(): void;
  destroy(): void;
  setTimeout(timeoutMs: number, listener: () => void): void;
  once(event: "connect" | "error" | "end" | "close", listener: () => void): void;
}

export interface AgentTcpConnector {
  connect(destination: Readonly<{ hostname: string; port: 443 }>): AgentTcpSocket;
}

class NodeTcpSocket implements AgentTcpSocket {
  public constructor(private readonly socket: Socket) {}

  public end(): void {
    this.socket.end();
  }

  public destroy(): void {
    this.socket.destroy();
  }

  public setTimeout(timeoutMs: number, listener: () => void): void {
    this.socket.setTimeout(timeoutMs, listener);
  }

  public once(event: "connect" | "error" | "end" | "close", listener: () => void): void {
    this.socket.once(event, listener);
  }
}

/** 默认实现只允许 node 在严格目标校验后按配置 hostname:443 拨号。 */
class DefaultAgentTcpConnector implements AgentTcpConnector {
  public connect(destination: Readonly<{ hostname: string; port: 443 }>): AgentTcpSocket {
    return new NodeTcpSocket(connectTcp({ host: destination.hostname, port: destination.port }));
  }
}

interface ActiveDial {
  readonly streamKey: string;
  readonly streamId: Uint8Array;
  readonly session: EgressAgentStreamSession;
  readonly lifecycle: StreamLifecycle;
  socket: AgentTcpSocket | undefined;
  connected: boolean;
  closeRequested: boolean;
  active: boolean;
}

function streamKey(streamId: Uint8Array): string {
  if (streamId.byteLength !== 16) {
    throw new TypeError("stream ID must contain 16 bytes");
  }

  return Array.from(streamId, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isStreamOpenPayload(
  payload: ReturnType<typeof decodeFramePayload>
): payload is { readonly hostname: string; readonly port: 443; readonly capability: Uint8Array } {
  return (
    payload !== undefined &&
    !(payload instanceof Uint8Array) &&
    "hostname" in payload &&
    "port" in payload &&
    "capability" in payload
  );
}

/**
 * egress agent 的最终授权与拨号边界。所有外部输入在这里先验证 capability 和
 * 静态 allowlist，只有通过后才可能调用 connector。它从不创建 listener、HTTP
 * 客户端、代理链或显式 DNS 查询。
 */
export class EgressAgentDialer implements EgressAgentStreamResources {
  private readonly config: EgressAgentConfig;
  private readonly serverIdentity: ServerSigningIdentity;
  private readonly connector: AgentTcpConnector;
  private readonly now: () => number;
  private readonly capabilities = new CapabilityReplayProtector();
  private readonly bufferBudget: StreamBufferBudget;
  private readonly streams = new Map<string, ActiveDial>();

  public constructor(options: {
    readonly config: EgressAgentConfig;
    readonly capabilityServerIdentity: ServerSigningIdentity;
    readonly connector?: AgentTcpConnector;
    readonly now?: () => number;
  }) {
    this.config = options.config;
    this.serverIdentity = createServerSigningIdentity(options.capabilityServerIdentity);
    this.connector = options.connector ?? new DefaultAgentTcpConnector();
    this.now = options.now ?? Date.now;
    this.bufferBudget = new StreamBufferBudget(this.config.limits);
  }

  public get activeStreamCount(): number {
    return this.streams.size;
  }

  public handleFrame(session: EgressAgentStreamSession, frame: TunnelFrame): void {
    if (frame.type === FrameType.STREAM_OPEN) {
      this.handleOpen(session, frame);
      return;
    }

    const active = this.streams.get(streamKey(frame.streamId));

    if (active === undefined || active.session.id !== session.id || !active.active) {
      this.sendError(session, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    if (frame.type === FrameType.STREAM_CLOSE) {
      this.handleRemoteClose(active, frame);
      return;
    }

    // 数据、credit 和状态确认将在阶段 3 接入；此处不允许它们绕过 connecting
    // 状态或在未经受控的 socket 上写入。
    this.fail(active, TunnelErrorCode.PROTOCOL_VIOLATION);
  }

  public closeAll(): void {
    for (const active of [...this.streams.values()]) {
      this.remove(active, true);
    }
  }

  private handleOpen(session: EgressAgentStreamSession, frame: TunnelFrame): void {
    let payload: ReturnType<typeof decodeFramePayload>;

    try {
      payload = decodeFramePayload(frame);
    } catch {
      this.reject(session, frame.streamId, TunnelErrorCode.CAPABILITY_INVALID);
      return;
    }

    if (!isStreamOpenPayload(payload)) {
      this.reject(session, frame.streamId, TunnelErrorCode.CAPABILITY_INVALID);
      return;
    }

    // 此顺序是最终边界的一部分：session 由 runtime 限定；随后先验证 capability
    // 的签名、时效与绑定，再检查本地 stream 状态、静态目标和本地配额。
    const verified = verifyCapabilityForAgent({
      capability: payload.capability,
      serverIdentity: this.serverIdentity,
      agentId: this.config.agentId,
      streamId: frame.streamId,
      destination: this.config.allowedDestination,
      allowedDestination: this.config.allowedDestination,
      replayProtector: this.capabilities,
      nowMs: session.nowMs
    });

    if (!verified.ok) {
      this.reject(session, frame.streamId, TunnelErrorCode.CAPABILITY_INVALID);
      return;
    }

    let key: string;

    try {
      key = streamKey(frame.streamId);
    } catch {
      this.reject(session, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    if (this.streams.has(key)) {
      this.reject(session, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    let destination: Readonly<{ hostname: string; port: 443 }>;

    try {
      destination = validateDestination(payload.hostname, payload.port, this.config.allowedDestination);
    } catch {
      this.reject(session, frame.streamId, TunnelErrorCode.DESTINATION_REJECTED);
      return;
    }

    if (this.streams.size >= this.config.limits.maxConcurrentStreams) {
      this.reject(session, frame.streamId, TunnelErrorCode.STREAM_LIMIT_EXCEEDED);
      return;
    }

    const lifecycle = new StreamLifecycle({
      streamId: frame.streamId,
      sessionId: `egress:${key}`,
      limits: this.config.limits,
      bufferBudget: this.bufferBudget,
      now: this.now
    });
    const receivedOpen = lifecycle.handleInbound(frame, lifecycle.sessionId, session.nowMs);
    const authorized = receivedOpen.accepted ? lifecycle.authorize(session.nowMs) : undefined;
    const connecting = authorized?.accepted ? lifecycle.beginConnecting(session.nowMs) : undefined;

    if (!receivedOpen.accepted || !authorized?.accepted || !connecting?.accepted) {
      this.reject(session, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    const active: ActiveDial = {
      streamKey: key,
      streamId: Uint8Array.from(frame.streamId),
      session,
      lifecycle,
      socket: undefined,
      connected: false,
      closeRequested: false,
      active: true
    };
    this.streams.set(key, active);

    try {
      // destination 只来自经过本地 allowlist 验证的配置值，不能被 request 覆盖。
      const socket = this.connector.connect(destination);
      active.socket = socket;
      this.bindSocket(active, socket);
    } catch {
      this.fail(active, TunnelErrorCode.CONNECT_FAILED);
    }
  }

  private bindSocket(active: ActiveDial, socket: AgentTcpSocket): void {
    socket.once("connect", () => {
      if (!this.isActive(active)) {
        return;
      }

      active.connected = true;
      socket.setTimeout(this.config.limits.maxIdleMs, () => this.handleIdleTimeout(active));
    });
    socket.once("error", () => this.fail(active, TunnelErrorCode.CONNECT_FAILED));
    socket.once("end", () => this.handleSocketEnd(active));
    socket.once("close", () => this.handleSocketClose(active));
    socket.setTimeout(this.config.limits.connectTimeoutMs, () => this.handleConnectTimeout(active));
  }

  private handleRemoteClose(active: ActiveDial, frame: TunnelFrame): void {
    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());

    if (!result.accepted) {
      this.fail(active, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    active.closeRequested = true;
    try {
      active.socket?.end();
    } catch {
      this.remove(active, true);
    }
  }

  private handleConnectTimeout(active: ActiveDial): void {
    if (!this.isActive(active) || active.connected) {
      return;
    }

    this.fail(active, TunnelErrorCode.CONNECT_FAILED);
  }

  private handleIdleTimeout(active: ActiveDial): void {
    if (!this.isActive(active) || !active.connected) {
      return;
    }

    this.fail(active, TunnelErrorCode.IDLE_TIMEOUT);
  }

  private handleSocketEnd(active: ActiveDial): void {
    if (!this.isActive(active)) {
      return;
    }

    if (active.closeRequested) {
      this.remove(active, true);
      return;
    }

    if (active.connected) {
      this.closeFromSocket(active);
      return;
    }

    this.fail(active, TunnelErrorCode.CONNECT_FAILED);
  }

  private handleSocketClose(active: ActiveDial): void {
    if (!this.isActive(active)) {
      return;
    }

    if (active.closeRequested) {
      this.remove(active, false);
      return;
    }

    this.fail(active, TunnelErrorCode.CONNECT_FAILED);
  }

  private fail(active: ActiveDial, code: typeof TunnelErrorCode[keyof typeof TunnelErrorCode]): void {
    if (!this.isActive(active)) {
      return;
    }

    active.lifecycle.fail(code, this.now());
    this.sendError(active.session, active.streamId, code);
    this.remove(active, true);
  }

  private closeFromSocket(active: ActiveDial): void {
    if (!this.isActive(active)) {
      return;
    }

    const closeFrame = streamFrame(
      FrameType.STREAM_CLOSE,
      active.streamId,
      encodeStreamClosePayload({ code: StreamCloseCode.NORMAL })
    );
    const requested = active.lifecycle.requestClose(StreamCloseCode.NORMAL, this.now());

    if (!requested.accepted) {
      this.fail(active, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    active.session.send(closeFrame);
    active.lifecycle.completeClose(this.now());
    this.remove(active, true);
  }

  private reject(
    session: EgressAgentStreamSession,
    streamId: Uint8Array,
    code: typeof TunnelErrorCode[keyof typeof TunnelErrorCode]
  ): void {
    session.send(streamFrame(FrameType.STREAM_REJECTED, streamId, encodeStreamErrorPayload({ code })));
  }

  private sendError(
    session: EgressAgentStreamSession,
    streamId: Uint8Array,
    code: typeof TunnelErrorCode[keyof typeof TunnelErrorCode]
  ): void {
    session.send(streamFrame(FrameType.STREAM_ERROR, streamId, encodeStreamErrorPayload({ code })));
  }

  private remove(active: ActiveDial, destroySocket: boolean): void {
    if (!active.active) {
      return;
    }

    active.active = false;
    this.streams.delete(active.streamKey);
    active.lifecycle.onSessionDisconnected(active.lifecycle.sessionId, this.now());

    if (destroySocket) {
      try {
        active.socket?.destroy();
      } catch {
        // socket 已不可用时，stream 映射仍必须先清理。
      }
    }
  }

  private isActive(active: ActiveDial): boolean {
    return active.active && this.streams.get(active.streamKey) === active;
  }
}
