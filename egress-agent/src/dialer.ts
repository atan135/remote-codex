import { Socket } from "node:net";

import {
  CapabilityReplayProtector,
  createServerSigningIdentity,
  decodeFramePayload,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
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
  /** 当前 WSS 出站缓冲字节数；未提供时保持兼容的立即发送策略。 */
  getSendBufferedBytes?(): number | undefined;
  /** WSS 完成一次发送后触发，供每流队列按轮次恢复，不传递 payload。 */
  subscribeSendAvailability?(listener: () => void): () => void;
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
  write(data: Uint8Array): boolean;
  pause(): void;
  resume(): void;
  setTimeout(timeoutMs: number, listener: () => void): void;
  once(event: "connect" | "error" | "end" | "close", listener: () => void): void;
  on(event: "data", listener: (data: Uint8Array) => void): void;
  on(event: "drain", listener: () => void): void;
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

  public write(data: Uint8Array): boolean {
    return this.socket.write(data);
  }

  public pause(): void {
    this.socket.pause();
  }

  public resume(): void {
    this.socket.resume();
  }

  public setTimeout(timeoutMs: number, listener: () => void): void {
    this.socket.setTimeout(timeoutMs, listener);
  }

  public once(event: "connect" | "error" | "end" | "close", listener: () => void): void {
    this.socket.once(event, listener);
  }

  public on(event: "data", listener: (data: Uint8Array) => void): void;
  public on(event: "drain", listener: () => void): void;
  public on(event: "data" | "drain", listener: ((data: Uint8Array) => void) | (() => void)): void {
    if (event === "data") {
      this.socket.on("data", listener as (data: Uint8Array) => void);
      return;
    }

    this.socket.on("drain", listener as () => void);
  }
}

/** 默认实现只允许 node 在严格目标校验后按配置 hostname:443 拨号。 */
class DefaultAgentTcpConnector implements AgentTcpConnector {
  public connect(destination: Readonly<{ hostname: string; port: 443 }>): AgentTcpSocket {
    const socket = new Socket();
    socket.connect({ host: destination.hostname, port: destination.port });
    return new NodeTcpSocket(socket);
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
  socketEnded: boolean;
  producerPaused: boolean;
  pendingOutboundData: TunnelFrame[];
  pendingOutboundDataBytes: number;
  pendingReceiveCreditBytes: number;
  pendingSocketDrainBytes: number;
  pendingCloseCode: typeof StreamCloseCode[keyof typeof StreamCloseCode] | undefined;
  unsubscribeSendAvailability: (() => void) | undefined;
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
  /** 只计量仍由 agent 本地队列持有的 TCP -> WSS bytes。 */
  private readonly pendingQueueBudget: StreamBufferBudget;
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
    this.pendingQueueBudget = new StreamBufferBudget(this.config.limits);
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

    if (frame.type === FrameType.STREAM_DATA) {
      this.handleInboundData(active, frame);
      return;
    }

    if (frame.type === FrameType.STREAM_CREDIT) {
      this.handleInboundCredit(active, frame);
      return;
    }

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
      socketEnded: false,
      producerPaused: false,
      pendingOutboundData: [],
      pendingOutboundDataBytes: 0,
      pendingReceiveCreditBytes: 0,
      pendingSocketDrainBytes: 0,
      pendingCloseCode: undefined,
      unsubscribeSendAvailability: undefined,
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
      socket.on("data", (data) => this.handleSocketData(active, data));
      socket.on("drain", () => this.handleSocketDrain(active));
      this.pauseProducer(active);
      if (!this.isActive(active)) {
        return;
      }
      active.unsubscribeSendAvailability = active.session.subscribeSendAvailability?.(() => this.flushOnePendingFrame(active));

      const opened = streamFrame(FrameType.STREAM_OPENED, active.streamId, new Uint8Array());
      const openedResult = active.lifecycle.handleOutbound(opened, active.lifecycle.sessionId, this.now());
      if (!openedResult.accepted || !this.sendFrame(active, opened)) {
        this.fail(active, TunnelErrorCode.PEER_DISCONNECTED);
        return;
      }

      active.pendingReceiveCreditBytes = active.lifecycle.pendingReceiveCreditBytes;
      this.flushOnePendingFrame(active);
      this.syncProducerReadState(active);
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
    this.pauseProducer(active);
    this.clearPendingOutboundData(active);
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
      active.socketEnded = true;
      this.requestCloseFromSocket(active, StreamCloseCode.NORMAL);
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

    if (active.socketEnded && active.pendingCloseCode !== undefined) {
      return;
    }

    this.fail(active, TunnelErrorCode.CONNECT_FAILED);
  }

  private handleSocketData(active: ActiveDial, data: Uint8Array): void {
    if (!this.isActive(active) || !active.connected || active.closeRequested || active.socketEnded) {
      return;
    }

    if (data.byteLength === 0) {
      return;
    }

    if (!this.canBufferBytes(active, data.byteLength) || !this.pendingQueueBudget.canReserve(active.streamKey, data.byteLength)) {
      this.fail(active, TunnelErrorCode.FLOW_CONTROL_VIOLATION);
      return;
    }

    for (let offset = 0; offset < data.byteLength; offset += this.config.limits.maxFramePayloadBytes) {
      const payload = data.subarray(offset, Math.min(offset + this.config.limits.maxFramePayloadBytes, data.byteLength));
      if (!this.pendingQueueBudget.reserve(active.streamKey, payload.byteLength)) {
        this.fail(active, TunnelErrorCode.FLOW_CONTROL_VIOLATION);
        return;
      }

      active.pendingOutboundData.push(streamFrame(FrameType.STREAM_DATA, active.streamId, payload));
      active.pendingOutboundDataBytes += payload.byteLength;
    }

    this.flushOnePendingFrame(active);
    this.syncProducerReadState(active);
  }

  private handleSocketDrain(active: ActiveDial): void {
    if (!this.isActive(active) || active.pendingSocketDrainBytes === 0) {
      return;
    }

    const bytes = active.pendingSocketDrainBytes;
    active.pendingSocketDrainBytes = 0;
    this.queueReceiveCredit(active, bytes);
  }

  private handleInboundData(active: ActiveDial, frame: TunnelFrame): void {
    const payload = decodeFramePayload(frame);
    if (!(payload instanceof Uint8Array) || payload.byteLength === 0) {
      this.fail(active, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    // lifecycle 已确认数据和 agent 本地待发队列共同构成实际内存水位；两个方向
    // 都必须先经过组合准入，不能让慢 WSS 队列绕开 inbound data 的聚合限制。
    if (!this.canBufferBytes(active, payload.byteLength)) {
      this.fail(active, TunnelErrorCode.FLOW_CONTROL_VIOLATION);
      return;
    }

    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());
    if (!result.accepted) {
      this.fail(active, result.errorCode ?? TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    try {
      if (active.socket?.write(payload) === false) {
        active.pendingSocketDrainBytes += payload.byteLength;
        return;
      }
    } catch {
      this.fail(active, TunnelErrorCode.CONNECT_FAILED);
      return;
    }

    this.queueReceiveCredit(active, payload.byteLength);
  }

  private handleInboundCredit(active: ActiveDial, frame: TunnelFrame): void {
    const result = active.lifecycle.handleInbound(frame, active.lifecycle.sessionId, this.now());
    if (!result.accepted) {
      this.fail(active, result.errorCode ?? TunnelErrorCode.FLOW_CONTROL_VIOLATION);
      return;
    }

    this.flushOnePendingFrame(active);
    this.syncProducerReadState(active);
  }

  private queueReceiveCredit(active: ActiveDial, bytes: number): void {
    const queued = active.lifecycle.queueReceiveCredit(bytes, this.now());
    if (!queued.accepted) {
      this.fail(active, queued.errorCode ?? TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    active.pendingReceiveCreditBytes += bytes;
    this.flushOnePendingFrame(active);
  }

  /** 每次 WSS 可写只取每流一个待发送项，避免单一慢用户流独占发送机会。 */
  private flushOnePendingFrame(active: ActiveDial): void {
    if (!this.isActive(active) || !active.connected) {
      return;
    }

    if (active.pendingReceiveCreditBytes > 0) {
      const bytes = active.pendingReceiveCreditBytes;
      const credit = streamFrame(
        FrameType.STREAM_CREDIT,
        active.streamId,
        encodeStreamCreditPayload({ bytes })
      );
      if (this.shouldDelayForWss(active, credit.payload.byteLength)) {
        this.syncProducerReadState(active);
        return;
      }
      const result = active.lifecycle.handleOutbound(credit, active.lifecycle.sessionId, this.now());
      if (!result.accepted || !this.sendFrame(active, credit)) {
        this.fail(active, result.errorCode ?? TunnelErrorCode.PEER_DISCONNECTED);
        return;
      }

      active.pendingReceiveCreditBytes = 0;
      this.syncProducerReadState(active);
      return;
    }

    const outbound = active.pendingOutboundData[0];
    if (outbound !== undefined) {
      if (this.shouldDelayForWss(active, outbound.payload.byteLength)) {
        this.syncProducerReadState(active);
        return;
      }

      if (active.lifecycle.availableSendCreditBytes < outbound.payload.byteLength) {
        this.syncProducerReadState(active);
        return;
      }

      // 将本地队列的占用转移给 lifecycle：先释放队列计量，再 reserve lifecycle，
      // 组合水位保持不变，不会在一次转移内出现双重记账峰值。
      active.pendingOutboundData.shift();
      active.pendingOutboundDataBytes -= outbound.payload.byteLength;
      this.pendingQueueBudget.release(active.streamKey, outbound.payload.byteLength);
      const result = active.lifecycle.handleOutbound(outbound, active.lifecycle.sessionId, this.now());
      if (!result.accepted) {
        this.fail(active, result.errorCode ?? TunnelErrorCode.FLOW_CONTROL_VIOLATION);
        return;
      }

      if (!this.sendFrame(active, outbound)) {
        this.fail(active, TunnelErrorCode.PEER_DISCONNECTED);
        return;
      }

      this.syncProducerReadState(active);
      return;
    }

    if (active.pendingCloseCode !== undefined) {
      const code = active.pendingCloseCode;
      const closeFrame = streamFrame(
        FrameType.STREAM_CLOSE,
        active.streamId,
        encodeStreamClosePayload({ code })
      );
      if (this.shouldDelayForWss(active, closeFrame.payload.byteLength)) {
        return;
      }
      const result = active.lifecycle.handleOutbound(closeFrame, active.lifecycle.sessionId, this.now());
      if (!result.accepted || !this.sendFrame(active, closeFrame)) {
        this.remove(active, true);
        return;
      }

      active.pendingCloseCode = undefined;
      active.lifecycle.completeClose(this.now());
      this.remove(active, true);
    }
  }

  private requestCloseFromSocket(
    active: ActiveDial,
    code: typeof StreamCloseCode[keyof typeof StreamCloseCode]
  ): void {
    const requested = active.lifecycle.requestClose(code, this.now());
    if (!requested.accepted) {
      this.fail(active, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    active.pendingCloseCode = code;
    // EOF 后不再接收新的对端数据，尚未送出的初始/补充 credit 不应在 closing
    // 状态下补发，否则会把正常关闭变成协议错误。
    active.pendingReceiveCreditBytes = 0;
    this.pauseProducer(active);
    this.flushOnePendingFrame(active);
  }

  private shouldDelayForWss(active: ActiveDial, nextPayloadBytes = 0): boolean {
    const bufferedBytes = active.session.getSendBufferedBytes?.();
    return (
      bufferedBytes !== undefined &&
      (!Number.isSafeInteger(bufferedBytes) ||
        bufferedBytes < 0 ||
        bufferedBytes > this.config.limits.maxBufferedBytesPerStream - nextPayloadBytes)
    );
  }

  /** lifecycle 和 agent 本地队列的总占用必须始终不超过同一组部署限制。 */
  private canBufferBytes(active: ActiveDial, bytes: number): boolean {
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

  private sendFrame(active: ActiveDial, frame: TunnelFrame): boolean {
    try {
      return active.session.send(frame);
    } catch {
      return false;
    }
  }

  private syncProducerReadState(active: ActiveDial): void {
    if (!this.isActive(active) || active.closeRequested || active.socketEnded || active.pendingCloseCode !== undefined) {
      this.pauseProducer(active);
      return;
    }

    if (active.pendingOutboundData.length > 0 || !active.lifecycle.canReadFromProducer || this.shouldDelayForWss(active, 1)) {
      this.pauseProducer(active);
      return;
    }

    if (!active.producerPaused) {
      return;
    }

    try {
      active.socket?.resume();
      active.producerPaused = false;
    } catch {
      this.fail(active, TunnelErrorCode.CONNECT_FAILED);
    }
  }

  private pauseProducer(active: ActiveDial): void {
    if (active.producerPaused) {
      return;
    }

    try {
      active.socket?.pause();
      active.producerPaused = true;
    } catch {
      this.fail(active, TunnelErrorCode.CONNECT_FAILED);
    }
  }

  private clearPendingOutboundData(active: ActiveDial): void {
    if (active.pendingOutboundDataBytes > 0) {
      this.pendingQueueBudget.releaseAll(active.streamKey);
    }

    active.pendingOutboundData.length = 0;
    active.pendingOutboundDataBytes = 0;
  }

  private fail(active: ActiveDial, code: typeof TunnelErrorCode[keyof typeof TunnelErrorCode]): void {
    if (!this.isActive(active)) {
      return;
    }

    active.lifecycle.fail(code, this.now());
    try {
      this.sendError(active.session, active.streamId, code);
    } catch {
      // WSS 已不可写时仍须完成本地流和 TCP 的幂等清理。
    }
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
    this.clearPendingOutboundData(active);
    active.unsubscribeSendAvailability?.();
    active.unsubscribeSendAvailability = undefined;
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
