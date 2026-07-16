import {
  createStreamId,
  decodeFramePayload,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
  encodeStreamErrorPayload,
  encodeStreamOpenPayload,
  FrameType,
  issueCapability,
  MAX_CAPABILITY_WINDOW_MS,
  StreamCloseCode,
  StreamBufferBudget,
  StreamLifecycle,
  streamFrame,
  TunnelErrorCode,
  validateDestination,
  DEFAULT_RESOURCE_LIMITS,
  type AllowedDestination,
  type ResourceLimits,
  type ServerSigningCredentials,
  type StreamCloseCode as StreamCloseCodeValue,
  type StreamState,
  type TunnelErrorCode as TunnelErrorCodeValue,
  type TunnelFrame
} from "@remote-codex/shared";

import type { AuthorizationQuota, AuthorizationRegistry, AuthorizationRevocation } from "./authorization-registry.js";
import type {
  AuthenticatedPeerSession,
  PeerSessionRemovalListener,
  PeerSessionSendAvailabilityListener,
  PeerSessionStreamFrameListener
} from "./peer-session.js";

/** Stream 层所需的最小 peer 会话能力；不暴露 socket 或任何 TLS 明文。 */
export interface StreamPeerSessionGateway {
  getAgentSession(agentId: string): AuthenticatedPeerSession | undefined;
  sendFrame(peerId: string, frame: TunnelFrame): boolean;
  subscribeStreamFrames(listener: PeerSessionStreamFrameListener): () => void;
  subscribeSessionRemovals(listener: PeerSessionRemovalListener): () => void;
  /** 可选的本地 WSS 发送队列水位；未实现时仍由 credit 和内存上限保护。 */
  getSendBufferedBytes?(peerId: string): number | undefined;
  /** 可选的 WSS 发送完成通知，用于恢复被背压延迟的帧。 */
  subscribeSendAvailability?(listener: PeerSessionSendAvailabilityListener): () => void;
}

export interface StreamOpenCoordinatorOptions {
  readonly peerSessions: StreamPeerSessionGateway;
  readonly authorizationRegistry: AuthorizationRegistry;
  /** 仅由 server 进程注入的 capability 签名凭据。 */
  readonly signingCredentials: ServerSigningCredentials;
  readonly allowedDestination: AllowedDestination;
  readonly resourceLimits?: ResourceLimits;
  readonly capabilityTtlMs?: number;
  /** 受控时钟使 capability 过期与打开超时可确定性测试。 */
  readonly now?: () => number;
}

export interface StreamOwnership {
  /** server 分配并仅在 server-agent 间使用的 stream ID。 */
  readonly streamId: Uint8Array;
  /** edge 侧原始 ID；所有发回 edge 的结果都使用它。 */
  readonly edgeStreamId: Uint8Array;
  readonly edgePeerId: string;
  readonly agentPeerId: string;
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
  readonly agentId: string;
  readonly quota: AuthorizationQuota;
  readonly authorizationAuditVersion: number;
  readonly capabilityExpiresAtMs: number;
  readonly state: StreamState;
  /** server 为该 stream 保留的未确认字节数，不包含任何 payload 内容。 */
  readonly bufferedBytes: number;
}

interface PendingDataFrame {
  readonly frame: TunnelFrame;
}

interface PendingCreditFrame {
  readonly bytes: number;
}

interface ActiveStream extends Omit<StreamOwnership, "state" | "bufferedBytes"> {
  readonly serverStreamKey: string;
  readonly edgeStreamKey: string;
  readonly authorizationKey: string;
  /** 仅用于 shared 状态机的内部绑定值，不可由任意 peer 指定。 */
  readonly relaySessionId: string;
  readonly lifecycle: StreamLifecycle;
  readonly pendingDataToAgent: PendingDataFrame[];
  readonly pendingDataToEdge: PendingDataFrame[];
  readonly pendingCreditToAgent: PendingCreditFrame[];
  readonly pendingCreditToEdge: PendingCreditFrame[];
  pendingCreditToAgentBytes: number;
  pendingCreditToEdgeBytes: number;
}

function streamKey(streamId: Uint8Array): string {
  return Buffer.from(streamId).toString("hex");
}

function edgeStreamKey(peerId: string, streamId: Uint8Array): string {
  return `${peerId}\u0000${streamKey(streamId)}`;
}

function authorizationKey(edgeUserId: string, edgeDeviceId: string, agentId: string): string {
  return `${edgeUserId}\u0000${edgeDeviceId}\u0000${agentId}`;
}

function errorPayload(frame: TunnelFrame): TunnelErrorCodeValue | undefined {
  if (frame.type !== FrameType.STREAM_REJECTED && frame.type !== FrameType.STREAM_ERROR) {
    return undefined;
  }
  const payload = decodeFramePayload(frame);
  return payload === undefined || payload instanceof Uint8Array || !("code" in payload)
    ? undefined
    : (payload.code as TunnelErrorCodeValue);
}

function closePayload(frame: TunnelFrame): StreamCloseCodeValue | undefined {
  if (frame.type !== FrameType.STREAM_CLOSE) {
    return undefined;
  }
  const payload = decodeFramePayload(frame);
  return payload === undefined || payload instanceof Uint8Array || !("code" in payload)
    ? undefined
    : (payload.code as StreamCloseCodeValue);
}

function creditPayload(frame: TunnelFrame): number | undefined {
  if (frame.type !== FrameType.STREAM_CREDIT) {
    return undefined;
  }

  const payload = decodeFramePayload(frame);
  return payload === undefined || payload instanceof Uint8Array || !("bytes" in payload) ? undefined : payload.bytes;
}

function closeCodeForError(errorCode: TunnelErrorCodeValue): StreamCloseCodeValue {
  switch (errorCode) {
    case TunnelErrorCode.OPEN_TIMEOUT:
      return StreamCloseCode.OPEN_TIMEOUT;
    case TunnelErrorCode.PEER_DISCONNECTED:
      return StreamCloseCode.PEER_DISCONNECTED;
    case TunnelErrorCode.CONNECT_FAILED:
      return StreamCloseCode.CONNECT_FAILED;
    case TunnelErrorCode.DESTINATION_REJECTED:
      return StreamCloseCode.DESTINATION_REJECTED;
    case TunnelErrorCode.FLOW_CONTROL_VIOLATION:
      return StreamCloseCode.RESOURCE_LIMIT;
    case TunnelErrorCode.IDLE_TIMEOUT:
      return StreamCloseCode.IDLE_TIMEOUT;
    default:
      return StreamCloseCode.PROTOCOL_ERROR;
  }
}

/**
 * 开流授权器只建立 edge-session -> server-stream -> agent-session 的临时所有权。
 * 它不创建 TCP 连接，也不转发 `STREAM_DATA` 或其内容。
 */
export class StreamOpenCoordinator {
  private readonly peerSessions: StreamPeerSessionGateway;
  private readonly authorizationRegistry: AuthorizationRegistry;
  private readonly signingCredentials: ServerSigningCredentials;
  private readonly allowedDestination: AllowedDestination;
  private readonly resourceLimits: ResourceLimits;
  private readonly capabilityTtlMs: number;
  private readonly now: () => number;
  /** 所有存量 stream 共用的聚合字节预算，防止一个 WSS 会话无限积压。 */
  private readonly bufferBudget: StreamBufferBudget;
  private readonly streamsByServerId = new Map<string, ActiveStream>();
  private readonly streamsByEdgeId = new Map<string, ActiveStream>();
  private readonly streamCountsByAuthorization = new Map<string, number>();
  private readonly streamCountsByEdgeUser = new Map<string, number>();
  private readonly bufferedBytesByAuthorization = new Map<string, number>();
  private readonly bufferedBytesByEdgeUser = new Map<string, number>();
  private readonly unsubscribeFrames: () => void;
  private readonly unsubscribeRemovals: () => void;
  private readonly unsubscribeRevocations: () => void;
  private readonly unsubscribeSendAvailability: () => void;
  private flushingPendingFrames = false;

  public constructor(options: StreamOpenCoordinatorOptions) {
    this.peerSessions = options.peerSessions;
    this.authorizationRegistry = options.authorizationRegistry;
    this.signingCredentials = options.signingCredentials;
    this.allowedDestination = validateDestination(
      options.allowedDestination.hostname,
      options.allowedDestination.port,
      options.allowedDestination
    );
    this.resourceLimits = Object.freeze({ ...(options.resourceLimits ?? DEFAULT_RESOURCE_LIMITS) });
    this.capabilityTtlMs = options.capabilityTtlMs ?? Math.min(30_000, MAX_CAPABILITY_WINDOW_MS);
    if (
      !Number.isSafeInteger(this.capabilityTtlMs) ||
      this.capabilityTtlMs < 1 ||
      this.capabilityTtlMs > MAX_CAPABILITY_WINDOW_MS
    ) {
      throw new RangeError("SERVER_STREAM_CAPABILITY_TTL_INVALID");
    }

    this.now = options.now ?? Date.now;
    this.bufferBudget = new StreamBufferBudget(this.resourceLimits);
    this.unsubscribeFrames = this.peerSessions.subscribeStreamFrames((session, frame) => this.handleFrame(session, frame));
    this.unsubscribeRemovals = this.peerSessions.subscribeSessionRemovals((session) => this.handleSessionRemoval(session));
    this.unsubscribeSendAvailability =
      this.peerSessions.subscribeSendAvailability?.(() => this.flushPendingFrames()) ?? (() => undefined);
    this.unsubscribeRevocations = this.authorizationRegistry.subscribeRevocations((result) => {
      for (const revocation of result.revocations) {
        this.handleRevocation(revocation);
      }
    });
  }

  public getActiveStreams(): readonly StreamOwnership[] {
    return Object.freeze(
      [...this.streamsByServerId.values()].map((stream) =>
        Object.freeze({
          streamId: Uint8Array.from(stream.streamId),
          edgeStreamId: Uint8Array.from(stream.edgeStreamId),
          edgePeerId: stream.edgePeerId,
          agentPeerId: stream.agentPeerId,
          edgeUserId: stream.edgeUserId,
          edgeDeviceId: stream.edgeDeviceId,
          agentId: stream.agentId,
          quota: Object.freeze({
            maxConcurrentStreams: stream.quota.maxConcurrentStreams,
            maxBufferedBytes: stream.quota.maxBufferedBytes
          }),
          authorizationAuditVersion: stream.authorizationAuditVersion,
          capabilityExpiresAtMs: stream.capabilityExpiresAtMs,
          state: stream.lifecycle.state,
          bufferedBytes: stream.lifecycle.bufferedBytes
        })
      )
    );
  }

  /** 由运行时定时调用；测试可推进受控时钟后直接调用。 */
  public expireOpenStreams(): void {
    this.flushPendingFrames();
    const nowMs = this.readNow();
    for (const stream of [...this.streamsByServerId.values()]) {
      if (stream.lifecycle.state !== "open" && nowMs >= stream.capabilityExpiresAtMs) {
        this.abortStream(stream, TunnelErrorCode.CAPABILITY_INVALID, true);
        continue;
      }

      const result = stream.lifecycle.tick(nowMs);
      if (result.errorCode !== undefined) {
        this.abortStream(stream, result.errorCode, true);
        continue;
      }

      if (result.shouldSendClose && result.closeCode !== undefined) {
        this.closeStream(stream, result.closeCode);
      }
    }
  }

  /**
   * 在 WebSocket 发送完成或运行时定时器触发时公平地重试各 stream 的待发帧。
   * 每轮每个方向至多发送一帧，避免一个慢用户清空队列时饿死同 agent 的其他用户。
   */
  public flushPendingFrames(): void {
    if (this.flushingPendingFrames) {
      return;
    }

    this.flushingPendingFrames = true;
    try {
      for (const stream of [...this.streamsByServerId.values()]) {
        if (!this.streamsByServerId.has(stream.serverStreamKey)) {
          continue;
        }

        this.flushOnePendingFrame(stream, "agent");
        if (this.streamsByServerId.has(stream.serverStreamKey)) {
          this.flushOnePendingFrame(stream, "edge");
        }
      }
    } finally {
      this.flushingPendingFrames = false;
    }
  }

  public close(): void {
    this.unsubscribeFrames();
    this.unsubscribeRemovals();
    this.unsubscribeSendAvailability();
    this.unsubscribeRevocations();
    for (const stream of [...this.streamsByServerId.values()]) {
      this.removeStream(stream);
    }
  }

  private handleFrame(session: AuthenticatedPeerSession, frame: TunnelFrame): void {
    try {
      if (session.role === "edge-client") {
        this.handleEdgeFrame(session, frame);
        return;
      }

      this.handleAgentFrame(session, frame);
    } catch {
      // 所有解析失败均在 shared 帧校验后转为固定错误，不记录帧 payload。
      if (session.role === "edge-client") {
        const stream = this.streamsByEdgeId.get(edgeStreamKey(session.peerId, frame.streamId));
        if (stream !== undefined && stream.edgePeerId === session.peerId) {
          this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        } else {
          this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
        }
      } else {
        const stream = this.streamsByServerId.get(streamKey(frame.streamId));
        if (stream !== undefined && stream.agentPeerId === session.peerId && session.identity.agentId === stream.agentId) {
          this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        } else {
          this.sendAgentError(session.peerId, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
        }
      }
    }
  }

  private handleEdgeFrame(session: AuthenticatedPeerSession, frame: TunnelFrame): void {
    if (frame.type !== FrameType.STREAM_OPEN) {
      this.handleNonOpenEdgeFrame(session, frame);
      return;
    }

    if (
      session.identity.kind !== "edge-device" ||
      session.identity.edgeUserId === undefined ||
      session.identity.edgeDeviceId === undefined
    ) {
      this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.AUTH_UNAUTHORIZED);
      return;
    }

    const edgeKey = edgeStreamKey(session.peerId, frame.streamId);
    if (this.streamsByEdgeId.has(edgeKey)) {
      this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    const payload = decodeFramePayload(frame);
    if (payload === undefined || payload instanceof Uint8Array || !("hostname" in payload) || !("port" in payload)) {
      this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    let destination: AllowedDestination;
    try {
      destination = validateDestination(payload.hostname, payload.port, this.allowedDestination);
    } catch {
      this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.DESTINATION_REJECTED);
      return;
    }

    const route = this.authorizationRegistry.resolveAgentForEdge(session.identity);
    if (route === undefined) {
      this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.AUTH_UNAUTHORIZED);
      return;
    }

    const countKey = authorizationKey(session.identity.edgeUserId, session.identity.edgeDeviceId, route.agentId);
    if (
      (this.streamCountsByAuthorization.get(countKey) ?? 0) >= route.quota.maxConcurrentStreams ||
      (this.streamCountsByEdgeUser.get(session.identity.edgeUserId) ?? 0) >= route.quota.maxConcurrentStreams
    ) {
      this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.STREAM_LIMIT_EXCEEDED);
      return;
    }

    const agentSession = this.peerSessions.getAgentSession(route.agentId);
    if (agentSession === undefined) {
      this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.PEER_DISCONNECTED);
      return;
    }

    const nowMs = this.readNow();
    const serverStreamId = this.allocateServerStreamId();
    const capability = issueCapability({
      credentials: this.signingCredentials,
      binding: {
        edgeUserId: session.identity.edgeUserId,
        edgeDeviceId: session.identity.edgeDeviceId,
        agentId: route.agentId,
        streamId: serverStreamId,
        destination
      },
      allowedDestination: this.allowedDestination,
      nowMs,
      ttlMs: this.capabilityTtlMs
    });
    const forwardedOpen = streamFrame(
      FrameType.STREAM_OPEN,
      serverStreamId,
      encodeStreamOpenPayload({ hostname: destination.hostname, port: 443, capability })
    );
    const serverStreamKey = streamKey(serverStreamId);
    const relaySessionId = `relay:${serverStreamKey}`;
    const lifecycle = new StreamLifecycle({
      streamId: serverStreamId,
      sessionId: relaySessionId,
      limits: this.resourceLimits,
      bufferBudget: this.bufferBudget,
      now: this.now
    });
    const openResult = lifecycle.handleInbound(forwardedOpen, relaySessionId, nowMs);
    const authorizationResult = openResult.accepted ? lifecycle.authorize(nowMs) : undefined;
    const connectingResult = authorizationResult?.accepted ? lifecycle.beginConnecting(nowMs) : undefined;
    if (!openResult.accepted || !authorizationResult?.accepted || !connectingResult?.accepted) {
      this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.FLOW_CONTROL_VIOLATION);
      return;
    }

    const stream: ActiveStream = {
      streamId: Uint8Array.from(serverStreamId),
      edgeStreamId: Uint8Array.from(frame.streamId),
      edgePeerId: session.peerId,
      agentPeerId: agentSession.peerId,
      edgeUserId: session.identity.edgeUserId,
      edgeDeviceId: session.identity.edgeDeviceId,
      agentId: route.agentId,
      quota: Object.freeze({
        maxConcurrentStreams: route.quota.maxConcurrentStreams,
        maxBufferedBytes: route.quota.maxBufferedBytes
      }),
      authorizationAuditVersion: route.authorizationAuditVersion,
      capabilityExpiresAtMs: nowMs + this.capabilityTtlMs,
      serverStreamKey,
      edgeStreamKey: edgeKey,
      authorizationKey: countKey,
      relaySessionId,
      lifecycle,
      pendingDataToAgent: [],
      pendingDataToEdge: [],
      pendingCreditToAgent: [],
      pendingCreditToEdge: [],
      pendingCreditToAgentBytes: 0,
      pendingCreditToEdgeBytes: 0
    };
    this.streamsByServerId.set(stream.serverStreamKey, stream);
    this.streamsByEdgeId.set(stream.edgeStreamKey, stream);
    this.streamCountsByAuthorization.set(countKey, (this.streamCountsByAuthorization.get(countKey) ?? 0) + 1);
    this.streamCountsByEdgeUser.set(
      session.identity.edgeUserId,
      (this.streamCountsByEdgeUser.get(session.identity.edgeUserId) ?? 0) + 1
    );

    if (!this.peerSessions.sendFrame(agentSession.peerId, forwardedOpen)) {
      this.abortStream(stream, TunnelErrorCode.PEER_DISCONNECTED, false);
    }
  }

  private handleNonOpenEdgeFrame(session: AuthenticatedPeerSession, frame: TunnelFrame): void {
    const stream = this.streamsByEdgeId.get(edgeStreamKey(session.peerId, frame.streamId));
    if (stream === undefined || stream.edgePeerId !== session.peerId) {
      this.sendEdgeError(session.peerId, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    if (frame.type === FrameType.STREAM_DATA) {
      this.relayDataFromEdge(stream, frame);
      return;
    }

    if (frame.type === FrameType.STREAM_CREDIT) {
      this.relayCreditFromEdge(stream, frame);
      return;
    }

    if (frame.type === FrameType.STREAM_CLOSE) {
      const code = closePayload(frame);
      if (code === undefined) {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }
      const beforeBufferedBytes = stream.lifecycle.bufferedBytes;
      const result = stream.lifecycle.handleOutbound(
        streamFrame(FrameType.STREAM_CLOSE, stream.streamId, encodeStreamClosePayload({ code })),
        stream.relaySessionId,
        this.readNow()
      );
      this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
      if (!result.accepted) {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }
      this.closeStream(stream, code, "edge");
      return;
    }

    // edge 只能发起 open、在已打开流上发送 data/credit，以及请求 close。
    this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
  }

  private handleAgentFrame(session: AuthenticatedPeerSession, frame: TunnelFrame): void {
    const stream = this.streamsByServerId.get(streamKey(frame.streamId));
    if (stream === undefined || stream.agentPeerId !== session.peerId || session.identity.agentId !== stream.agentId) {
      this.sendAgentError(session.peerId, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    if (frame.type === FrameType.STREAM_OPENED) {
      if (this.readNow() >= stream.capabilityExpiresAtMs) {
        this.abortStream(stream, TunnelErrorCode.CAPABILITY_INVALID, true);
        return;
      }

      const result = stream.lifecycle.handleInbound(frame, stream.relaySessionId, this.readNow());
      if (!result.accepted || stream.lifecycle.state !== "open") {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }

      if (!this.peerSessions.sendFrame(stream.edgePeerId, streamFrame(FrameType.STREAM_OPENED, stream.edgeStreamId, new Uint8Array()))) {
        this.abortStream(stream, TunnelErrorCode.PEER_DISCONNECTED, false);
      }
      return;
    }

    if (frame.type === FrameType.STREAM_DATA) {
      this.relayDataFromAgent(stream, frame);
      return;
    }

    if (frame.type === FrameType.STREAM_CREDIT) {
      this.relayCreditFromAgent(stream, frame);
      return;
    }

    if (frame.type === FrameType.STREAM_REJECTED || frame.type === FrameType.STREAM_ERROR) {
      const code = errorPayload(frame);
      if (code === undefined) {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }

      const beforeBufferedBytes = stream.lifecycle.bufferedBytes;
      const result = stream.lifecycle.handleInbound(frame, stream.relaySessionId, this.readNow());
      this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
      if (!result.accepted) {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }

      const translated = streamFrame(frame.type, stream.edgeStreamId, encodeStreamErrorPayload({ code }));
      this.peerSessions.sendFrame(stream.edgePeerId, translated);
      this.removeStream(stream);
      return;
    }

    if (frame.type === FrameType.STREAM_CLOSE) {
      const code = closePayload(frame);
      if (code === undefined) {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }
      const beforeBufferedBytes = stream.lifecycle.bufferedBytes;
      const result = stream.lifecycle.handleInbound(
        streamFrame(FrameType.STREAM_CLOSE, stream.streamId, encodeStreamClosePayload({ code })),
        stream.relaySessionId,
        this.readNow()
      );
      this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
      if (!result.accepted) {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }
      this.closeStream(stream, code, "agent");
      return;
    }

    // agent 只能报告 opened/rejected/error，或在已打开流上发送 data/credit/close。
    this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
  }

  private relayDataFromEdge(stream: ActiveStream, frame: TunnelFrame): void {
    const payload = decodeFramePayload(frame);
    if (stream.lifecycle.state !== "open" || !(payload instanceof Uint8Array) || payload.byteLength === 0) {
      this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
      return;
    }

    if (!this.canReserveAuthorizationBytes(stream, payload.byteLength)) {
      this.abortStream(stream, TunnelErrorCode.FLOW_CONTROL_VIOLATION, true);
      return;
    }

    const forwarded = streamFrame(FrameType.STREAM_DATA, stream.streamId, payload);
    const beforeBufferedBytes = stream.lifecycle.bufferedBytes;
    const result = stream.lifecycle.handleOutbound(forwarded, stream.relaySessionId, this.readNow());
    this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
    if (!result.accepted) {
      this.abortStream(stream, result.errorCode ?? TunnelErrorCode.PROTOCOL_VIOLATION, true);
      return;
    }

    this.queueOrSendData(stream, "agent", forwarded);
  }

  private relayDataFromAgent(stream: ActiveStream, frame: TunnelFrame): void {
    const payload = decodeFramePayload(frame);
    if (stream.lifecycle.state !== "open" || !(payload instanceof Uint8Array) || payload.byteLength === 0) {
      this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
      return;
    }

    if (!this.canReserveAuthorizationBytes(stream, payload.byteLength)) {
      this.abortStream(stream, TunnelErrorCode.FLOW_CONTROL_VIOLATION, true);
      return;
    }

    const beforeBufferedBytes = stream.lifecycle.bufferedBytes;
    const result = stream.lifecycle.handleInbound(frame, stream.relaySessionId, this.readNow());
    this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
    if (!result.accepted) {
      this.abortStream(stream, result.errorCode ?? TunnelErrorCode.PROTOCOL_VIOLATION, true);
      return;
    }

    this.queueOrSendData(stream, "edge", streamFrame(FrameType.STREAM_DATA, stream.edgeStreamId, payload));
  }

  /** edge 发出的 credit 仅在目标 agent WSS 可接收时才应用，避免提前放宽发送窗口。 */
  private relayCreditFromEdge(stream: ActiveStream, frame: TunnelFrame): void {
    const bytes = creditPayload(frame);
    if (stream.lifecycle.state !== "open" || bytes === undefined) {
      this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
      return;
    }

    if (this.shouldDelayFramesFor(stream.agentPeerId)) {
      this.queueCredit(stream, "agent", bytes);
      return;
    }

    this.forwardCreditFromEdge(stream, bytes);
  }

  /** agent 发出的 credit 仅在目标 edge WSS 可接收时才应用，避免提前放宽发送窗口。 */
  private relayCreditFromAgent(stream: ActiveStream, frame: TunnelFrame): void {
    const bytes = creditPayload(frame);
    if (stream.lifecycle.state !== "open" || bytes === undefined) {
      this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
      return;
    }

    if (this.shouldDelayFramesFor(stream.edgePeerId)) {
      this.queueCredit(stream, "edge", bytes);
      return;
    }

    this.forwardCreditFromAgent(stream, bytes);
  }

  private forwardCreditFromEdge(stream: ActiveStream, bytes: number): void {
    const forwarded = streamFrame(
      FrameType.STREAM_CREDIT,
      stream.streamId,
      encodeStreamCreditPayload({ bytes })
    );
    const beforeBufferedBytes = stream.lifecycle.bufferedBytes;
    let result;

    if (stream.lifecycle.pendingReceiveCreditBytes >= bytes) {
      result = stream.lifecycle.handleOutbound(forwarded, stream.relaySessionId, this.readNow());
    } else {
      const queued = stream.lifecycle.queueReceiveCredit(bytes, this.readNow());
      if (!queued.accepted) {
        this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
        this.abortStream(stream, queued.errorCode ?? TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }
      result = stream.lifecycle.handleOutbound(forwarded, stream.relaySessionId, this.readNow());
    }

    this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
    if (!result.accepted) {
      this.abortStream(stream, result.errorCode ?? TunnelErrorCode.PROTOCOL_VIOLATION, true);
      return;
    }

    if (!this.peerSessions.sendFrame(stream.agentPeerId, forwarded)) {
      this.abortStream(stream, TunnelErrorCode.PEER_DISCONNECTED, false);
    }
  }

  private forwardCreditFromAgent(stream: ActiveStream, bytes: number): void {
    const forwarded = streamFrame(
      FrameType.STREAM_CREDIT,
      stream.edgeStreamId,
      encodeStreamCreditPayload({ bytes })
    );
    const beforeBufferedBytes = stream.lifecycle.bufferedBytes;
    const result = stream.lifecycle.handleInbound(
      streamFrame(FrameType.STREAM_CREDIT, stream.streamId, encodeStreamCreditPayload({ bytes })),
      stream.relaySessionId,
      this.readNow()
    );
    this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
    if (!result.accepted) {
      this.abortStream(stream, result.errorCode ?? TunnelErrorCode.PROTOCOL_VIOLATION, true);
      return;
    }

    if (!this.peerSessions.sendFrame(stream.edgePeerId, forwarded)) {
      this.abortStream(stream, TunnelErrorCode.PEER_DISCONNECTED, false);
    }
  }

  private queueOrSendData(stream: ActiveStream, destination: "edge" | "agent", frame: TunnelFrame): void {
    const queue = destination === "agent" ? stream.pendingDataToAgent : stream.pendingDataToEdge;
    const peerId = destination === "agent" ? stream.agentPeerId : stream.edgePeerId;
    if (queue.length > 0 || this.shouldDelayFramesFor(peerId, frame.payload.byteLength)) {
      queue.push(Object.freeze({ frame }));
      return;
    }

    if (!this.peerSessions.sendFrame(peerId, frame)) {
      this.abortStream(stream, TunnelErrorCode.PEER_DISCONNECTED, false);
    }
  }

  private queueCredit(stream: ActiveStream, destination: "edge" | "agent", bytes: number): void {
    const total = destination === "agent" ? stream.pendingCreditToAgentBytes : stream.pendingCreditToEdgeBytes;
    if (bytes <= 0 || total + bytes > stream.lifecycle.initialReceiveCreditBytes) {
      this.abortStream(stream, TunnelErrorCode.FLOW_CONTROL_VIOLATION, true);
      return;
    }

    if (destination === "agent") {
      stream.pendingCreditToAgent.push(Object.freeze({ bytes }));
      stream.pendingCreditToAgentBytes += bytes;
    } else {
      stream.pendingCreditToEdge.push(Object.freeze({ bytes }));
      stream.pendingCreditToEdgeBytes += bytes;
    }
  }

  private flushOnePendingFrame(stream: ActiveStream, destination: "edge" | "agent"): void {
    const peerId = destination === "agent" ? stream.agentPeerId : stream.edgePeerId;
    if (this.shouldDelayFramesFor(peerId)) {
      return;
    }

    const creditQueue = destination === "agent" ? stream.pendingCreditToAgent : stream.pendingCreditToEdge;
    const pendingCredit = creditQueue.shift();
    if (pendingCredit !== undefined) {
      if (destination === "agent") {
        stream.pendingCreditToAgentBytes -= pendingCredit.bytes;
        this.forwardCreditFromEdge(stream, pendingCredit.bytes);
      } else {
        stream.pendingCreditToEdgeBytes -= pendingCredit.bytes;
        this.forwardCreditFromAgent(stream, pendingCredit.bytes);
      }

      if (!this.streamsByServerId.has(stream.serverStreamKey) || this.shouldDelayFramesFor(peerId)) {
        return;
      }
    }

    const dataQueue = destination === "agent" ? stream.pendingDataToAgent : stream.pendingDataToEdge;
    const pendingData = dataQueue.shift();
    if (pendingData !== undefined) {
      if (this.shouldDelayFramesFor(peerId, pendingData.frame.payload.byteLength)) {
        dataQueue.unshift(pendingData);
        return;
      }
      if (!this.peerSessions.sendFrame(peerId, pendingData.frame)) {
        this.abortStream(stream, TunnelErrorCode.PEER_DISCONNECTED, false);
      }
    }
  }

  private shouldDelayFramesFor(peerId: string, nextFrameBytes = 0): boolean {
    const bufferedBytes = this.peerSessions.getSendBufferedBytes?.(peerId);
    return (
      bufferedBytes !== undefined &&
      bufferedBytes + nextFrameBytes >= this.resourceLimits.maxBufferedBytesPerStream
    );
  }

  private canReserveAuthorizationBytes(stream: ActiveStream, bytes: number): boolean {
    const authorizationBufferedBytes = this.bufferedBytesByAuthorization.get(stream.authorizationKey) ?? 0;
    const userBufferedBytes = this.bufferedBytesByEdgeUser.get(stream.edgeUserId) ?? 0;
    return (
      bytes <= stream.quota.maxBufferedBytes - authorizationBufferedBytes &&
      bytes <= stream.quota.maxBufferedBytes - userBufferedBytes
    );
  }

  private reconcileAuthorizationBytes(stream: ActiveStream, beforeBufferedBytes: number): void {
    const delta = stream.lifecycle.bufferedBytes - beforeBufferedBytes;
    if (delta === 0) {
      return;
    }

    const current = this.bufferedBytesByAuthorization.get(stream.authorizationKey) ?? 0;
    const next = current + delta;
    if (next <= 0) {
      this.bufferedBytesByAuthorization.delete(stream.authorizationKey);
    } else {
      this.bufferedBytesByAuthorization.set(stream.authorizationKey, next);
    }

    const currentUserBytes = this.bufferedBytesByEdgeUser.get(stream.edgeUserId) ?? 0;
    const nextUserBytes = currentUserBytes + delta;
    if (nextUserBytes <= 0) {
      this.bufferedBytesByEdgeUser.delete(stream.edgeUserId);
    } else {
      this.bufferedBytesByEdgeUser.set(stream.edgeUserId, nextUserBytes);
    }
  }

  private closeStream(stream: ActiveStream, code: StreamCloseCodeValue, origin?: "edge" | "agent"): void {
    if (origin !== "edge") {
      this.peerSessions.sendFrame(
        stream.edgePeerId,
        streamFrame(FrameType.STREAM_CLOSE, stream.edgeStreamId, encodeStreamClosePayload({ code }))
      );
    }
    if (origin !== "agent") {
      this.peerSessions.sendFrame(
        stream.agentPeerId,
        streamFrame(FrameType.STREAM_CLOSE, stream.streamId, encodeStreamClosePayload({ code }))
      );
    }
    this.removeStream(stream);
  }

  private handleSessionRemoval(session: AuthenticatedPeerSession): void {
    for (const stream of [...this.streamsByServerId.values()]) {
      if (stream.edgePeerId === session.peerId) {
        // edge 已不可用，不能再向它发送错误；必须通知仍在线 agent 关闭其本地 TCP。
        this.peerSessions.sendFrame(
          stream.agentPeerId,
          streamFrame(
            FrameType.STREAM_CLOSE,
            stream.streamId,
            encodeStreamClosePayload({ code: StreamCloseCode.PEER_DISCONNECTED })
          )
        );
        this.removeStream(stream);
        continue;
      }

      if (stream.agentPeerId === session.peerId) {
        // agent 已不可用，保留既有 edge 错误契约；绝不向断开的 agent 写入。
        this.sendEdgeError(stream.edgePeerId, stream.edgeStreamId, TunnelErrorCode.PEER_DISCONNECTED);
        this.removeStream(stream);
      }
    }
  }

  private handleRevocation(revocation: AuthorizationRevocation): void {
    for (const stream of [...this.streamsByServerId.values()]) {
      if (
        stream.edgeUserId === revocation.edgeUserId &&
        stream.edgeDeviceId === revocation.edgeDeviceId &&
        stream.agentId === revocation.agentId
      ) {
        this.abortStream(stream, TunnelErrorCode.AUTH_UNAUTHORIZED, true);
      }
    }
  }

  private allocateServerStreamId(): Uint8Array {
    let streamId: Uint8Array;
    do {
      streamId = createStreamId();
    } while (this.streamsByServerId.has(streamKey(streamId)));
    return streamId;
  }

  private abortStream(stream: ActiveStream, errorCode: TunnelErrorCodeValue, notifyAgent: boolean): void {
    this.sendEdgeError(stream.edgePeerId, stream.edgeStreamId, errorCode);
    if (notifyAgent) {
      this.peerSessions.sendFrame(
        stream.agentPeerId,
        streamFrame(
          FrameType.STREAM_CLOSE,
          stream.streamId,
          encodeStreamClosePayload({ code: closeCodeForError(errorCode) })
        )
      );
    }
    this.removeStream(stream);
  }

  private removeStream(stream: ActiveStream): void {
    if (this.streamsByServerId.get(stream.serverStreamKey) !== stream) {
      return;
    }

    const beforeBufferedBytes = stream.lifecycle.bufferedBytes;
    stream.lifecycle.onSessionDisconnected(stream.relaySessionId, this.readNow());
    this.reconcileAuthorizationBytes(stream, beforeBufferedBytes);
    stream.pendingDataToAgent.length = 0;
    stream.pendingDataToEdge.length = 0;
    stream.pendingCreditToAgent.length = 0;
    stream.pendingCreditToEdge.length = 0;
    stream.pendingCreditToAgentBytes = 0;
    stream.pendingCreditToEdgeBytes = 0;
    this.streamsByServerId.delete(stream.serverStreamKey);
    this.streamsByEdgeId.delete(stream.edgeStreamKey);
    const nextCount = (this.streamCountsByAuthorization.get(stream.authorizationKey) ?? 1) - 1;
    if (nextCount <= 0) {
      this.streamCountsByAuthorization.delete(stream.authorizationKey);
    } else {
      this.streamCountsByAuthorization.set(stream.authorizationKey, nextCount);
    }
    const nextUserCount = (this.streamCountsByEdgeUser.get(stream.edgeUserId) ?? 1) - 1;
    if (nextUserCount <= 0) {
      this.streamCountsByEdgeUser.delete(stream.edgeUserId);
    } else {
      this.streamCountsByEdgeUser.set(stream.edgeUserId, nextUserCount);
    }
  }

  private sendEdgeRejected(peerId: string, streamId: Uint8Array, code: TunnelErrorCodeValue): void {
    this.peerSessions.sendFrame(
      peerId,
      streamFrame(FrameType.STREAM_REJECTED, streamId, encodeStreamErrorPayload({ code }))
    );
  }

  private sendEdgeError(peerId: string, streamId: Uint8Array, code: TunnelErrorCodeValue): void {
    this.peerSessions.sendFrame(
      peerId,
      streamFrame(FrameType.STREAM_ERROR, streamId, encodeStreamErrorPayload({ code }))
    );
  }

  private sendAgentError(peerId: string, streamId: Uint8Array, code: TunnelErrorCodeValue): void {
    this.peerSessions.sendFrame(
      peerId,
      streamFrame(FrameType.STREAM_ERROR, streamId, encodeStreamErrorPayload({ code }))
    );
  }

  private readNow(): number {
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new TypeError("clock must return a non-negative safe integer millisecond timestamp");
    }
    return nowMs;
  }
}
