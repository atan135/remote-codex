import {
  createStreamId,
  decodeFramePayload,
  encodeStreamClosePayload,
  encodeStreamErrorPayload,
  encodeStreamOpenPayload,
  FrameType,
  issueCapability,
  MAX_CAPABILITY_WINDOW_MS,
  StreamCloseCode,
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
  PeerSessionStreamFrameListener
} from "./peer-session.js";

/** Stream 层所需的最小 peer 会话能力；不暴露 socket 或任何 TLS 明文。 */
export interface StreamPeerSessionGateway {
  getAgentSession(agentId: string): AuthenticatedPeerSession | undefined;
  sendFrame(peerId: string, frame: TunnelFrame): boolean;
  subscribeStreamFrames(listener: PeerSessionStreamFrameListener): () => void;
  subscribeSessionRemovals(listener: PeerSessionRemovalListener): () => void;
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
}

interface ActiveStream extends Omit<StreamOwnership, "state"> {
  readonly serverStreamKey: string;
  readonly edgeStreamKey: string;
  readonly authorizationKey: string;
  readonly lifecycle: StreamLifecycle;
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
  private readonly streamsByServerId = new Map<string, ActiveStream>();
  private readonly streamsByEdgeId = new Map<string, ActiveStream>();
  private readonly streamCountsByAuthorization = new Map<string, number>();
  private readonly unsubscribeFrames: () => void;
  private readonly unsubscribeRemovals: () => void;
  private readonly unsubscribeRevocations: () => void;

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
    this.unsubscribeFrames = this.peerSessions.subscribeStreamFrames((session, frame) => this.handleFrame(session, frame));
    this.unsubscribeRemovals = this.peerSessions.subscribeSessionRemovals((session) => this.handleSessionRemoval(session));
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
          state: stream.lifecycle.state
        })
      )
    );
  }

  /** 由运行时定时调用；测试可推进受控时钟后直接调用。 */
  public expireOpenStreams(): void {
    const nowMs = this.readNow();
    for (const stream of [...this.streamsByServerId.values()]) {
      if (stream.lifecycle.state === "open") {
        continue;
      }

      if (nowMs >= stream.capabilityExpiresAtMs) {
        this.abortStream(stream, TunnelErrorCode.CAPABILITY_INVALID, true);
        continue;
      }

      const result = stream.lifecycle.tick(nowMs);
      if (result.errorCode !== undefined) {
        this.abortStream(stream, result.errorCode, true);
      }
    }
  }

  public close(): void {
    this.unsubscribeFrames();
    this.unsubscribeRemovals();
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
        this.sendEdgeRejected(session.peerId, frame.streamId, TunnelErrorCode.INTERNAL_ERROR);
      } else {
        this.sendAgentError(session.peerId, frame.streamId, TunnelErrorCode.INTERNAL_ERROR);
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
    if ((this.streamCountsByAuthorization.get(countKey) ?? 0) >= route.quota.maxConcurrentStreams) {
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
    const lifecycle = new StreamLifecycle({
      streamId: serverStreamId,
      sessionId: agentSession.peerId,
      limits: this.resourceLimits,
      now: this.now
    });
    lifecycle.handleInbound(forwardedOpen, agentSession.peerId, nowMs);
    lifecycle.authorize(nowMs);
    lifecycle.beginConnecting(nowMs);

    const stream: ActiveStream = Object.freeze({
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
      serverStreamKey: streamKey(serverStreamId),
      edgeStreamKey: edgeKey,
      authorizationKey: countKey,
      lifecycle
    });
    this.streamsByServerId.set(stream.serverStreamKey, stream);
    this.streamsByEdgeId.set(stream.edgeStreamKey, stream);
    this.streamCountsByAuthorization.set(countKey, (this.streamCountsByAuthorization.get(countKey) ?? 0) + 1);

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

    if (frame.type === FrameType.STREAM_CLOSE) {
      const code = closePayload(frame);
      if (code === undefined) {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }
      this.peerSessions.sendFrame(
        stream.agentPeerId,
        streamFrame(FrameType.STREAM_CLOSE, stream.streamId, encodeStreamClosePayload({ code }))
      );
      this.removeStream(stream);
      return;
    }

    // 阶段 4 尚未开始 data/credit relay；任何此类帧都不会离开 server。
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

      const result = stream.lifecycle.handleInbound(frame, session.peerId, this.readNow());
      if (!result.accepted || stream.lifecycle.state !== "open") {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }

      this.peerSessions.sendFrame(stream.edgePeerId, streamFrame(FrameType.STREAM_OPENED, stream.edgeStreamId, new Uint8Array()));
      return;
    }

    if (frame.type === FrameType.STREAM_REJECTED || frame.type === FrameType.STREAM_ERROR) {
      const code = errorPayload(frame);
      if (code === undefined) {
        this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
        return;
      }

      const result = stream.lifecycle.handleInbound(frame, session.peerId, this.readNow());
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
      this.peerSessions.sendFrame(
        stream.edgePeerId,
        streamFrame(FrameType.STREAM_CLOSE, stream.edgeStreamId, encodeStreamClosePayload({ code }))
      );
      this.removeStream(stream);
      return;
    }

    // agent 不能在 opened 前写 data；本阶段 opened 后同样不允许 relay data/credit。
    this.abortStream(stream, TunnelErrorCode.PROTOCOL_VIOLATION, true);
  }

  private handleSessionRemoval(session: AuthenticatedPeerSession): void {
    for (const stream of [...this.streamsByServerId.values()]) {
      if (stream.edgePeerId === session.peerId || stream.agentPeerId === session.peerId) {
        this.abortStream(stream, TunnelErrorCode.PEER_DISCONNECTED, false);
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

    this.streamsByServerId.delete(stream.serverStreamKey);
    this.streamsByEdgeId.delete(stream.edgeStreamKey);
    const nextCount = (this.streamCountsByAuthorization.get(stream.authorizationKey) ?? 1) - 1;
    if (nextCount <= 0) {
      this.streamCountsByAuthorization.delete(stream.authorizationKey);
    } else {
      this.streamCountsByAuthorization.set(stream.authorizationKey, nextCount);
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
