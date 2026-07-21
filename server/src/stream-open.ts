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
import {
  serializeStreamAuditEvent,
  snapshotPositiveCounters,
  type StreamAuditEvent,
  type StreamAuditLogger,
  type StreamMetricsSnapshot
} from "./observability.js";

/** Stream 层所需的最小 peer 会话能力；不暴露 socket 或任何 TLS 明文。 */
export interface StreamPeerSessionGateway {
  getAgentSession(agentId: string): AuthenticatedPeerSession | undefined;
  /** 可选的已认证会话快照，仅用于聚合指标，绝不暴露 WebSocket 或 frame 内容。 */
  getActiveSessions?(): readonly AuthenticatedPeerSession[];
  sendFrame(peerId: string, frame: TunnelFrame): boolean;
  subscribeStreamFrames(listener: PeerSessionStreamFrameListener): () => void;
  subscribeSessionRemovals(listener: PeerSessionRemovalListener): () => void;
  /** 可选的本地 WSS 发送队列水位；未实现时仍由 credit 和内存上限保护。 */
  getSendBufferedBytes?(peerId: string): number | undefined;
  /** 可选的 WSS 发送完成通知，用于恢复被背压延迟的帧。 */
  subscribeSendAvailability?(listener: PeerSessionSendAvailabilityListener): () => void;
}

/**
 * server 进程内的四维资源上限。授权配额仍是更细粒度的额外约束；本配置用于
 * 防止单个 device、共享 agent 或全局流量绕过授权记录的资源边界。
 */
export interface StreamQuotaLimits {
  readonly maxConcurrentStreamsPerUser?: number;
  readonly maxConcurrentStreamsPerDevice?: number;
  readonly maxConcurrentStreamsPerAgent?: number;
  readonly maxConcurrentStreamsGlobal?: number;
  readonly maxBufferedBytesPerUser?: number;
  readonly maxBufferedBytesPerDevice?: number;
  readonly maxBufferedBytesPerAgent?: number;
  readonly maxBufferedBytesGlobal?: number;
  /** 每个 user/device/agent 以及整个 server 共享的开流频率上限。 */
  readonly maxOpenAttemptsPerWindow?: number;
  readonly openRateWindowMs?: number;
}

interface ResolvedStreamQuotaLimits {
  readonly maxConcurrentStreamsPerUser: number;
  readonly maxConcurrentStreamsPerDevice: number;
  readonly maxConcurrentStreamsPerAgent: number;
  readonly maxConcurrentStreamsGlobal: number;
  readonly maxBufferedBytesPerUser: number;
  readonly maxBufferedBytesPerDevice: number;
  readonly maxBufferedBytesPerAgent: number;
  readonly maxBufferedBytesGlobal: number;
  readonly maxOpenAttemptsPerWindow: number;
  readonly openRateWindowMs: number;
}

export interface StreamOpenCoordinatorOptions {
  readonly peerSessions: StreamPeerSessionGateway;
  readonly authorizationRegistry: AuthorizationRegistry;
  /** 仅由 server 进程注入的 capability 签名凭据。 */
  readonly signingCredentials: ServerSigningCredentials;
  readonly allowedDestination: AllowedDestination;
  readonly resourceLimits?: ResourceLimits;
  readonly capabilityTtlMs?: number;
  readonly quotaLimits?: StreamQuotaLimits;
  /** 已序列化的安全审计输出；不得传入会记录原始 frame 的实现。 */
  readonly auditLogger?: StreamAuditLogger;
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
  readonly createdAtMs: number;
  /** 仅用于 shared 状态机的内部绑定值，不可由任意 peer 指定。 */
  readonly relaySessionId: string;
  readonly lifecycle: StreamLifecycle;
  readonly pendingDataToAgent: PendingDataFrame[];
  readonly pendingDataToEdge: PendingDataFrame[];
  readonly pendingCreditToAgent: PendingCreditFrame[];
  readonly pendingCreditToEdge: PendingCreditFrame[];
  pendingCreditToAgentBytes: number;
  pendingCreditToEdgeBytes: number;
  edgeToAgentBytes: number;
  agentToEdgeBytes: number;
}

interface RecentlyClosedEdgeStream {
  readonly edgePeerId: string;
  readonly expiresAtMs: number;
}

// WSS is full duplex: a peer can have a credit/data/close frame in flight when
// the other side closes the stream. Remembering only recently closed IDs keeps
// that terminal race from escalating to a connection-level protocol failure.
const RECENTLY_CLOSED_EDGE_STREAM_GRACE_MS = 30_000;
const MAX_RECENTLY_CLOSED_EDGE_STREAMS = 1_024;

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

function assertPositiveSafeInteger(value: number, code: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(code);
  }
}

function resolveQuotaLimits(
  resourceLimits: ResourceLimits,
  configuredLimits: StreamQuotaLimits | undefined
): ResolvedStreamQuotaLimits {
  const configured = configuredLimits ?? {};
  const concurrentDefault = resourceLimits.maxConcurrentStreams;
  const bufferedDefault = resourceLimits.maxAggregateBufferedBytes;
  const limits: ResolvedStreamQuotaLimits = {
    maxConcurrentStreamsPerUser: configured.maxConcurrentStreamsPerUser ?? concurrentDefault,
    maxConcurrentStreamsPerDevice: configured.maxConcurrentStreamsPerDevice ?? concurrentDefault,
    maxConcurrentStreamsPerAgent: configured.maxConcurrentStreamsPerAgent ?? concurrentDefault,
    maxConcurrentStreamsGlobal: configured.maxConcurrentStreamsGlobal ?? concurrentDefault,
    maxBufferedBytesPerUser: configured.maxBufferedBytesPerUser ?? bufferedDefault,
    maxBufferedBytesPerDevice: configured.maxBufferedBytesPerDevice ?? bufferedDefault,
    maxBufferedBytesPerAgent: configured.maxBufferedBytesPerAgent ?? bufferedDefault,
    maxBufferedBytesGlobal: configured.maxBufferedBytesGlobal ?? bufferedDefault,
    maxOpenAttemptsPerWindow: configured.maxOpenAttemptsPerWindow ?? concurrentDefault * 4,
    openRateWindowMs: configured.openRateWindowMs ?? 60_000
  };

  for (const [key, value] of Object.entries(limits)) {
    assertPositiveSafeInteger(value, `SERVER_STREAM_QUOTA_LIMIT_INVALID_${key}`);
  }

  if (
    limits.maxBufferedBytesPerUser > resourceLimits.maxAggregateBufferedBytes ||
    limits.maxBufferedBytesPerDevice > resourceLimits.maxAggregateBufferedBytes ||
    limits.maxBufferedBytesPerAgent > resourceLimits.maxAggregateBufferedBytes ||
    limits.maxBufferedBytesGlobal > resourceLimits.maxAggregateBufferedBytes
  ) {
    throw new RangeError("SERVER_STREAM_QUOTA_BUFFER_LIMIT_EXCEEDS_RESOURCE_LIMIT");
  }

  return Object.freeze(limits);
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
  private readonly quotaLimits: ResolvedStreamQuotaLimits;
  private readonly capabilityTtlMs: number;
  private readonly now: () => number;
  private readonly auditLogger: StreamAuditLogger | undefined;
  /** 所有存量 stream 共用的聚合字节预算，防止一个 WSS 会话无限积压。 */
  private readonly bufferBudget: StreamBufferBudget;
  private readonly streamsByServerId = new Map<string, ActiveStream>();
  private readonly streamsByEdgeId = new Map<string, ActiveStream>();
  private readonly recentlyClosedEdgeStreams = new Map<string, RecentlyClosedEdgeStream>();
  private readonly streamCountsByAuthorization = new Map<string, number>();
  private readonly streamCountsByEdgeUser = new Map<string, number>();
  private readonly streamCountsByEdgeDevice = new Map<string, number>();
  private readonly streamCountsByAgent = new Map<string, number>();
  private readonly bufferedBytesByAuthorization = new Map<string, number>();
  private readonly bufferedBytesByEdgeUser = new Map<string, number>();
  private readonly bufferedBytesByEdgeDevice = new Map<string, number>();
  private readonly bufferedBytesByAgent = new Map<string, number>();
  private readonly rejectedStreamsByEdgeUser = new Map<string, number>();
  private readonly closedStreamsByReason = new Map<string, number>();
  private readonly openAttemptsByEdgeUser = new Map<string, number[]>();
  private readonly openAttemptsByEdgeDevice = new Map<string, number[]>();
  private readonly openAttemptsByAgent = new Map<string, number[]>();
  private readonly globalOpenAttempts: number[] = [];
  private readonly unsubscribeFrames: () => void;
  private readonly unsubscribeRemovals: () => void;
  private readonly unsubscribeRevocations: () => void;
  private readonly unsubscribeSendAvailability: () => void;
  private flushingPendingFrames = false;
  private peakBufferedBytes = 0;

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
    this.quotaLimits = resolveQuotaLimits(this.resourceLimits, options.quotaLimits);
    this.capabilityTtlMs = options.capabilityTtlMs ?? Math.min(30_000, MAX_CAPABILITY_WINDOW_MS);
    if (
      !Number.isSafeInteger(this.capabilityTtlMs) ||
      this.capabilityTtlMs < 1 ||
      this.capabilityTtlMs > MAX_CAPABILITY_WINDOW_MS
    ) {
      throw new RangeError("SERVER_STREAM_CAPABILITY_TTL_INVALID");
    }

    this.now = options.now ?? Date.now;
    this.auditLogger = options.auditLogger;
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

  /**
   * 返回只含计数和身份维度的指标快照，供受控的进程内监控适配器拉取。它不经
   * `/health` 或 WebSocket 暴露，也不含 stream payload、目的地址或认证材料。
   */
  public getMetrics(): StreamMetricsSnapshot {
    const sessions = this.peerSessions.getActiveSessions?.() ?? [];
    let authenticatedEdgePeers = 0;
    let authenticatedAgentPeers = 0;

    for (const session of sessions) {
      if (session.role === "edge-client") {
        authenticatedEdgePeers += 1;
      } else if (session.role === "egress-agent") {
        authenticatedAgentPeers += 1;
      }
    }

    return Object.freeze({
      authenticatedEdgePeers,
      authenticatedAgentPeers,
      activeStreamsByAgent: snapshotPositiveCounters(this.streamCountsByAgent),
      rejectedStreamsByEdgeUser: snapshotPositiveCounters(this.rejectedStreamsByEdgeUser),
      closedStreamsByReason: snapshotPositiveCounters(this.closedStreamsByReason),
      bufferWatermark: Object.freeze({
        currentBytes: this.bufferBudget.totalBufferedBytes,
        peakBytes: this.peakBufferedBytes,
        limitBytes: this.quotaLimits.maxBufferedBytesGlobal
      })
    });
  }

  /** 由运行时定时调用；测试可推进受控时钟后直接调用。 */
  public expireOpenStreams(): void {
    this.flushPendingFrames();
    const nowMs = this.readNow();
    this.pruneOpenAttempts(nowMs);
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
      this.removeStream(stream, "SERVER_SHUTDOWN");
    }
    this.recentlyClosedEdgeStreams.clear();
    this.openAttemptsByEdgeUser.clear();
    this.openAttemptsByEdgeDevice.clear();
    this.openAttemptsByAgent.clear();
    this.globalOpenAttempts.length = 0;
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
          this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
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
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.AUTH_UNAUTHORIZED);
      return;
    }

    const edgeKey = edgeStreamKey(session.peerId, frame.streamId);
    if (this.streamsByEdgeId.has(edgeKey)) {
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    const payload = decodeFramePayload(frame);
    if (payload === undefined || payload instanceof Uint8Array || !("hostname" in payload) || !("port" in payload)) {
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.PROTOCOL_VIOLATION);
      return;
    }

    let destination: AllowedDestination;
    try {
      destination = validateDestination(payload.hostname, payload.port, this.allowedDestination);
    } catch {
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.DESTINATION_REJECTED);
      return;
    }

    const route = this.authorizationRegistry.resolveAgentForEdge(session.identity);
    if (route === undefined) {
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.AUTH_UNAUTHORIZED);
      return;
    }

    const nowMs = this.readNow();
    const countKey = authorizationKey(session.identity.edgeUserId, session.identity.edgeDeviceId, route.agentId);
    if (!this.consumeOpenAttempt(session.identity.edgeUserId, session.identity.edgeDeviceId, route.agentId, nowMs)) {
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.STREAM_LIMIT_EXCEEDED, route.agentId);
      return;
    }

    if (!this.canOpenStream(session.identity.edgeUserId, session.identity.edgeDeviceId, route.agentId, countKey, route.quota)) {
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.STREAM_LIMIT_EXCEEDED, route.agentId);
      return;
    }

    const agentSession = this.peerSessions.getAgentSession(route.agentId);
    if (agentSession === undefined) {
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.PEER_DISCONNECTED, route.agentId);
      return;
    }

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
      this.sendEdgeRejected(session, frame.streamId, TunnelErrorCode.FLOW_CONTROL_VIOLATION, route.agentId);
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
      createdAtMs: nowMs,
      relaySessionId,
      lifecycle,
      pendingDataToAgent: [],
      pendingDataToEdge: [],
      pendingCreditToAgent: [],
      pendingCreditToEdge: [],
      pendingCreditToAgentBytes: 0,
      pendingCreditToEdgeBytes: 0,
      edgeToAgentBytes: 0,
      agentToEdgeBytes: 0
    };
    this.streamsByServerId.set(stream.serverStreamKey, stream);
    this.streamsByEdgeId.set(stream.edgeStreamKey, stream);
    this.incrementCounter(this.streamCountsByAuthorization, countKey);
    this.incrementCounter(this.streamCountsByEdgeUser, stream.edgeUserId);
    this.incrementCounter(this.streamCountsByEdgeDevice, stream.edgeDeviceId);
    this.incrementCounter(this.streamCountsByAgent, stream.agentId);
    this.recordState(stream);

    if (!this.peerSessions.sendFrame(agentSession.peerId, forwardedOpen)) {
      this.abortStream(stream, TunnelErrorCode.PEER_DISCONNECTED, false);
    }
  }

  private handleNonOpenEdgeFrame(session: AuthenticatedPeerSession, frame: TunnelFrame): void {
    const stream = this.streamsByEdgeId.get(edgeStreamKey(session.peerId, frame.streamId));
    if (stream === undefined || stream.edgePeerId !== session.peerId) {
      if (this.isLateFrameForRecentlyClosedEdgeStream(session.peerId, frame)) {
        return;
      }
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

      this.recordState(stream);

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
      this.removeStream(stream, code);
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

    stream.edgeToAgentBytes += payload.byteLength;

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

    stream.agentToEdgeBytes += payload.byteLength;

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
    const deviceBufferedBytes = this.bufferedBytesByEdgeDevice.get(stream.edgeDeviceId) ?? 0;
    const agentBufferedBytes = this.bufferedBytesByAgent.get(stream.agentId) ?? 0;
    return (
      bytes <= stream.quota.maxBufferedBytes - authorizationBufferedBytes &&
      bytes <= stream.quota.maxBufferedBytes - userBufferedBytes &&
      bytes <= this.quotaLimits.maxBufferedBytesPerUser - userBufferedBytes &&
      bytes <= this.quotaLimits.maxBufferedBytesPerDevice - deviceBufferedBytes &&
      bytes <= this.quotaLimits.maxBufferedBytesPerAgent - agentBufferedBytes &&
      bytes <= this.quotaLimits.maxBufferedBytesGlobal - this.bufferBudget.totalBufferedBytes
    );
  }

  private reconcileAuthorizationBytes(stream: ActiveStream, beforeBufferedBytes: number): void {
    const delta = stream.lifecycle.bufferedBytes - beforeBufferedBytes;
    if (delta === 0) {
      return;
    }

    const current = this.bufferedBytesByAuthorization.get(stream.authorizationKey) ?? 0;
    this.updateCounterByDelta(this.bufferedBytesByAuthorization, stream.authorizationKey, current, delta);

    const currentUserBytes = this.bufferedBytesByEdgeUser.get(stream.edgeUserId) ?? 0;
    this.updateCounterByDelta(this.bufferedBytesByEdgeUser, stream.edgeUserId, currentUserBytes, delta);
    const currentDeviceBytes = this.bufferedBytesByEdgeDevice.get(stream.edgeDeviceId) ?? 0;
    this.updateCounterByDelta(this.bufferedBytesByEdgeDevice, stream.edgeDeviceId, currentDeviceBytes, delta);
    const currentAgentBytes = this.bufferedBytesByAgent.get(stream.agentId) ?? 0;
    this.updateCounterByDelta(this.bufferedBytesByAgent, stream.agentId, currentAgentBytes, delta);
    this.peakBufferedBytes = Math.max(this.peakBufferedBytes, this.bufferBudget.totalBufferedBytes);
  }

  private canOpenStream(
    edgeUserId: string,
    edgeDeviceId: string,
    agentId: string,
    authorizationCountKey: string,
    quota: AuthorizationQuota
  ): boolean {
    return (
      (this.streamCountsByAuthorization.get(authorizationCountKey) ?? 0) < quota.maxConcurrentStreams &&
      (this.streamCountsByEdgeUser.get(edgeUserId) ?? 0) < this.quotaLimits.maxConcurrentStreamsPerUser &&
      (this.streamCountsByEdgeDevice.get(edgeDeviceId) ?? 0) < this.quotaLimits.maxConcurrentStreamsPerDevice &&
      (this.streamCountsByAgent.get(agentId) ?? 0) < this.quotaLimits.maxConcurrentStreamsPerAgent &&
      this.streamsByServerId.size < this.quotaLimits.maxConcurrentStreamsGlobal
    );
  }

  /** 在单个事件循环轮次内检查并写入四维开流频率窗口，避免部分计数更新。 */
  private consumeOpenAttempt(edgeUserId: string, edgeDeviceId: string, agentId: string, nowMs: number): boolean {
    const userAttempts = this.recentAttempts(this.openAttemptsByEdgeUser, edgeUserId, nowMs);
    const deviceAttempts = this.recentAttempts(this.openAttemptsByEdgeDevice, edgeDeviceId, nowMs);
    const agentAttempts = this.recentAttempts(this.openAttemptsByAgent, agentId, nowMs);
    this.pruneTimestampArray(this.globalOpenAttempts, nowMs);

    if (
      userAttempts.length >= this.quotaLimits.maxOpenAttemptsPerWindow ||
      deviceAttempts.length >= this.quotaLimits.maxOpenAttemptsPerWindow ||
      agentAttempts.length >= this.quotaLimits.maxOpenAttemptsPerWindow ||
      this.globalOpenAttempts.length >= this.quotaLimits.maxOpenAttemptsPerWindow
    ) {
      return false;
    }

    userAttempts.push(nowMs);
    deviceAttempts.push(nowMs);
    agentAttempts.push(nowMs);
    this.globalOpenAttempts.push(nowMs);
    return true;
  }

  private recentAttempts(attemptsByIdentity: Map<string, number[]>, identity: string, nowMs: number): number[] {
    const attempts = attemptsByIdentity.get(identity) ?? [];
    this.pruneTimestampArray(attempts, nowMs);
    if (!attemptsByIdentity.has(identity)) {
      attemptsByIdentity.set(identity, attempts);
    }
    return attempts;
  }

  private pruneOpenAttempts(nowMs: number): void {
    this.pruneAttemptMap(this.openAttemptsByEdgeUser, nowMs);
    this.pruneAttemptMap(this.openAttemptsByEdgeDevice, nowMs);
    this.pruneAttemptMap(this.openAttemptsByAgent, nowMs);
    this.pruneTimestampArray(this.globalOpenAttempts, nowMs);
  }

  private pruneAttemptMap(attemptsByIdentity: Map<string, number[]>, nowMs: number): void {
    for (const [identity, attempts] of attemptsByIdentity) {
      this.pruneTimestampArray(attempts, nowMs);
      if (attempts.length === 0) {
        attemptsByIdentity.delete(identity);
      }
    }
  }

  private pruneTimestampArray(attempts: number[], nowMs: number): void {
    const firstRecentIndex = attempts.findIndex((timestamp) => nowMs - timestamp < this.quotaLimits.openRateWindowMs);
    if (firstRecentIndex === -1) {
      attempts.length = 0;
    } else if (firstRecentIndex > 0) {
      attempts.splice(0, firstRecentIndex);
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
    this.removeStream(stream, code);
  }

  private isLateFrameForRecentlyClosedEdgeStream(sessionPeerId: string, frame: TunnelFrame): boolean {
    const edgeKey = edgeStreamKey(sessionPeerId, frame.streamId);
    this.pruneRecentlyClosedEdgeStreams(this.readNow());
    const closed = this.recentlyClosedEdgeStreams.get(edgeKey);
    if (closed === undefined || closed.edgePeerId !== sessionPeerId) {
      return false;
    }

    if (frame.type === FrameType.STREAM_DATA) {
      const payload = decodeFramePayload(frame);
      return payload instanceof Uint8Array && payload.byteLength > 0;
    }
    if (frame.type === FrameType.STREAM_CREDIT) {
      return creditPayload(frame) !== undefined;
    }
    return frame.type === FrameType.STREAM_CLOSE && closePayload(frame) !== undefined;
  }

  private rememberRecentlyClosedEdgeStream(stream: ActiveStream): void {
    const nowMs = this.readNow();
    this.pruneRecentlyClosedEdgeStreams(nowMs);
    while (this.recentlyClosedEdgeStreams.size >= MAX_RECENTLY_CLOSED_EDGE_STREAMS) {
      const oldestKey = this.recentlyClosedEdgeStreams.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      this.recentlyClosedEdgeStreams.delete(oldestKey);
    }
    this.recentlyClosedEdgeStreams.set(stream.edgeStreamKey, {
      edgePeerId: stream.edgePeerId,
      expiresAtMs: nowMs + RECENTLY_CLOSED_EDGE_STREAM_GRACE_MS
    });
  }

  private pruneRecentlyClosedEdgeStreams(nowMs: number): void {
    for (const [key, closed] of this.recentlyClosedEdgeStreams) {
      if (closed.expiresAtMs <= nowMs) {
        this.recentlyClosedEdgeStreams.delete(key);
      }
    }
  }

  private removeRecentlyClosedEdgeStreamsForPeer(peerId: string): void {
    for (const [key, closed] of this.recentlyClosedEdgeStreams) {
      if (closed.edgePeerId === peerId) {
        this.recentlyClosedEdgeStreams.delete(key);
      }
    }
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
        this.removeStream(stream, TunnelErrorCode.PEER_DISCONNECTED);
        continue;
      }

      if (stream.agentPeerId === session.peerId) {
        // agent 已不可用，保留既有 edge 错误契约；绝不向断开的 agent 写入。
        this.sendEdgeError(stream.edgePeerId, stream.edgeStreamId, TunnelErrorCode.PEER_DISCONNECTED);
        this.removeStream(stream, TunnelErrorCode.PEER_DISCONNECTED);
      }
    }
    this.removeRecentlyClosedEdgeStreamsForPeer(session.peerId);
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
    this.removeStream(stream, errorCode);
  }

  /**
   * 唯一的 stream 终结路径。先确认映射所有权，再释放生命周期预算、所有四维
   * 计数和本地发送队列；重复调用只会无操作。
   */
  private removeStream(stream: ActiveStream, reason: string): void {
    if (this.streamsByServerId.get(stream.serverStreamKey) !== stream) {
      return;
    }

    const closeCode = stream.lifecycle.closeCode;
    const errorCode = stream.lifecycle.errorCode;
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
    this.rememberRecentlyClosedEdgeStream(stream);
    this.decrementCounter(this.streamCountsByAuthorization, stream.authorizationKey);
    this.decrementCounter(this.streamCountsByEdgeUser, stream.edgeUserId);
    this.decrementCounter(this.streamCountsByEdgeDevice, stream.edgeDeviceId);
    this.decrementCounter(this.streamCountsByAgent, stream.agentId);
    this.incrementCounter(this.closedStreamsByReason, reason);
    this.recordClosed(stream, reason, closeCode, errorCode);
  }

  private sendEdgeRejected(
    session: AuthenticatedPeerSession,
    streamId: Uint8Array,
    code: TunnelErrorCodeValue,
    agentId?: string
  ): void {
    if (session.identity.kind === "edge-device" && session.identity.edgeUserId !== undefined) {
      this.incrementCounter(this.rejectedStreamsByEdgeUser, session.identity.edgeUserId);
    }
    this.emitAudit({
      event: "stream.rejected",
      occurredAtMs: this.readNow(),
      streamId: streamKey(streamId),
      edgePeerId: session.peerId,
      ...(session.identity.edgeUserId === undefined ? {} : { edgeUserId: session.identity.edgeUserId }),
      ...(session.identity.edgeDeviceId === undefined ? {} : { edgeDeviceId: session.identity.edgeDeviceId }),
      ...(agentId === undefined ? {} : { agentId }),
      state: "rejected",
      edgeToAgentBytes: 0,
      agentToEdgeBytes: 0,
      durationMs: 0,
      errorCode: code
    });
    this.peerSessions.sendFrame(
      session.peerId,
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

  private incrementCounter(counters: Map<string, number>, key: string): void {
    counters.set(key, (counters.get(key) ?? 0) + 1);
  }

  private decrementCounter(counters: Map<string, number>, key: string): void {
    const next = (counters.get(key) ?? 0) - 1;
    if (next <= 0) {
      counters.delete(key);
    } else {
      counters.set(key, next);
    }
  }

  private updateCounterByDelta(
    counters: Map<string, number>,
    key: string,
    current: number,
    delta: number
  ): void {
    const next = current + delta;
    if (next < 0) {
      throw new RangeError("SERVER_STREAM_BUFFER_COUNTER_UNDERFLOW");
    }
    if (next === 0) {
      counters.delete(key);
    } else {
      counters.set(key, next);
    }
  }

  private recordState(stream: ActiveStream): void {
    this.emitAudit({
      event: "stream.state",
      occurredAtMs: this.readNow(),
      streamId: stream.serverStreamKey,
      edgePeerId: stream.edgePeerId,
      edgeUserId: stream.edgeUserId,
      edgeDeviceId: stream.edgeDeviceId,
      agentPeerId: stream.agentPeerId,
      agentId: stream.agentId,
      state: stream.lifecycle.state,
      edgeToAgentBytes: stream.edgeToAgentBytes,
      agentToEdgeBytes: stream.agentToEdgeBytes,
      durationMs: Math.max(0, this.readNow() - stream.createdAtMs)
    });
  }

  private recordClosed(
    stream: ActiveStream,
    reason: string,
    closeCode: StreamCloseCodeValue | undefined,
    errorCode: TunnelErrorCodeValue | undefined
  ): void {
    const isCloseCode = Object.values(StreamCloseCode).includes(reason as StreamCloseCodeValue);
    const isErrorCode = Object.values(TunnelErrorCode).includes(reason as TunnelErrorCodeValue);
    this.emitAudit({
      event: "stream.closed",
      occurredAtMs: this.readNow(),
      streamId: stream.serverStreamKey,
      edgePeerId: stream.edgePeerId,
      edgeUserId: stream.edgeUserId,
      edgeDeviceId: stream.edgeDeviceId,
      agentPeerId: stream.agentPeerId,
      agentId: stream.agentId,
      state: "closed",
      edgeToAgentBytes: stream.edgeToAgentBytes,
      agentToEdgeBytes: stream.agentToEdgeBytes,
      durationMs: Math.max(0, this.readNow() - stream.createdAtMs),
      ...(errorCode === undefined && !isErrorCode ? {} : { errorCode: errorCode ?? reason }),
      ...(closeCode === undefined && !isCloseCode ? {} : { closeCode: closeCode ?? reason })
    });
  }

  private emitAudit(event: StreamAuditEvent): void {
    if (this.auditLogger === undefined) {
      return;
    }
    try {
      this.auditLogger(serializeStreamAuditEvent(event));
    } catch {
      // 审计输出故障不能放宽任何 stream 授权或阻断清理路径。
    }
  }

  private readNow(): number {
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new TypeError("clock must return a non-negative safe integer millisecond timestamp");
    }
    return nowMs;
  }
}
