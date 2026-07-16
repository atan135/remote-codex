import type { StreamState } from "@remote-codex/shared";

/**
 * 可交给进程日志适配器的已序列化审计记录。调用方不得改为记录原始 frame，
 * 因为 frame 可能包含 TLS 密文、认证材料或请求内容。
 */
export type StreamAuditLogger = (serializedEvent: string) => void;

export type StreamAuditEventKind = "stream.rejected" | "stream.state" | "stream.closed";

/**
 * 审计事件只包含允许聚合的 stream 元数据。这里刻意没有 destination、payload、
 * capability、认证 key 或任何来自 TLS 的内容字段。
 */
export interface StreamAuditEvent {
  readonly event: StreamAuditEventKind;
  readonly occurredAtMs: number;
  readonly streamId: string;
  readonly edgePeerId: string;
  readonly edgeUserId?: string;
  readonly edgeDeviceId?: string;
  readonly agentPeerId?: string;
  readonly agentId?: string;
  readonly state: StreamState | "rejected" | "closed";
  readonly edgeToAgentBytes: number;
  readonly agentToEdgeBytes: number;
  readonly durationMs: number;
  readonly errorCode?: string;
  readonly closeCode?: string;
}

export interface StreamMetricsSnapshot {
  readonly authenticatedEdgePeers: number;
  readonly authenticatedAgentPeers: number;
  readonly activeStreamsByAgent: Readonly<Record<string, number>>;
  readonly rejectedStreamsByEdgeUser: Readonly<Record<string, number>>;
  readonly closedStreamsByReason: Readonly<Record<string, number>>;
  readonly bufferWatermark: Readonly<{
    currentBytes: number;
    peakBytes: number;
    limitBytes: number;
  }>;
}

/**
 * 使用白名单字段重新构造 JSON，确保即使上游对象被错误扩展，也不会将敏感字段
 * 序列化进日志。
 */
export function serializeStreamAuditEvent(event: StreamAuditEvent): string {
  return JSON.stringify({
    event: event.event,
    occurredAtMs: event.occurredAtMs,
    streamId: event.streamId,
    edgePeerId: event.edgePeerId,
    ...(event.edgeUserId === undefined ? {} : { edgeUserId: event.edgeUserId }),
    ...(event.edgeDeviceId === undefined ? {} : { edgeDeviceId: event.edgeDeviceId }),
    ...(event.agentPeerId === undefined ? {} : { agentPeerId: event.agentPeerId }),
    ...(event.agentId === undefined ? {} : { agentId: event.agentId }),
    state: event.state,
    edgeToAgentBytes: event.edgeToAgentBytes,
    agentToEdgeBytes: event.agentToEdgeBytes,
    durationMs: event.durationMs,
    ...(event.errorCode === undefined ? {} : { errorCode: event.errorCode }),
    ...(event.closeCode === undefined ? {} : { closeCode: event.closeCode })
  });
}

/** 将内部 Map 转为稳定、只读且可聚合的指标字典。 */
export function snapshotPositiveCounters(counters: ReadonlyMap<string, number>): Readonly<Record<string, number>> {
  return Object.freeze(
    Object.fromEntries(
      [...counters.entries()]
        .filter(([, value]) => Number.isSafeInteger(value) && value > 0)
        .sort(([left], [right]) => left.localeCompare(right))
    )
  );
}
