import type { StreamMetricsSnapshot } from "@remote-codex/server";
import { StreamCloseCode, StreamState, TunnelErrorCode } from "@remote-codex/shared";

export type ProcessLogWriter = (serializedRecord: string) => void;

type LifecycleEvent =
  | "server.started"
  | "server.stopping"
  | "server.stopped"
  | "server.tls_reloaded"
  | "server.tls_reload_failed"
  | "server.start_failed";

const SAFE_IDENTIFIER_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const SAFE_AUDIT_EVENTS = new Set(["stream.rejected", "stream.state", "stream.closed"]);
const SAFE_STREAM_STATES: ReadonlySet<string> = new Set(Object.values(StreamState));
const SAFE_LIFECYCLE_CODES = new Set([
  "SERVER_HOST_COMPONENT_MISMATCH",
  "SERVER_HOST_LISTEN_FAILED",
  "SERVER_HOST_RELOAD_REQUIRES_RESTART",
  "SERVER_HOST_START_FAILED",
  "SERVER_HOST_TLS_CREDENTIALS_INVALID",
  "SERVER_HOST_TLS_RELOAD_FAILED"
]);
const SAFE_STREAM_CODES: ReadonlySet<string> = new Set([
  ...Object.values(TunnelErrorCode),
  ...Object.values(StreamCloseCode)
]);
const SAFE_AUDIT_FIELDS = Object.freeze([
  "event",
  "occurredAtMs",
  "streamId",
  "edgePeerId",
  "edgeUserId",
  "edgeDeviceId",
  "agentPeerId",
  "agentId",
  "state",
  "edgeToAgentBytes",
  "agentToEdgeBytes",
  "durationMs",
  "errorCode",
  "closeCode"
] as const);

function stableCounters(value: Readonly<Record<string, number>>): Readonly<Record<string, number>> {
  return Object.freeze(Object.fromEntries(
    Object.entries(value)
      .filter(([key, count]) => SAFE_IDENTIFIER_PATTERN.test(key) && Number.isSafeInteger(count) && count >= 0)
      .sort(([left], [right]) => left.localeCompare(right))
  ));
}

export class SafeServerProcessLogger {
  public constructor(
    private readonly writer: ProcessLogWriter,
    private readonly now: () => number = Date.now
  ) {}

  public lifecycle(
    event: LifecycleEvent,
    fields: {
      readonly code?: string;
      readonly listenPort?: number;
    } = {}
  ): void {
    const code = fields.code !== undefined && SAFE_LIFECYCLE_CODES.has(fields.code) ? fields.code : undefined;
    this.write({
      event,
      occurredAtMs: this.now(),
      ...(code === undefined ? {} : { code }),
      ...(Number.isSafeInteger(fields.listenPort) && (fields.listenPort ?? 0) >= 0
        ? { listenPort: fields.listenPort }
        : {})
    });
  }

  /** 重新按白名单构造审计行，避免调用方扩展字段后把敏感值带入进程日志。 */
  public audit(serializedEvent: string): void {
    try {
      const source = JSON.parse(serializedEvent) as unknown;
      if (source === null || typeof source !== "object" || Array.isArray(source)) {
        return;
      }
      const record = source as Record<string, unknown>;
      const safeRecord: Record<string, string | number> = {};
      for (const key of SAFE_AUDIT_FIELDS) {
        const value = record[key];
        if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
          safeRecord[key] = value;
          continue;
        }
        if (typeof value !== "string") {
          continue;
        }
        if (key === "event" && SAFE_AUDIT_EVENTS.has(value)) {
          safeRecord[key] = value;
          continue;
        }
        if (key === "state" && SAFE_STREAM_STATES.has(value)) {
          safeRecord[key] = value;
          continue;
        }
        if ((key === "errorCode" || key === "closeCode") && SAFE_STREAM_CODES.has(value)) {
          safeRecord[key] = value;
          continue;
        }
        if (
          (key === "streamId" || key === "edgePeerId" || key === "edgeUserId" ||
            key === "edgeDeviceId" || key === "agentPeerId" || key === "agentId") &&
          SAFE_IDENTIFIER_PATTERN.test(value)
        ) {
          safeRecord[key] = value;
        }
      }
      if (typeof safeRecord.event === "string" && typeof safeRecord.occurredAtMs === "number") {
        this.write(safeRecord);
      }
    } catch {
      // 畸形审计行被丢弃，不能把原始输入或异常对象写入日志。
    }
  }

  public metrics(snapshot: StreamMetricsSnapshot): void {
    this.write({
      event: "server.metrics",
      occurredAtMs: this.now(),
      authenticatedEdgePeers: snapshot.authenticatedEdgePeers,
      authenticatedAgentPeers: snapshot.authenticatedAgentPeers,
      activeStreamsByAgent: stableCounters(snapshot.activeStreamsByAgent),
      rejectedStreamsByEdgeUser: stableCounters(snapshot.rejectedStreamsByEdgeUser),
      closedStreamsByReason: stableCounters(snapshot.closedStreamsByReason),
      bufferWatermark: {
        currentBytes: snapshot.bufferWatermark.currentBytes,
        peakBytes: snapshot.bufferWatermark.peakBytes,
        limitBytes: snapshot.bufferWatermark.limitBytes
      }
    });
  }

  private write(record: Readonly<Record<string, unknown>>): void {
    try {
      this.writer(`${JSON.stringify(record)}\n`);
    } catch {
      // 日志 writer 故障不能影响 listener、TLS reload、stream 或 shutdown。
    }
  }
}
