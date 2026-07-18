import type { StreamMetricsSnapshot } from "@remote-codex/server";

export type ProcessLogWriter = (serializedRecord: string) => void;

type LifecycleEvent =
  | "server.started"
  | "server.stopping"
  | "server.stopped"
  | "server.tls_reloaded"
  | "server.tls_reload_failed"
  | "server.start_failed";

const SAFE_IDENTIFIER_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
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

function safeCode(code: string | undefined): string | undefined {
  return code !== undefined && /^[A-Z][A-Z0-9_]{0,127}$/u.test(code) ? code : undefined;
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
      readonly listenHost?: string;
      readonly listenPort?: number;
      readonly publicWssUrl?: string;
    } = {}
  ): void {
    const code = safeCode(fields.code);
    this.write({
      event,
      occurredAtMs: this.now(),
      ...(code === undefined ? {} : { code }),
      ...(fields.listenHost === undefined ? {} : { listenHost: fields.listenHost }),
      ...(fields.listenPort === undefined ? {} : { listenPort: fields.listenPort }),
      ...(fields.publicWssUrl === undefined ? {} : { publicWssUrl: fields.publicWssUrl })
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
        if (typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0)) {
          safeRecord[key] = value;
        }
      }
      if (typeof safeRecord.event === "string") {
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
    this.writer(`${JSON.stringify(record)}\n`);
  }
}
