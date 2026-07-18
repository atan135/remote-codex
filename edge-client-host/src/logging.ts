import type { EdgeClientStatusSnapshot } from "@remote-codex/edge-client";

export type EdgeProcessLogWriter = (serializedRecord: string) => void;

type EdgeLifecycleEvent =
  | "edge.started"
  | "edge.state_changed"
  | "edge.terminal_failure"
  | "edge.start_failed"
  | "edge.stopping"
  | "edge.stopped";

const STATES = new Set(["offline", "connecting", "authenticating", "online", "closing", "backoff", "stopped"]);
const SAFE_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/u;

function safeStatus(status: EdgeClientStatusSnapshot | undefined): Readonly<Record<string, string | number>> {
  if (status === undefined) {
    return Object.freeze({});
  }
  const state = STATES.has(status.state) ? status.state : "offline";
  const reconnectAttempts = Number.isSafeInteger(status.reconnectAttempts) && status.reconnectAttempts >= 0
    ? status.reconnectAttempts
    : 0;
  const code = status.lastErrorCode !== undefined && SAFE_CODE_PATTERN.test(status.lastErrorCode)
    ? status.lastErrorCode
    : undefined;
  return Object.freeze({
    state,
    reconnectAttempts,
    ...(code === undefined ? {} : { code })
  });
}

export class SafeEdgeProcessLogger {
  public constructor(
    private readonly writer: EdgeProcessLogWriter,
    private readonly now: () => number = Date.now
  ) {}

  public lifecycle(event: EdgeLifecycleEvent, status?: EdgeClientStatusSnapshot): void {
    try {
      this.writer(`${JSON.stringify({ event, occurredAtMs: this.now(), ...safeStatus(status) })}\n`);
    } catch {
      // 持久日志故障不能影响 WSS、listener 或 stream 清理。
    }
  }
}
