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
const SAFE_CODES = new Set([
  "AUTH_EXPIRED",
  "AUTH_FAILED",
  "AUTH_REPLAYED",
  "AUTH_UNAUTHORIZED",
  "AUTH_TIMEOUT",
  "BINARY_FRAME_REQUIRED",
  "EACCES",
  "EADDRINUSE",
  "EDGE_HOST_COMPONENT_MISMATCH",
  "EDGE_HOST_DESTINATION_INVALID",
  "EDGE_HOST_LISTENER_INVALID",
  "EDGE_HOST_NETWORK_POLICY_INVALID",
  "EDGE_HOST_SERVER_URL_INVALID",
  "EDGE_HOST_START_FAILED",
  "EDGE_HOST_TERMINATED_DURING_START",
  "EDGE_RECONNECT_JITTER_INVALID",
  "EDGE_RECONNECT_ATTEMPT_INVALID",
  "EDGE_RUNTIME_START_FAILED",
  "EDGE_STREAM_ID_INVALID",
  "HEARTBEAT_TIMEOUT",
  "PROTOCOL_VIOLATION",
  "RECONNECT_LIMIT_EXCEEDED",
  "WSS_CONNECTION_FAILED",
  "WSS_DISCONNECTED"
]);

function safeStatus(status: EdgeClientStatusSnapshot | undefined): Readonly<Record<string, string | number>> {
  if (status === undefined) {
    return Object.freeze({});
  }
  const state = STATES.has(status.state) ? status.state : "offline";
  const reconnectAttempts = Number.isSafeInteger(status.reconnectAttempts) && status.reconnectAttempts >= 0
    ? status.reconnectAttempts
    : 0;
  const code = status.lastErrorCode !== undefined && SAFE_CODES.has(status.lastErrorCode)
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
