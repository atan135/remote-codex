import type { EgressAgentStatusSnapshot } from "@remote-codex/egress-agent";

export type AgentProcessLogWriter = (serializedRecord: string) => void;

type AgentLifecycleEvent =
  | "agent.started"
  | "agent.state_changed"
  | "agent.terminal_failure"
  | "agent.start_failed"
  | "agent.stopping"
  | "agent.stopped";

const STATES = new Set(["offline", "connecting", "authenticating", "online", "backoff", "stopped"]);
const SAFE_CODES = new Set([
  "AGENT_HOST_COMPONENT_MISMATCH",
  "AGENT_HOST_LIFETIME_INIT_FAILED",
  "AGENT_HOST_SERVER_URL_INVALID",
  "AGENT_HOST_START_FAILED",
  "AGENT_RECONNECT_ATTEMPT_INVALID",
  "AGENT_RECONNECT_JITTER_INVALID",
  "AGENT_STREAM_CLEANUP_FAILED",
  "AUTH_EXPIRED",
  "AUTH_FAILED",
  "AUTH_REPLAYED",
  "AUTH_UNAUTHORIZED",
  "BINARY_FRAME_REQUIRED",
  "HEARTBEAT_TIMEOUT",
  "PROTOCOL_VIOLATION",
  "RECONNECT_LIMIT_EXCEEDED",
  "WSS_CONNECTION_FAILED",
  "WSS_DISCONNECTED"
]);

function safeStatus(status: EgressAgentStatusSnapshot | undefined): Readonly<Record<string, string | number>> {
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

export class SafeEgressAgentProcessLogger {
  public constructor(
    private readonly writer: AgentProcessLogWriter,
    private readonly now: () => number = Date.now
  ) {}

  public lifecycle(event: AgentLifecycleEvent, status?: EgressAgentStatusSnapshot): void {
    try {
      this.writer(`${JSON.stringify({ event, occurredAtMs: this.now(), ...safeStatus(status) })}\n`);
    } catch {
      // 持久日志故障不能改变认证、重连或 stream 清理状态机。
    }
  }
}
