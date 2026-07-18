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
const SAFE_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/u;

function safeStatus(status: EgressAgentStatusSnapshot | undefined): Readonly<Record<string, string | number>> {
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
