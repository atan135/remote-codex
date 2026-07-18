export { runEgressAgentHostCli, type EgressAgentHostCliIo } from "./cli.js";
export { SafeEgressAgentProcessLogger, type AgentProcessLogWriter } from "./logging.js";
export {
  AGENT_STATUS_LOG_RELATIVE_PATH,
  createPersistentAgentStatusLog,
  DEFAULT_AGENT_STATUS_LOG_BACKUPS,
  DEFAULT_AGENT_STATUS_LOG_MAX_BYTES,
  EgressAgentLogError,
  type AgentProcessLogSink,
  type AgentStatusLogOptions
} from "./persistent-log.js";
export {
  acquireProcessLifetimeLease,
  EgressAgentHostError,
  startEgressAgentHost,
  type EgressAgentHostDependencies,
  type EgressAgentRuntimeHandle,
  type ProcessLifetimeLease,
  type RunningEgressAgentHost
} from "./runtime.js";
