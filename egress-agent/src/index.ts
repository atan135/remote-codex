import { DEFAULT_ALLOWED_DESTINATION } from "@remote-codex/shared";
import type { EgressAgentConfig } from "@remote-codex/shared";

export {
  calculateReconnectDelayMs,
  EgressAgentRuntime,
  EgressAgentRuntimeError,
  loadEgressAgentConfig,
  type AgentSocket,
  type AgentSocketFactory,
  type EgressAgentRuntimeOptions,
  type EgressAgentState,
  type EgressAgentStatusListener,
  type EgressAgentStatusSnapshot,
  type EgressAgentStreamResources
} from "./runtime.js";

export const packageName = "@remote-codex/egress-agent" as const;
export const approvedDestinationPort: EgressAgentConfig["allowedDestination"]["port"] = DEFAULT_ALLOWED_DESTINATION.port;
