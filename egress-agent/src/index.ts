import { DEFAULT_ALLOWED_DESTINATION } from "@remote-codex/shared";
import type { EgressAgentConfig } from "@remote-codex/shared";

export const packageName = "@remote-codex/egress-agent" as const;
export const approvedDestinationPort: EgressAgentConfig["allowedDestination"]["port"] = DEFAULT_ALLOWED_DESTINATION.port;
