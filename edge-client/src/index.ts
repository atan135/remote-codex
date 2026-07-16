import { PROTOCOL_VERSION } from "@remote-codex/shared";
import type { EdgeClientConfig } from "@remote-codex/shared";

export const packageName = "@remote-codex/edge-client" as const;
export const sharedProtocolVersion: EdgeClientConfig["protocolVersion"] = PROTOCOL_VERSION;
