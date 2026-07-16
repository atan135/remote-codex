import { PROTOCOL_VERSION } from "@remote-codex/shared";
import type { ServerConfig } from "@remote-codex/shared";

export const packageName = "@remote-codex/server" as const;
export const sharedProtocolVersion: ServerConfig["protocolVersion"] = PROTOCOL_VERSION;
