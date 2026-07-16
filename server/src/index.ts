import { PROTOCOL_VERSION } from "@remote-codex/shared";
import type { ServerConfig } from "@remote-codex/shared";

export {
  createTunnelServer,
  DEFAULT_SERVER_TRANSPORT_LIMITS,
  HEALTH_CHECK_PATH,
  loadTlsCredentials,
  ServerStartupError,
  TUNNEL_WEBSOCKET_PATH,
  type ServerTransportLimits,
  type TlsCredentialPaths,
  type TlsCredentials,
  type TunnelServer,
  type TunnelServerOptions
} from "./runtime.js";

export const packageName = "@remote-codex/server" as const;
export const sharedProtocolVersion: ServerConfig["protocolVersion"] = PROTOCOL_VERSION;
