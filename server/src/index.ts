import { PROTOCOL_VERSION } from "@remote-codex/shared";
import type { ServerConfig } from "@remote-codex/shared";

export {
  createTunnelServer,
  DEFAULT_PEER_HEARTBEAT_TIMEOUT_MS,
  DEFAULT_SERVER_TRANSPORT_LIMITS,
  HEALTH_CHECK_PATH,
  loadTlsCredentials,
  ServerStartupError,
  TUNNEL_WEBSOCKET_PATH,
  type ServerTransportLimits,
  type TlsCredentialPaths,
  type TlsCredentials,
  type TunnelServer,
  type TunnelServerOptions,
  type ServerStreamAuthorizationOptions
} from "./runtime.js";

export {
  PeerSessionError,
  PeerSessionManager,
  type AuthenticatedPeerSession,
  type PeerAuthenticationMetadata,
  type PeerSessionManagerOptions,
  type PeerSessionRemovalListener,
  type PeerSessionStreamFrameListener,
  type ServerPeerIdentityRegistration
} from "./peer-session.js";

export {
  StreamOpenCoordinator,
  type StreamOpenCoordinatorOptions,
  type StreamOwnership,
  type StreamPeerSessionGateway
} from "./stream-open.js";

export {
  AuthorizationRegistry,
  AuthorizationRegistryError,
  AuthorizationStatus,
  parseAuthorizationRegistryJson,
  type AuthorizedAgentRoute,
  type AuthorizationQuota,
  type AuthorizationRegistration,
  type AuthorizationRegistryDocument,
  type AuthorizationRegistryOptions,
  type AuthorizationRegistryUpdateResult,
  type AuthorizationRevocation,
  type AuthorizationRevocationListener,
  type AuthorizationStatus as AuthorizationStatusType
} from "./authorization-registry.js";

export const packageName = "@remote-codex/server" as const;
export const sharedProtocolVersion: ServerConfig["protocolVersion"] = PROTOCOL_VERSION;
