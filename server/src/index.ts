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
  type PeerSessionSendAvailabilityListener,
  type PeerSessionStreamFrameListener,
  type ServerPeerIdentityRegistration
} from "./peer-session.js";

export {
  StreamOpenCoordinator,
  type StreamOpenCoordinatorOptions,
  type StreamOwnership,
  type StreamPeerSessionGateway,
  type StreamQuotaLimits
} from "./stream-open.js";

export {
  serializeStreamAuditEvent,
  type StreamAuditEvent,
  type StreamAuditEventKind,
  type StreamAuditLogger,
  type StreamMetricsSnapshot
} from "./observability.js";

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

export {
  ConnectionRateTracker,
  MAX_CONNECTION_RATE_WINDOW_MS,
  MIN_CONNECTION_RATE_WINDOW_MS,
  type ConnectionRateDecision,
  type ConnectionRateTrackerLimits,
  type ConnectionRateTrackerScheduler
} from "./connection-rate-tracker.js";

export const packageName = "@remote-codex/server" as const;
export const sharedProtocolVersion: ServerConfig["protocolVersion"] = PROTOCOL_VERSION;
