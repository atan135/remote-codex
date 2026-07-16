// `@remote-codex/shared` 只有一个受控的公共入口；运行组件不得导入 package 子路径。
import {
  FrameType as frameType,
  ProtocolErrorCode as protocolErrorCode,
  StreamCloseCode as streamCloseCode,
  TunnelErrorCode as tunnelErrorCode
} from "./protocol.js";
import type {
  FrameType as FrameTypeType,
  ProtocolErrorCode as ProtocolErrorCodeType,
  StreamCloseCode as StreamCloseCodeType,
  TunnelErrorCode as TunnelErrorCodeType
} from "./protocol.js";
import { IdentityKeyRole as identityKeyRole } from "./identity.js";
import type { IdentityKeyRole as IdentityKeyRoleType } from "./identity.js";
import { StreamState as streamState } from "./stream.js";
import type { StreamState as StreamStateType } from "./stream.js";

export const IdentityKeyRole = identityKeyRole;
export const FrameType = frameType;
export const ProtocolErrorCode = protocolErrorCode;
export const StreamCloseCode = streamCloseCode;
export const TunnelErrorCode = tunnelErrorCode;
export const StreamState = streamState;
export type IdentityKeyRole = IdentityKeyRoleType;
export type FrameType = FrameTypeType;
export type ProtocolErrorCode = ProtocolErrorCodeType;
export type StreamCloseCode = StreamCloseCodeType;
export type TunnelErrorCode = TunnelErrorCodeType;
export type StreamState = StreamStateType;

export {
  assertTlsVerificationEnabled,
  ConfigError,
  DEFAULT_ALLOWED_DESTINATION,
  DEFAULT_RESOURCE_LIMITS,
  parseEdgeClientConfig,
  parseEgressAgentConfig,
  parseResourceLimits,
  parseRuntimeConfig,
  parseRuntimeConfigJson,
  parseServerConfig,
  PROTOCOL_VERSION,
  type AllowedDestination,
  type EdgeClientConfig,
  type EgressAgentConfig,
  type ResourceLimits,
  type RuntimeConfig,
  type ServerConfig
} from "./config.js";

export {
  DestinationValidationError,
  normalizeHostname,
  validateDestination,
  type ValidatedDestination
} from "./destination.js";

export {
  AUTHENTICATION_CHALLENGE_NONCE_BYTES,
  CAPABILITY_HEADER_BYTES,
  CAPABILITY_ID_BYTES,
  CAPABILITY_SIGNATURE_BYTES,
  CAPABILITY_VERSION,
  CapabilityError,
  CapabilityReplayProtector,
  createEdgeDeviceIdentity,
  createEgressAgentIdentity,
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  IdentityError,
  issueAuthenticationChallenge,
  issueCapability,
  loadIdentityPrivateKey,
  loadIdentityPublicKey,
  MAX_AUTHENTICATION_WINDOW_MS,
  MAX_CAPABILITY_WINDOW_MS,
  MAX_IDENTITY_ID_BYTES,
  MAX_REPLAY_ENTRIES,
  NonceReplayProtector,
  signAuthenticationChallenge,
  verifyAuthenticationChallenge,
  verifyCapability,
  type AuthenticationChallengeOptions,
  type AuthenticationProofInput,
  type AuthenticationVerificationInput,
  type AuthenticationVerificationResult,
  type CapabilityBinding,
  type CapabilityIssueInput,
  type CapabilityVerificationInput,
  type CapabilityVerificationResult,
  type EdgeDeviceIdentity,
  type EgressAgentIdentity,
  type IdentityKeyLoader,
  type IdentityKeyReference,
  type IdentityPrivateKey,
  type IdentityPublicKey,
  type IssuedAuthenticationChallenge,
  type PeerAuthenticationIdentity,
  type RandomByteSource,
  type ServerSigningCredentials,
  type ServerSigningIdentity,
  type VerifiedCapability
} from "./identity.js";

export {
  connectionFrame,
  createStreamId,
  decodeAuthenticatePayload,
  decodeChallengePayload,
  decodeFrame,
  decodeFramePayload,
  decodeHeartbeatPayload,
  decodeRegisterPayload,
  decodeStreamClosePayload,
  decodeStreamCreditPayload,
  decodeStreamErrorPayload,
  decodeStreamOpenPayload,
  encodeAuthenticatePayload,
  encodeChallengePayload,
  encodeFrame,
  encodeHeartbeatPayload,
  encodeRegisterPayload,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
  encodeStreamErrorPayload,
  encodeStreamOpenPayload,
  FRAME_HEADER_BYTES,
  MAX_CAPABILITY_BYTES,
  MAX_CONTROL_PAYLOAD_BYTES,
  MAX_DATA_PAYLOAD_BYTES,
  MAX_FRAME_BYTES,
  MAX_HOSTNAME_BYTES,
  MAX_NONCE_BYTES,
  MAX_PEER_ID_BYTES,
  MAX_SIGNATURE_BYTES,
  MIN_NONCE_BYTES,
  ProtocolError,
  STREAM_ID_BYTES,
  streamFrame,
  type AuthenticatePayload,
  type ChallengePayload,
  type DecodedFramePayload,
  type HeartbeatPayload,
  type PeerRole,
  type RegisterPayload,
  type StreamClosePayload,
  type StreamCreditPayload,
  type StreamErrorPayload,
  type StreamOpenPayload,
  type TunnelFrame
} from "./protocol.js";

export {
  DEFAULT_INITIAL_RECEIVE_CREDIT_BYTES,
  StreamBufferBudget,
  StreamLifecycle,
  type StreamCreditGrant,
  type StreamFrameDirection,
  type StreamLifecycleOptions,
  type StreamLifecycleResult,
} from "./stream.js";
