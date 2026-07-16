import {
  createPublicKey,
  KeyObject,
  randomBytes as secureRandomBytes,
  sign as signDetached,
  timingSafeEqual,
  verify as verifyDetached
} from "node:crypto";

import type { AllowedDestination } from "./config.js";
import { normalizeHostname, validateDestination } from "./destination.js";
import {
  MAX_CAPABILITY_BYTES,
  MAX_NONCE_BYTES,
  MAX_SIGNATURE_BYTES,
  MIN_NONCE_BYTES,
  STREAM_ID_BYTES,
  TunnelErrorCode
} from "./protocol.js";
import type { AuthenticatePayload, ChallengePayload, PeerRole, RegisterPayload } from "./protocol.js";

export const IdentityKeyRole = {
  EDGE_DEVICE_AUTHENTICATION: "edge-device-authentication",
  EGRESS_AGENT_AUTHENTICATION: "egress-agent-authentication",
  SERVER_CAPABILITY_SIGNING: "server-capability-signing"
} as const;

export type IdentityKeyRole = (typeof IdentityKeyRole)[keyof typeof IdentityKeyRole];

export const AUTHENTICATION_CHALLENGE_NONCE_BYTES = 32;
export const CAPABILITY_VERSION = 1;
export const CAPABILITY_ID_BYTES = 16;
export const CAPABILITY_SIGNATURE_BYTES = 64;
export const CAPABILITY_HEADER_BYTES = 56;
export const MAX_AUTHENTICATION_WINDOW_MS = 60_000;
export const MAX_CAPABILITY_WINDOW_MS = 60_000;
export const MAX_IDENTITY_ID_BYTES = 128;
export const MAX_REPLAY_ENTRIES = 65_536;

export type RandomByteSource = (size: number) => Uint8Array;

export interface IdentityKeyReference<Role extends IdentityKeyRole = IdentityKeyRole> {
  readonly role: Role;
  readonly keyId: string;
}

export interface IdentityKeyLoader {
  loadPublicKey(reference: IdentityKeyReference): KeyObject;
  loadPrivateKey(reference: IdentityKeyReference): KeyObject;
}

export interface IdentityPublicKey<Role extends IdentityKeyRole = IdentityKeyRole>
  extends IdentityKeyReference<Role> {
  readonly key: KeyObject;
}

export interface IdentityPrivateKey<Role extends IdentityKeyRole = IdentityKeyRole>
  extends IdentityKeyReference<Role> {
  readonly key: KeyObject;
}

export interface EdgeDeviceIdentity {
  readonly kind: "edge-device";
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
  readonly authenticationKey: IdentityPublicKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
}

export interface EgressAgentIdentity {
  readonly kind: "egress-agent";
  readonly agentId: string;
  readonly authenticationKey: IdentityPublicKey<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
}

export interface ServerSigningIdentity {
  readonly kind: "server";
  readonly serverId: string;
  readonly capabilityVerificationKey: IdentityPublicKey<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>;
}

export interface ServerSigningCredentials {
  readonly identity: ServerSigningIdentity;
  readonly capabilitySigningKey: IdentityPrivateKey<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>;
}

export type PeerAuthenticationIdentity = EdgeDeviceIdentity | EgressAgentIdentity;

export interface IssuedAuthenticationChallenge {
  readonly issuedAtMs: number;
  readonly payload: ChallengePayload;
}

export interface AuthenticationChallengeOptions {
  readonly nowMs: number;
  readonly ttlMs?: number;
  readonly randomBytes?: RandomByteSource;
}

export interface AuthenticationProofInput {
  readonly identity: PeerAuthenticationIdentity;
  readonly signingKey:
    | IdentityPrivateKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>
    | IdentityPrivateKey<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
  readonly registration: RegisterPayload;
  readonly challenge: IssuedAuthenticationChallenge;
}

export interface AuthenticationVerificationInput {
  readonly identity: PeerAuthenticationIdentity;
  readonly registration: RegisterPayload;
  readonly challenge: IssuedAuthenticationChallenge;
  readonly response: AuthenticatePayload;
  readonly replayProtector: NonceReplayProtector;
  readonly nowMs: number;
}

export type AuthenticationVerificationResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly errorCode:
        | typeof TunnelErrorCode.AUTH_FAILED
        | typeof TunnelErrorCode.AUTH_EXPIRED
        | typeof TunnelErrorCode.AUTH_REPLAYED;
    };

export interface CapabilityBinding {
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
  readonly agentId: string;
  readonly streamId: Uint8Array;
  readonly destination: {
    readonly hostname: string;
    readonly port: 443;
  };
}

export interface CapabilityIssueInput {
  readonly credentials: ServerSigningCredentials;
  readonly binding: CapabilityBinding;
  readonly allowedDestination: AllowedDestination;
  readonly nowMs: number;
  readonly ttlMs: number;
  readonly randomBytes?: RandomByteSource;
}

export interface VerifiedCapability {
  readonly binding: CapabilityBinding;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly capabilityId: Uint8Array;
  readonly signingKeyId: string;
}

export interface CapabilityVerificationInput {
  readonly capability: Uint8Array;
  readonly serverIdentity: ServerSigningIdentity;
  readonly expectedBinding: CapabilityBinding;
  readonly allowedDestination: AllowedDestination;
  readonly replayProtector: CapabilityReplayProtector;
  readonly nowMs: number;
}

export type CapabilityVerificationResult =
  | { readonly ok: true; readonly capability: VerifiedCapability }
  | { readonly ok: false; readonly errorCode: typeof TunnelErrorCode.CAPABILITY_INVALID };

export class IdentityError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "IdentityError";
  }
}

export class CapabilityError extends Error {
  public constructor() {
    super(TunnelErrorCode.CAPABILITY_INVALID);
    this.name = "CapabilityError";
  }
}

interface ParsedCapability {
  readonly signingKeyId: string;
  readonly binding: CapabilityBinding;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly capabilityId: Uint8Array;
  readonly signature: Uint8Array;
  readonly signedBytes: Uint8Array;
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PEER_ROLE_TO_WIRE: Readonly<Record<PeerRole, number>> = {
  "edge-client": 1,
  "egress-agent": 2
};
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

function failIdentity(code: string): never {
  throw new IdentityError(code);
}

function failCapability(): never {
  throw new CapabilityError();
}

function assertSafeTimestamp(value: number, errorCode = "IDENTITY_INVALID_TIMESTAMP"): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    failIdentity(errorCode);
  }
}

function assertIdentityId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) {
    failIdentity("IDENTITY_INVALID_ID");
  }
}

function assertKnownKeyRole(value: unknown): asserts value is IdentityKeyRole {
  if (!Object.values(IdentityKeyRole).includes(value as IdentityKeyRole)) {
    failIdentity("IDENTITY_INVALID_KEY_ROLE");
  }
}

function assertKeyObject(key: unknown, expectedType: "public" | "private"): asserts key is KeyObject {
  if (
    !(key instanceof KeyObject) ||
    key.type !== expectedType ||
    key.asymmetricKeyType !== "ed25519"
  ) {
    failIdentity("IDENTITY_INVALID_KEY");
  }
}

function assertKeyRole<Key extends IdentityKeyRole>(
  key: IdentityKeyReference,
  expectedRole: Key
): asserts key is IdentityKeyReference<Key> {
  if (key.role !== expectedRole) {
    failIdentity("IDENTITY_KEY_ROLE_MISMATCH");
  }
}

function freezeBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

function safeEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function bytesKey(bytes: Uint8Array): string {
  let key = "";

  for (const byte of bytes) {
    key += byte.toString(16).padStart(2, "0");
  }

  return key;
}

function validateRandomBytes(source: RandomByteSource | undefined, length: number): Uint8Array {
  const bytes = (source ?? secureRandomBytes)(length);

  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) {
    failIdentity("IDENTITY_RANDOM_SOURCE_INVALID");
  }

  return freezeBytes(bytes);
}

function identityPeerRole(identity: PeerAuthenticationIdentity): PeerRole {
  return identity.kind === "edge-device" ? "edge-client" : "egress-agent";
}

function identityPeerId(identity: PeerAuthenticationIdentity): string {
  return identity.kind === "edge-device" ? identity.edgeDeviceId : identity.agentId;
}

function expectedAuthenticationKeyRole(
  identity: PeerAuthenticationIdentity
): typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION | typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION {
  return identity.kind === "edge-device"
    ? IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION
    : IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION;
}

function isMatchingRegistration(identity: PeerAuthenticationIdentity, registration: RegisterPayload): boolean {
  return (
    registration.role === identityPeerRole(identity) &&
    registration.peerId === identityPeerId(identity) &&
    registration.nonce instanceof Uint8Array &&
    registration.nonce.byteLength >= MIN_NONCE_BYTES &&
    registration.nonce.byteLength <= MAX_NONCE_BYTES
  );
}

function encodeAuthenticationMessage(
  identity: PeerAuthenticationIdentity,
  registration: RegisterPayload,
  challenge: IssuedAuthenticationChallenge
): Uint8Array {
  if (!isMatchingRegistration(identity, registration)) {
    failIdentity("IDENTITY_REGISTRATION_MISMATCH");
  }

  assertSafeTimestamp(challenge.issuedAtMs);
  assertSafeTimestamp(challenge.payload.expiresAtMs);

  if (
    challenge.payload.expiresAtMs <= challenge.issuedAtMs ||
    challenge.payload.expiresAtMs - challenge.issuedAtMs > MAX_AUTHENTICATION_WINDOW_MS ||
    challenge.payload.nonce.byteLength !== AUTHENTICATION_CHALLENGE_NONCE_BYTES
  ) {
    failIdentity("IDENTITY_INVALID_CHALLENGE");
  }

  const peerId = TEXT_ENCODER.encode(registration.peerId);
  const role = PEER_ROLE_TO_WIRE[registration.role];

  if (peerId.byteLength === 0 || peerId.byteLength > MAX_IDENTITY_ID_BYTES || role === undefined) {
    failIdentity("IDENTITY_REGISTRATION_MISMATCH");
  }

  const encoded = new Uint8Array(
    1 + 1 + 1 + 1 + peerId.byteLength + registration.nonce.byteLength + challenge.payload.nonce.byteLength + 8
  );
  const view = new DataView(encoded.buffer);
  let offset = 0;

  encoded[offset] = 1;
  offset += 1;
  encoded[offset] = role;
  offset += 1;
  encoded[offset] = peerId.byteLength;
  offset += 1;
  encoded[offset] = registration.nonce.byteLength;
  offset += 1;
  encoded.set(peerId, offset);
  offset += peerId.byteLength;
  encoded.set(registration.nonce, offset);
  offset += registration.nonce.byteLength;
  encoded.set(challenge.payload.nonce, offset);
  offset += challenge.payload.nonce.byteLength;
  view.setBigUint64(offset, BigInt(challenge.payload.expiresAtMs));
  return encoded;
}

function normalizeBinding(binding: CapabilityBinding, allowedDestination: AllowedDestination): CapabilityBinding {
  assertIdentityId(binding.edgeUserId);
  assertIdentityId(binding.edgeDeviceId);
  assertIdentityId(binding.agentId);

  if (!(binding.streamId instanceof Uint8Array) || binding.streamId.byteLength !== STREAM_ID_BYTES) {
    failIdentity("IDENTITY_INVALID_STREAM_ID");
  }

  const destination = validateDestination(binding.destination.hostname, binding.destination.port, allowedDestination);

  return Object.freeze({
    edgeUserId: binding.edgeUserId,
    edgeDeviceId: binding.edgeDeviceId,
    agentId: binding.agentId,
    streamId: freezeBytes(binding.streamId),
    destination: Object.freeze({ hostname: destination.hostname, port: 443 })
  });
}

function readTimestamp(bytes: Uint8Array, offset: number): number {
  const value = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(offset);

  if (value > MAX_SAFE_BIGINT) {
    failCapability();
  }

  return Number(value);
}

function decodeCapabilityText(bytes: Uint8Array): string {
  try {
    const value = TEXT_DECODER.decode(bytes);

    assertIdentityId(value);
    return value;
  } catch {
    return failCapability();
  }
}

function encodeCapabilityText(value: string): Uint8Array {
  assertIdentityId(value);
  const bytes = TEXT_ENCODER.encode(value);

  if (bytes.byteLength === 0 || bytes.byteLength > MAX_IDENTITY_ID_BYTES) {
    failIdentity("IDENTITY_INVALID_ID");
  }

  return bytes;
}

function encodeCapabilityHostname(value: string): Uint8Array {
  const normalized = normalizeHostname(value);
  const bytes = TEXT_ENCODER.encode(normalized);

  if (bytes.byteLength === 0 || bytes.byteLength > 253) {
    failIdentity("IDENTITY_INVALID_DESTINATION");
  }

  return bytes;
}

function encodeUnsignedCapability(
  signingKeyId: string,
  binding: CapabilityBinding,
  issuedAtMs: number,
  expiresAtMs: number,
  capabilityId: Uint8Array
): Uint8Array {
  const keyId = encodeCapabilityText(signingKeyId);
  const edgeUserId = encodeCapabilityText(binding.edgeUserId);
  const edgeDeviceId = encodeCapabilityText(binding.edgeDeviceId);
  const agentId = encodeCapabilityText(binding.agentId);
  const hostname = encodeCapabilityHostname(binding.destination.hostname);

  if (capabilityId.byteLength !== CAPABILITY_ID_BYTES) {
    failIdentity("IDENTITY_INVALID_CAPABILITY_ID");
  }

  const encoded = new Uint8Array(
    CAPABILITY_HEADER_BYTES + keyId.byteLength + edgeUserId.byteLength + edgeDeviceId.byteLength + agentId.byteLength + hostname.byteLength
  );
  const view = new DataView(encoded.buffer);

  encoded[0] = CAPABILITY_VERSION;
  encoded[1] = keyId.byteLength;
  encoded[2] = edgeUserId.byteLength;
  encoded[3] = edgeDeviceId.byteLength;
  encoded[4] = agentId.byteLength;
  encoded[5] = hostname.byteLength;
  view.setUint16(6, 443);
  view.setBigUint64(8, BigInt(issuedAtMs));
  view.setBigUint64(16, BigInt(expiresAtMs));
  encoded.set(binding.streamId, 24);
  encoded.set(capabilityId, 40);

  let offset = CAPABILITY_HEADER_BYTES;
  for (const value of [keyId, edgeUserId, edgeDeviceId, agentId, hostname]) {
    encoded.set(value, offset);
    offset += value.byteLength;
  }

  return encoded;
}

function decodeCapability(capability: Uint8Array): ParsedCapability {
  if (
    !(capability instanceof Uint8Array) ||
    capability.byteLength < CAPABILITY_HEADER_BYTES + CAPABILITY_SIGNATURE_BYTES ||
    capability.byteLength > MAX_CAPABILITY_BYTES
  ) {
    return failCapability();
  }

  if (capability[0] !== CAPABILITY_VERSION) {
    return failCapability();
  }

  const lengths = capability.subarray(1, 6);

  if (
    lengths[0] === undefined ||
    lengths[1] === undefined ||
    lengths[2] === undefined ||
    lengths[3] === undefined ||
    lengths[4] === undefined ||
    lengths[0] === 0 ||
    lengths[1] === 0 ||
    lengths[2] === 0 ||
    lengths[3] === 0 ||
    lengths[4] === 0 ||
    lengths[0] > MAX_IDENTITY_ID_BYTES ||
    lengths[1] > MAX_IDENTITY_ID_BYTES ||
    lengths[2] > MAX_IDENTITY_ID_BYTES ||
    lengths[3] > MAX_IDENTITY_ID_BYTES ||
    lengths[4] > 253
  ) {
    return failCapability();
  }

  const variableBytes = lengths.reduce((total, length) => total + length, 0);
  const unsignedLength = CAPABILITY_HEADER_BYTES + variableBytes;

  if (unsignedLength + CAPABILITY_SIGNATURE_BYTES !== capability.byteLength) {
    return failCapability();
  }

  const view = new DataView(capability.buffer, capability.byteOffset, capability.byteLength);

  if (view.getUint16(6) !== 443) {
    return failCapability();
  }

  const issuedAtMs = readTimestamp(capability, 8);
  const expiresAtMs = readTimestamp(capability, 16);
  const streamId = capability.subarray(24, 40);
  const capabilityId = capability.subarray(40, 56);
  let offset = CAPABILITY_HEADER_BYTES;
  const values: string[] = [];

  for (const length of lengths) {
    values.push(decodeCapabilityText(capability.subarray(offset, offset + length)));
    offset += length;
  }

  const [signingKeyId, edgeUserId, edgeDeviceId, agentId, hostname] = values;

  if (
    signingKeyId === undefined ||
    edgeUserId === undefined ||
    edgeDeviceId === undefined ||
    agentId === undefined ||
    hostname === undefined ||
    streamId.byteLength !== STREAM_ID_BYTES ||
    capabilityId.byteLength !== CAPABILITY_ID_BYTES
  ) {
    return failCapability();
  }

  try {
    normalizeHostname(hostname);
  } catch {
    return failCapability();
  }

  return Object.freeze({
    signingKeyId,
    binding: Object.freeze({
      edgeUserId,
      edgeDeviceId,
      agentId,
      streamId: freezeBytes(streamId),
      destination: Object.freeze({ hostname, port: 443 })
    }),
    issuedAtMs,
    expiresAtMs,
    capabilityId: freezeBytes(capabilityId),
    signature: freezeBytes(capability.subarray(unsignedLength)),
    signedBytes: freezeBytes(capability.subarray(0, unsignedLength))
  });
}

function bindingsMatch(left: CapabilityBinding, right: CapabilityBinding): boolean {
  return (
    left.edgeUserId === right.edgeUserId &&
    left.edgeDeviceId === right.edgeDeviceId &&
    left.agentId === right.agentId &&
    left.destination.hostname === right.destination.hostname &&
    left.destination.port === right.destination.port &&
    safeEqual(left.streamId, right.streamId)
  );
}

function capabilityTimeIsValid(issuedAtMs: number, expiresAtMs: number, nowMs: number): boolean {
  return (
    Number.isSafeInteger(nowMs) &&
    nowMs >= 0 &&
    Number.isSafeInteger(issuedAtMs) &&
    Number.isSafeInteger(expiresAtMs) &&
    issuedAtMs >= 0 &&
    expiresAtMs > issuedAtMs &&
    expiresAtMs - issuedAtMs <= MAX_CAPABILITY_WINDOW_MS &&
    issuedAtMs <= nowMs &&
    nowMs < expiresAtMs
  );
}

function publicAndPrivateKeysMatch(
  publicKey: IdentityPublicKey<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>,
  privateKey: IdentityPrivateKey<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>
): boolean {
  const derivedPublicKey = createPublicKey(privateKey.key);
  const left = Uint8Array.from(publicKey.key.export({ format: "der", type: "spki" }));
  const right = Uint8Array.from(derivedPublicKey.export({ format: "der", type: "spki" }));
  return safeEqual(left, right);
}

export function createIdentityPublicKey<Role extends IdentityKeyRole>(
  reference: IdentityKeyReference<Role>,
  key: KeyObject
): IdentityPublicKey<Role> {
  assertKnownKeyRole(reference.role);
  assertIdentityId(reference.keyId);
  assertKeyObject(key, "public");
  return Object.freeze({ role: reference.role, keyId: reference.keyId, key });
}

export function createIdentityPrivateKey<Role extends IdentityKeyRole>(
  reference: IdentityKeyReference<Role>,
  key: KeyObject
): IdentityPrivateKey<Role> {
  assertKnownKeyRole(reference.role);
  assertIdentityId(reference.keyId);
  assertKeyObject(key, "private");
  return Object.freeze({ role: reference.role, keyId: reference.keyId, key });
}

export function loadIdentityPublicKey<Role extends IdentityKeyRole>(
  loader: IdentityKeyLoader,
  reference: IdentityKeyReference<Role>
): IdentityPublicKey<Role> {
  try {
    return createIdentityPublicKey(reference, loader.loadPublicKey(reference));
  } catch {
    return failIdentity("IDENTITY_KEY_LOAD_FAILED");
  }
}

export function loadIdentityPrivateKey<Role extends IdentityKeyRole>(
  loader: IdentityKeyLoader,
  reference: IdentityKeyReference<Role>
): IdentityPrivateKey<Role> {
  try {
    return createIdentityPrivateKey(reference, loader.loadPrivateKey(reference));
  } catch {
    return failIdentity("IDENTITY_KEY_LOAD_FAILED");
  }
}

export function createEdgeDeviceIdentity(input: {
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
  readonly authenticationKey: IdentityPublicKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
}): EdgeDeviceIdentity {
  assertIdentityId(input.edgeUserId);
  assertIdentityId(input.edgeDeviceId);
  assertKeyRole(input.authenticationKey, IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION);
  assertKeyObject(input.authenticationKey.key, "public");
  return Object.freeze({
    kind: "edge-device",
    edgeUserId: input.edgeUserId,
    edgeDeviceId: input.edgeDeviceId,
    authenticationKey: input.authenticationKey
  });
}

export function createEgressAgentIdentity(input: {
  readonly agentId: string;
  readonly authenticationKey: IdentityPublicKey<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
}): EgressAgentIdentity {
  assertIdentityId(input.agentId);
  assertKeyRole(input.authenticationKey, IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION);
  assertKeyObject(input.authenticationKey.key, "public");
  return Object.freeze({
    kind: "egress-agent",
    agentId: input.agentId,
    authenticationKey: input.authenticationKey
  });
}

export function createServerSigningIdentity(input: {
  readonly serverId: string;
  readonly capabilityVerificationKey: IdentityPublicKey<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>;
}): ServerSigningIdentity {
  assertIdentityId(input.serverId);
  assertKeyRole(input.capabilityVerificationKey, IdentityKeyRole.SERVER_CAPABILITY_SIGNING);
  assertKeyObject(input.capabilityVerificationKey.key, "public");
  return Object.freeze({
    kind: "server",
    serverId: input.serverId,
    capabilityVerificationKey: input.capabilityVerificationKey
  });
}

export function createServerSigningCredentials(input: {
  readonly identity: ServerSigningIdentity;
  readonly capabilitySigningKey: IdentityPrivateKey<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>;
}): ServerSigningCredentials {
  assertKeyRole(input.capabilitySigningKey, IdentityKeyRole.SERVER_CAPABILITY_SIGNING);
  assertKeyObject(input.capabilitySigningKey.key, "private");

  if (
    input.identity.capabilityVerificationKey.keyId !== input.capabilitySigningKey.keyId ||
    !publicAndPrivateKeysMatch(input.identity.capabilityVerificationKey, input.capabilitySigningKey)
  ) {
    failIdentity("IDENTITY_KEYPAIR_MISMATCH");
  }

  return Object.freeze({ identity: input.identity, capabilitySigningKey: input.capabilitySigningKey });
}

export class NonceReplayProtector {
  private readonly entries = new Map<string, number>();

  public constructor(private readonly maximumEntries = MAX_REPLAY_ENTRIES) {
    if (!Number.isSafeInteger(maximumEntries) || maximumEntries < 1 || maximumEntries > MAX_REPLAY_ENTRIES) {
      failIdentity("IDENTITY_INVALID_REPLAY_LIMIT");
    }
  }

  public consume(nonce: Uint8Array, expiresAtMs: number, nowMs: number): boolean {
    if (
      !(nonce instanceof Uint8Array) ||
      nonce.byteLength < MIN_NONCE_BYTES ||
      nonce.byteLength > MAX_NONCE_BYTES ||
      !Number.isSafeInteger(expiresAtMs) ||
      !Number.isSafeInteger(nowMs) ||
      expiresAtMs <= nowMs ||
      nowMs < 0
    ) {
      return false;
    }

    this.removeExpired(nowMs);
    const key = bytesKey(nonce);

    if (this.entries.has(key) || this.entries.size >= this.maximumEntries) {
      return false;
    }

    this.entries.set(key, expiresAtMs);
    return true;
  }

  private removeExpired(nowMs: number): void {
    for (const [key, expiresAtMs] of this.entries) {
      if (expiresAtMs <= nowMs) {
        this.entries.delete(key);
      }
    }
  }
}

export class CapabilityReplayProtector {
  private readonly entries = new Map<string, number>();

  public constructor(private readonly maximumEntries = MAX_REPLAY_ENTRIES) {
    if (!Number.isSafeInteger(maximumEntries) || maximumEntries < 1 || maximumEntries > MAX_REPLAY_ENTRIES) {
      failIdentity("IDENTITY_INVALID_REPLAY_LIMIT");
    }
  }

  public consume(capabilityId: Uint8Array, expiresAtMs: number, nowMs: number): boolean {
    if (
      !(capabilityId instanceof Uint8Array) ||
      capabilityId.byteLength !== CAPABILITY_ID_BYTES ||
      !Number.isSafeInteger(expiresAtMs) ||
      !Number.isSafeInteger(nowMs) ||
      expiresAtMs <= nowMs ||
      nowMs < 0
    ) {
      return false;
    }

    this.removeExpired(nowMs);
    const key = bytesKey(capabilityId);

    if (this.entries.has(key) || this.entries.size >= this.maximumEntries) {
      return false;
    }

    this.entries.set(key, expiresAtMs);
    return true;
  }

  private removeExpired(nowMs: number): void {
    for (const [key, expiresAtMs] of this.entries) {
      if (expiresAtMs <= nowMs) {
        this.entries.delete(key);
      }
    }
  }
}

export function issueAuthenticationChallenge(options: AuthenticationChallengeOptions): IssuedAuthenticationChallenge {
  assertSafeTimestamp(options.nowMs);
  const ttlMs = options.ttlMs ?? MAX_AUTHENTICATION_WINDOW_MS;

  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_AUTHENTICATION_WINDOW_MS) {
    failIdentity("IDENTITY_INVALID_CHALLENGE_WINDOW");
  }

  const expiresAtMs = options.nowMs + ttlMs;
  assertSafeTimestamp(expiresAtMs);
  return Object.freeze({
    issuedAtMs: options.nowMs,
    payload: Object.freeze({
      nonce: validateRandomBytes(options.randomBytes, AUTHENTICATION_CHALLENGE_NONCE_BYTES),
      expiresAtMs
    })
  });
}

export function signAuthenticationChallenge(input: AuthenticationProofInput): AuthenticatePayload {
  const expectedRole = expectedAuthenticationKeyRole(input.identity);
  assertKeyRole(input.signingKey, expectedRole);
  assertKeyObject(input.signingKey.key, "private");
  const message = encodeAuthenticationMessage(input.identity, input.registration, input.challenge);
  const signature = signDetached(null, message, input.signingKey.key);

  return Object.freeze({
    challengeNonce: freezeBytes(input.challenge.payload.nonce),
    signature: freezeBytes(signature)
  });
}

export function verifyAuthenticationChallenge(input: AuthenticationVerificationInput): AuthenticationVerificationResult {
  try {
    assertSafeTimestamp(input.nowMs);

    if (
      input.challenge.issuedAtMs > input.nowMs ||
      input.challenge.payload.expiresAtMs <= input.nowMs ||
      input.challenge.payload.expiresAtMs - input.challenge.issuedAtMs > MAX_AUTHENTICATION_WINDOW_MS
    ) {
      return { ok: false, errorCode: TunnelErrorCode.AUTH_EXPIRED };
    }

    if (!isMatchingRegistration(input.identity, input.registration)) {
      return { ok: false, errorCode: TunnelErrorCode.AUTH_FAILED };
    }

    if (
      !(input.response.challengeNonce instanceof Uint8Array) ||
      input.response.challengeNonce.byteLength !== AUTHENTICATION_CHALLENGE_NONCE_BYTES ||
      !(input.response.signature instanceof Uint8Array) ||
      input.response.signature.byteLength === 0 ||
      input.response.signature.byteLength > MAX_SIGNATURE_BYTES
    ) {
      return { ok: false, errorCode: TunnelErrorCode.AUTH_FAILED };
    }

    if (!safeEqual(input.response.challengeNonce, input.challenge.payload.nonce)) {
      return { ok: false, errorCode: TunnelErrorCode.AUTH_FAILED };
    }

    const expectedRole = expectedAuthenticationKeyRole(input.identity);
    assertKeyRole(input.identity.authenticationKey, expectedRole);
    assertKeyObject(input.identity.authenticationKey.key, "public");
    const message = encodeAuthenticationMessage(input.identity, input.registration, input.challenge);
    const isValid = verifyDetached(null, message, input.identity.authenticationKey.key, input.response.signature);

    if (!isValid) {
      return { ok: false, errorCode: TunnelErrorCode.AUTH_FAILED };
    }

    if (!input.replayProtector.consume(input.challenge.payload.nonce, input.challenge.payload.expiresAtMs, input.nowMs)) {
      return { ok: false, errorCode: TunnelErrorCode.AUTH_REPLAYED };
    }

    return { ok: true };
  } catch {
    return { ok: false, errorCode: TunnelErrorCode.AUTH_FAILED };
  }
}

export function issueCapability(input: CapabilityIssueInput): Uint8Array {
  assertSafeTimestamp(input.nowMs);

  if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1 || input.ttlMs > MAX_CAPABILITY_WINDOW_MS) {
    failIdentity("IDENTITY_INVALID_CAPABILITY_WINDOW");
  }

  const expiresAtMs = input.nowMs + input.ttlMs;
  assertSafeTimestamp(expiresAtMs);
  const binding = normalizeBinding(input.binding, input.allowedDestination);
  const credentials = createServerSigningCredentials(input.credentials);
  const capabilityId = validateRandomBytes(input.randomBytes, CAPABILITY_ID_BYTES);
  const signedBytes = encodeUnsignedCapability(
    credentials.identity.capabilityVerificationKey.keyId,
    binding,
    input.nowMs,
    expiresAtMs,
    capabilityId
  );
  const signature = signDetached(null, signedBytes, credentials.capabilitySigningKey.key);

  if (signature.byteLength !== CAPABILITY_SIGNATURE_BYTES) {
    failIdentity("IDENTITY_INVALID_SIGNATURE");
  }

  const capability = new Uint8Array(signedBytes.byteLength + signature.byteLength);
  capability.set(signedBytes);
  capability.set(signature, signedBytes.byteLength);
  return capability;
}

export function verifyCapability(input: CapabilityVerificationInput): CapabilityVerificationResult {
  try {
    const parsed = decodeCapability(input.capability);
    const expectedBinding = normalizeBinding(input.expectedBinding, input.allowedDestination);
    const serverIdentity = createServerSigningIdentity(input.serverIdentity);

    if (
      !capabilityTimeIsValid(parsed.issuedAtMs, parsed.expiresAtMs, input.nowMs) ||
      parsed.signingKeyId !== serverIdentity.capabilityVerificationKey.keyId ||
      !bindingsMatch(parsed.binding, expectedBinding) ||
      !verifyDetached(null, parsed.signedBytes, serverIdentity.capabilityVerificationKey.key, parsed.signature) ||
      !input.replayProtector.consume(parsed.capabilityId, parsed.expiresAtMs, input.nowMs)
    ) {
      return { ok: false, errorCode: TunnelErrorCode.CAPABILITY_INVALID };
    }

    return {
      ok: true,
      capability: Object.freeze({
        binding: parsed.binding,
        issuedAtMs: parsed.issuedAtMs,
        expiresAtMs: parsed.expiresAtMs,
        capabilityId: freezeBytes(parsed.capabilityId),
        signingKeyId: parsed.signingKeyId
      })
    };
  } catch {
    return { ok: false, errorCode: TunnelErrorCode.CAPABILITY_INVALID };
  }
}
