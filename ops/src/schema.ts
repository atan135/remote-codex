import { IdentityKeyRole, type IdentityKeyRole as IdentityKeyRoleType } from "@remote-codex/shared";

import { fail } from "./errors.js";

export const PRODUCTION_MANIFEST_SCHEMA_VERSION = 1 as const;
export const PEER_IDENTITY_REGISTRY_SCHEMA_VERSION = 1 as const;

export interface PublicKeyFileReference<Role extends IdentityKeyRoleType = IdentityKeyRoleType> {
  readonly role: Role;
  readonly keyId: string;
  readonly publicKeyPath: string;
}

export interface PrivateKeyFileReference<Role extends IdentityKeyRoleType = IdentityKeyRoleType>
  extends PublicKeyFileReference<Role> {
  readonly privateKeyPath: string;
}

export interface ServerProductionManifest {
  readonly schemaVersion: typeof PRODUCTION_MANIFEST_SCHEMA_VERSION;
  readonly component: "server";
  readonly configPath: string;
  readonly peerIdentityRegistryPath: string;
  readonly authorizationRegistryPath: string;
  readonly capabilitySigningKey: PrivateKeyFileReference<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>;
}

export interface EgressAgentProductionManifest {
  readonly schemaVersion: typeof PRODUCTION_MANIFEST_SCHEMA_VERSION;
  readonly component: "egress-agent";
  readonly serverId: string;
  readonly configPath: string;
  readonly authenticationKey: PrivateKeyFileReference<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
  readonly serverCapabilityVerificationKey: PublicKeyFileReference<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>;
}

export interface EdgeClientProductionManifest {
  readonly schemaVersion: typeof PRODUCTION_MANIFEST_SCHEMA_VERSION;
  readonly component: "edge-client";
  readonly serverId: string;
  readonly configPath: string;
  readonly authenticationKey: PrivateKeyFileReference<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
  readonly serverCapabilityVerificationKey: PublicKeyFileReference<typeof IdentityKeyRole.SERVER_CAPABILITY_SIGNING>;
}

export type ProductionManifest =
  | ServerProductionManifest
  | EgressAgentProductionManifest
  | EdgeClientProductionManifest;

export interface EdgePeerIdentityEntry {
  readonly kind: "edge-device";
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
  readonly authenticationKey: PublicKeyFileReference<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
  readonly expiresAtMs?: number;
}

export interface AgentPeerIdentityEntry {
  readonly kind: "egress-agent";
  readonly agentId: string;
  readonly authenticationKey: PublicKeyFileReference<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
  readonly expiresAtMs?: number;
}

export type PeerIdentityEntry = EdgePeerIdentityEntry | AgentPeerIdentityEntry;

export interface PeerIdentityRegistryDocument {
  readonly schemaVersion: typeof PEER_IDENTITY_REGISTRY_SCHEMA_VERSION;
  readonly identities: readonly PeerIdentityEntry[];
}

type JsonRecord = Record<string, unknown>;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function asRecord(value: unknown, path: string): JsonRecord {
  if (
    value === null ||
    typeof value !== "object" ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    return fail("OPS_EXPECTED_OBJECT", path);
  }
  return value as JsonRecord;
}

function exactKeys(record: JsonRecord, keys: readonly string[], path: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      fail("OPS_UNKNOWN_FIELD", `${path}.${key}`);
    }
  }
}

function stringValue(record: JsonRecord, key: string, path: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    return fail("OPS_INVALID_STRING", `${path}.${key}`);
  }
  return value;
}

function identifier(record: JsonRecord, key: string, path: string): string {
  const value = stringValue(record, key, path);
  if (!IDENTIFIER_PATTERN.test(value)) {
    return fail("OPS_INVALID_IDENTIFIER", `${path}.${key}`);
  }
  return value;
}

function relativePath(record: JsonRecord, key: string, path: string): string {
  const value = stringValue(record, key, path);
  if (
    value.includes("\\") ||
    value.includes(":") ||
    value.includes("\0") ||
    value.startsWith("/") ||
    value.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")
  ) {
    return fail("OPS_PATH_NOT_STRICTLY_RELATIVE", `${path}.${key}`);
  }
  return value;
}

function parsePublicKeyReference<Role extends IdentityKeyRoleType>(
  value: unknown,
  path: string,
  expectedRole: Role,
  includePrivate: false
): PublicKeyFileReference<Role>;
function parsePublicKeyReference<Role extends IdentityKeyRoleType>(
  value: unknown,
  path: string,
  expectedRole: Role,
  includePrivate: true
): PrivateKeyFileReference<Role>;
function parsePublicKeyReference<Role extends IdentityKeyRoleType>(
  value: unknown,
  path: string,
  expectedRole: Role,
  includePrivate: boolean
): PublicKeyFileReference<Role> | PrivateKeyFileReference<Role> {
  const record = asRecord(value, path);
  exactKeys(record, includePrivate ? ["role", "keyId", "publicKeyPath", "privateKeyPath"] : ["role", "keyId", "publicKeyPath"], path);
  if (record.role !== expectedRole) {
    return fail("OPS_IDENTITY_ROLE_MISMATCH", `${path}.role`);
  }
  const base = {
    role: expectedRole,
    keyId: identifier(record, "keyId", path),
    publicKeyPath: relativePath(record, "publicKeyPath", path)
  };
  if (!includePrivate) {
    return Object.freeze(base);
  }
  const privateKeyPath = relativePath(record, "privateKeyPath", path);
  if (privateKeyPath.toLowerCase() === base.publicKeyPath.toLowerCase()) {
    return fail("OPS_IDENTITY_KEY_PATH_CONFLICT", path);
  }
  return Object.freeze({ ...base, privateKeyPath });
}

function parseJson(serialized: string, path: string): unknown {
  if (typeof serialized !== "string" || serialized.length === 0) {
    return fail("OPS_INVALID_JSON", path);
  }
  try {
    return JSON.parse(serialized) as unknown;
  } catch {
    return fail("OPS_INVALID_JSON", path);
  }
}

export function parseProductionManifestJson(serialized: string): ProductionManifest {
  const record = asRecord(parseJson(serialized, "manifest"), "manifest");
  if (record.schemaVersion !== PRODUCTION_MANIFEST_SCHEMA_VERSION) {
    return fail("OPS_MANIFEST_VERSION_MISMATCH", "manifest.schemaVersion");
  }

  if (record.component === "server") {
    exactKeys(record, ["schemaVersion", "component", "configPath", "peerIdentityRegistryPath", "authorizationRegistryPath", "capabilitySigningKey"], "manifest");
    return Object.freeze({
      schemaVersion: PRODUCTION_MANIFEST_SCHEMA_VERSION,
      component: "server",
      configPath: relativePath(record, "configPath", "manifest"),
      peerIdentityRegistryPath: relativePath(record, "peerIdentityRegistryPath", "manifest"),
      authorizationRegistryPath: relativePath(record, "authorizationRegistryPath", "manifest"),
      capabilitySigningKey: parsePublicKeyReference(record.capabilitySigningKey, "manifest.capabilitySigningKey", IdentityKeyRole.SERVER_CAPABILITY_SIGNING, true)
    });
  }

  if (record.component === "egress-agent") {
    exactKeys(record, ["schemaVersion", "component", "serverId", "configPath", "authenticationKey", "serverCapabilityVerificationKey"], "manifest");
    return Object.freeze({
      schemaVersion: PRODUCTION_MANIFEST_SCHEMA_VERSION,
      component: "egress-agent",
      serverId: identifier(record, "serverId", "manifest"),
      configPath: relativePath(record, "configPath", "manifest"),
      authenticationKey: parsePublicKeyReference(record.authenticationKey, "manifest.authenticationKey", IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, true),
      serverCapabilityVerificationKey: parsePublicKeyReference(record.serverCapabilityVerificationKey, "manifest.serverCapabilityVerificationKey", IdentityKeyRole.SERVER_CAPABILITY_SIGNING, false)
    });
  }

  if (record.component === "edge-client") {
    exactKeys(record, ["schemaVersion", "component", "serverId", "configPath", "authenticationKey", "serverCapabilityVerificationKey"], "manifest");
    return Object.freeze({
      schemaVersion: PRODUCTION_MANIFEST_SCHEMA_VERSION,
      component: "edge-client",
      serverId: identifier(record, "serverId", "manifest"),
      configPath: relativePath(record, "configPath", "manifest"),
      authenticationKey: parsePublicKeyReference(record.authenticationKey, "manifest.authenticationKey", IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, true),
      serverCapabilityVerificationKey: parsePublicKeyReference(record.serverCapabilityVerificationKey, "manifest.serverCapabilityVerificationKey", IdentityKeyRole.SERVER_CAPABILITY_SIGNING, false)
    });
  }

  return fail("OPS_UNKNOWN_COMPONENT", "manifest.component");
}

function optionalExpiresAt(record: JsonRecord, path: string): { readonly expiresAtMs?: number } {
  if (!Object.prototype.hasOwnProperty.call(record, "expiresAtMs")) {
    return {};
  }
  if (!Number.isSafeInteger(record.expiresAtMs) || (record.expiresAtMs as number) < 0) {
    return fail("OPS_INVALID_EXPIRATION", `${path}.expiresAtMs`);
  }
  return { expiresAtMs: record.expiresAtMs as number };
}

export function parsePeerIdentityRegistryJson(serialized: string): PeerIdentityRegistryDocument {
  const record = asRecord(parseJson(serialized, "peerIdentities"), "peerIdentities");
  exactKeys(record, ["schemaVersion", "identities"], "peerIdentities");
  if (record.schemaVersion !== PEER_IDENTITY_REGISTRY_SCHEMA_VERSION || !Array.isArray(record.identities)) {
    return fail("OPS_PEER_IDENTITY_REGISTRY_INVALID", "peerIdentities");
  }
  const identities = record.identities.map((entry, index): PeerIdentityEntry => {
    const path = `peerIdentities.identities[${index}]`;
    const identity = asRecord(entry, path);
    if (identity.kind === "edge-device") {
      exactKeys(identity, ["kind", "edgeUserId", "edgeDeviceId", "authenticationKey", "expiresAtMs"], path);
      return Object.freeze({
        kind: "edge-device",
        edgeUserId: identifier(identity, "edgeUserId", path),
        edgeDeviceId: identifier(identity, "edgeDeviceId", path),
        authenticationKey: parsePublicKeyReference(identity.authenticationKey, `${path}.authenticationKey`, IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, false),
        ...optionalExpiresAt(identity, path)
      });
    }
    if (identity.kind === "egress-agent") {
      exactKeys(identity, ["kind", "agentId", "authenticationKey", "expiresAtMs"], path);
      return Object.freeze({
        kind: "egress-agent",
        agentId: identifier(identity, "agentId", path),
        authenticationKey: parsePublicKeyReference(identity.authenticationKey, `${path}.authenticationKey`, IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, false),
        ...optionalExpiresAt(identity, path)
      });
    }
    return fail("OPS_PEER_IDENTITY_KIND_INVALID", `${path}.kind`);
  });
  return Object.freeze({ schemaVersion: PEER_IDENTITY_REGISTRY_SCHEMA_VERSION, identities: Object.freeze(identities) });
}
