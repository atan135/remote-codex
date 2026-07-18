import { createHash, type Hash, type KeyObject } from "node:crypto";

import type { LoadedServerProductionBundle } from "@remote-codex/ops";
import type { ServerPeerIdentityRegistration } from "@remote-codex/server";

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("SERVER_HOST_FINGERPRINT_NUMBER_INVALID");
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("SERVER_HOST_FINGERPRINT_VALUE_INVALID");
}

function updateBytes(hash: Hash, label: string, value: Uint8Array): void {
  const labelBytes = Buffer.from(label, "utf8");
  const lengths = Buffer.allocUnsafe(8);
  lengths.writeUInt32BE(labelBytes.byteLength, 0);
  lengths.writeUInt32BE(value.byteLength, 4);
  hash.update(lengths);
  hash.update(labelBytes);
  hash.update(value);
}

function updateJson(hash: Hash, label: string, value: unknown): void {
  updateBytes(hash, label, Buffer.from(canonicalJson(value), "utf8"));
}

function exportedPublicKey(key: KeyObject): Buffer {
  return Buffer.from(key.export({ format: "der", type: "spki" }));
}

function peerSortKey(registration: ServerPeerIdentityRegistration): string {
  const identity = registration.identity;
  return identity.kind === "edge-device"
    ? `edge-device\0${identity.edgeUserId}\0${identity.edgeDeviceId}`
    : `egress-agent\0${identity.agentId}`;
}

function updatePeer(hash: Hash, registration: ServerPeerIdentityRegistration, index: number): void {
  const identity = registration.identity;
  const prefix = `peer[${index}]`;
  if (identity.kind === "edge-device") {
    updateJson(hash, `${prefix}.metadata`, {
      kind: identity.kind,
      edgeUserId: identity.edgeUserId,
      edgeDeviceId: identity.edgeDeviceId,
      keyRole: identity.authenticationKey.role,
      keyId: identity.authenticationKey.keyId,
      expiresAtMs: registration.expiresAtMs
    });
  } else {
    updateJson(hash, `${prefix}.metadata`, {
      kind: identity.kind,
      agentId: identity.agentId,
      keyRole: identity.authenticationKey.role,
      keyId: identity.authenticationKey.keyId,
      expiresAtMs: registration.expiresAtMs
    });
  }
  updateBytes(hash, `${prefix}.publicKey`, exportedPublicKey(identity.authenticationKey.key));
}

/** TLS PEM 不参与摘要；已验证配对的签名私钥只由 SPKI 与 key metadata 标识，不导出私钥字节。 */
export function fingerprintNonTlsServerBundle(bundle: LoadedServerProductionBundle): string {
  const hash = createHash("sha256");
  updateJson(hash, "serverConfig", bundle.config);
  updateJson(hash, "hostConfig", bundle.hostConfig);
  updateJson(hash, "authorizationDocument", bundle.authorizationDocument);

  const peers = [...bundle.peerIdentities].sort((left, right) => {
    const leftKey = peerSortKey(left);
    const rightKey = peerSortKey(right);
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  peers.forEach((registration, index) => updatePeer(hash, registration, index));

  const credentials = bundle.signingCredentials;
  updateJson(hash, "serverSigningIdentity", {
    kind: credentials.identity.kind,
    serverId: credentials.identity.serverId,
    verificationKeyRole: credentials.identity.capabilityVerificationKey.role,
    verificationKeyId: credentials.identity.capabilityVerificationKey.keyId,
    signingKeyRole: credentials.capabilitySigningKey.role,
    signingKeyId: credentials.capabilitySigningKey.keyId
  });
  updateBytes(
    hash,
    "serverSigningPublicKey",
    exportedPublicKey(credentials.identity.capabilityVerificationKey.key)
  );
  return hash.digest("hex");
}
