import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";

import {
  assertTlsVerificationEnabled,
  createEdgeDeviceIdentity,
  createEgressAgentIdentity,
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  parseRuntimeConfigJson,
  validateDestination,
  type EdgeClientConfig,
  type EdgeDeviceIdentity,
  type EgressAgentConfig,
  type EgressAgentIdentity,
  type IdentityPrivateKey,
  type ServerConfig,
  type ServerSigningCredentials,
  type ServerSigningIdentity
} from "@remote-codex/shared";
import {
  AuthorizationRegistry,
  parseAuthorizationRegistryJson,
  type AuthorizationRegistryDocument,
  type ServerPeerIdentityRegistration
} from "@remote-codex/server";

import { fail } from "./errors.js";
import { readDeploymentFileWithSecurity, type FileSecurityAdapter } from "./secure-files.js";
import { parseServerHostConfigJson, type ServerHostConfig } from "./server-host.js";
import {
  parsePeerIdentityRegistryJson,
  parseProductionManifestJson,
  type PeerIdentityRegistryDocument,
  type PrivateKeyFileReference,
  type PublicKeyFileReference
} from "./schema.js";

export const PRODUCTION_LISTEN_PORT_MIN = 8_000;
export const PRODUCTION_LISTEN_PORT_MAX = 9_000;

export interface LoadedServerProductionBundle {
  readonly component: "server";
  readonly config: ServerConfig;
  readonly hostConfig: ServerHostConfig;
  readonly tls: {
    readonly certificate: Buffer;
    readonly privateKey: Buffer;
  };
  readonly signingCredentials: ServerSigningCredentials;
  readonly peerIdentities: readonly ServerPeerIdentityRegistration[];
  readonly authorizationDocument: AuthorizationRegistryDocument;
}

export interface LoadedEgressAgentProductionBundle {
  readonly component: "egress-agent";
  readonly config: EgressAgentConfig;
  readonly identity: EgressAgentIdentity;
  readonly authenticationPrivateKey: IdentityPrivateKey<"egress-agent-authentication">;
  readonly serverIdentity: ServerSigningIdentity;
}

export interface LoadedEdgeClientProductionBundle {
  readonly component: "edge-client";
  readonly config: EdgeClientConfig;
  readonly identity: EdgeDeviceIdentity;
  readonly authenticationPrivateKey: IdentityPrivateKey<"edge-device-authentication">;
  readonly serverIdentity: ServerSigningIdentity;
}

export type LoadedProductionBundle =
  | LoadedServerProductionBundle
  | LoadedEgressAgentProductionBundle
  | LoadedEdgeClientProductionBundle;

function validateConfiguredDestination(config: ServerConfig | EgressAgentConfig | EdgeClientConfig): void {
  try {
    validateDestination(config.allowedDestination.hostname, config.allowedDestination.port, config.allowedDestination);
  } catch {
    fail("OPS_DESTINATION_INVALID", "config.allowedDestination");
  }
}

function loadPublicKey(
  rootDirectory: string,
  reference: PublicKeyFileReference,
  adapter?: FileSecurityAdapter
): KeyObject {
  try {
    const der = decodePemContainer(
      readDeploymentFileWithSecurity(rootDirectory, reference.publicKeyPath, "public-readonly", adapter),
      "PUBLIC KEY"
    );
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      return fail("OPS_PUBLIC_KEY_INVALID", reference.publicKeyPath);
    }
    return key;
  } catch (error: unknown) {
    if (error instanceof Error && error.name === "OpsError") {
      throw error;
    }
    return fail("OPS_PUBLIC_KEY_INVALID", reference.publicKeyPath);
  }
}

function loadPrivateKey(
  rootDirectory: string,
  reference: PrivateKeyFileReference,
  adapter?: FileSecurityAdapter
): KeyObject {
  try {
    const der = decodePemContainer(
      readDeploymentFileWithSecurity(rootDirectory, reference.privateKeyPath, "owner-only", adapter),
      "PRIVATE KEY"
    );
    const key = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
      return fail("OPS_PRIVATE_KEY_INVALID", reference.privateKeyPath);
    }
    return key;
  } catch (error: unknown) {
    if (error instanceof Error && error.name === "OpsError") {
      throw error;
    }
    return fail("OPS_PRIVATE_KEY_INVALID", reference.privateKeyPath);
  }
}

function decodePemContainer(serialized: string, label: "PUBLIC KEY" | "PRIVATE KEY"): Buffer {
  const escapedLabel = label.replace(" ", "\\s");
  const expression = new RegExp(
    `^-----BEGIN ${escapedLabel}-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+)\\r?\\n-----END ${escapedLabel}-----\\r?\\n?$`,
    "u"
  );
  const match = expression.exec(serialized);
  if (match?.[1] === undefined) {
    return fail(label === "PUBLIC KEY" ? "OPS_PUBLIC_KEY_INVALID" : "OPS_PRIVATE_KEY_INVALID");
  }
  const encoded = match[1].replace(/\r?\n/gu, "");
  if (encoded.length === 0 || encoded.length % 4 !== 0) {
    return fail(label === "PUBLIC KEY" ? "OPS_PUBLIC_KEY_INVALID" : "OPS_PRIVATE_KEY_INVALID");
  }
  const der = Buffer.from(encoded, "base64");
  if (der.toString("base64") !== encoded) {
    return fail(label === "PUBLIC KEY" ? "OPS_PUBLIC_KEY_INVALID" : "OPS_PRIVATE_KEY_INVALID");
  }
  return der;
}

function keyObjectsMatch(publicKey: KeyObject, privateKey: KeyObject): boolean {
  const expected = Buffer.from(publicKey.export({ format: "der", type: "spki" }));
  const actual = Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" }));
  return expected.equals(actual);
}

function loadPeerIdentities(
  rootDirectory: string,
  document: PeerIdentityRegistryDocument,
  adapter?: FileSecurityAdapter
): readonly ServerPeerIdentityRegistration[] {
  return Object.freeze(document.identities.map((entry): ServerPeerIdentityRegistration => {
    if (entry.kind === "edge-device") {
      const identity = createEdgeDeviceIdentity({
          edgeUserId: entry.edgeUserId,
          edgeDeviceId: entry.edgeDeviceId,
          authenticationKey: createIdentityPublicKey(entry.authenticationKey, loadPublicKey(rootDirectory, entry.authenticationKey, adapter))
        });
      return Object.freeze({ identity, ...(entry.expiresAtMs === undefined ? {} : { expiresAtMs: entry.expiresAtMs }) });
    }
    const identity = createEgressAgentIdentity({
      agentId: entry.agentId,
      authenticationKey: createIdentityPublicKey(entry.authenticationKey, loadPublicKey(rootDirectory, entry.authenticationKey, adapter))
    });
    return Object.freeze({ identity, ...(entry.expiresAtMs === undefined ? {} : { expiresAtMs: entry.expiresAtMs }) });
  }));
}

export function loadPeerIdentityRegistry(
  rootDirectory: string,
  registryPath: string
): readonly ServerPeerIdentityRegistration[] {
  return loadPeerIdentityRegistryWithSecurity(rootDirectory, registryPath);
}

export function loadPeerIdentityRegistryWithSecurity(
  rootDirectory: string,
  registryPath: string,
  adapter?: FileSecurityAdapter
): readonly ServerPeerIdentityRegistration[] {
  const document = parsePeerIdentityRegistryJson(
    readDeploymentFileWithSecurity(rootDirectory, registryPath, "owner-only", adapter)
  );
  return loadPeerIdentities(rootDirectory, document, adapter);
}

function loadServerBundle(
  rootDirectory: string,
  manifest: Extract<ReturnType<typeof parseProductionManifestJson>, { component: "server" }>,
  adapter?: FileSecurityAdapter
): LoadedServerProductionBundle {
  const parsedConfig = parseRuntimeConfigJson(
    readDeploymentFileWithSecurity(rootDirectory, manifest.configPath, "owner-only", adapter)
  );
  if (parsedConfig.component !== "server") {
    return fail("OPS_CONFIG_COMPONENT_MISMATCH", manifest.configPath);
  }
  validateConfiguredDestination(parsedConfig);
  const hostConfig = parseServerHostConfigJson(
    readDeploymentFileWithSecurity(rootDirectory, manifest.hostConfigPath, "owner-only", adapter)
  );
  if (hostConfig.transportLimits.maxMessageBytes < parsedConfig.limits.maxFramePayloadBytes + 256) {
    return fail("OPS_SERVER_MESSAGE_LIMIT_TOO_SMALL", manifest.hostConfigPath);
  }
  const certificate = Buffer.from(
    readDeploymentFileWithSecurity(rootDirectory, hostConfig.tlsCertificatePath, "public-readonly", adapter)
  );
  const tlsPrivateKey = Buffer.from(
    readDeploymentFileWithSecurity(rootDirectory, hostConfig.tlsPrivateKeyPath, "owner-only", adapter)
  );
  if (certificate.byteLength === 0 || tlsPrivateKey.byteLength === 0) {
    return fail("OPS_SERVER_TLS_CREDENTIALS_EMPTY", manifest.hostConfigPath);
  }
  const publicKey = createIdentityPublicKey(
    manifest.capabilitySigningKey,
    loadPublicKey(rootDirectory, manifest.capabilitySigningKey, adapter)
  );
  const privateKey = createIdentityPrivateKey(
    manifest.capabilitySigningKey,
    loadPrivateKey(rootDirectory, manifest.capabilitySigningKey, adapter)
  );
  const serverIdentity = createServerSigningIdentity({ serverId: parsedConfig.serverId, capabilityVerificationKey: publicKey });
  const signingCredentials = createServerSigningCredentials({ identity: serverIdentity, capabilitySigningKey: privateKey });
  const peerIdentities = loadPeerIdentityRegistryWithSecurity(rootDirectory, manifest.peerIdentityRegistryPath, adapter);
  const authorizationDocument = parseAuthorizationRegistryJson(
    readDeploymentFileWithSecurity(rootDirectory, manifest.authorizationRegistryPath, "owner-only", adapter)
  );
  new AuthorizationRegistry({ peerIdentities, document: authorizationDocument });
  return Object.freeze({
    component: "server",
    config: parsedConfig,
    hostConfig,
    tls: Object.freeze({ certificate, privateKey: tlsPrivateKey }),
    signingCredentials,
    peerIdentities,
    authorizationDocument
  });
}

function loadServerVerificationIdentity(
  rootDirectory: string,
  serverId: string,
  reference: PublicKeyFileReference<"server-capability-signing">,
  adapter?: FileSecurityAdapter
): ServerSigningIdentity {
  return createServerSigningIdentity({
    serverId,
    capabilityVerificationKey: createIdentityPublicKey(reference, loadPublicKey(rootDirectory, reference, adapter))
  });
}

export function loadProductionBundle(
  rootDirectory: string,
  manifestPath = "manifest.json",
  environment: NodeJS.ProcessEnv = process.env
): LoadedProductionBundle {
  return loadProductionBundleWithSecurity(rootDirectory, manifestPath, environment);
}

export function loadProductionBundleWithSecurity(
  rootDirectory: string,
  manifestPath: string,
  environment: NodeJS.ProcessEnv,
  adapter?: FileSecurityAdapter
): LoadedProductionBundle {
  assertTlsVerificationEnabled(environment);
  const manifest = parseProductionManifestJson(
    readDeploymentFileWithSecurity(rootDirectory, manifestPath, "owner-only", adapter)
  );
  if (manifest.component === "server") {
    return loadServerBundle(rootDirectory, manifest, adapter);
  }

  const parsedConfig = parseRuntimeConfigJson(
    readDeploymentFileWithSecurity(rootDirectory, manifest.configPath, "owner-only", adapter)
  );
  if (parsedConfig.component !== manifest.component) {
    return fail("OPS_CONFIG_COMPONENT_MISMATCH", manifest.configPath);
  }
  validateConfiguredDestination(parsedConfig);
  if (manifest.component === "egress-agent" && parsedConfig.component === "egress-agent") {
    const publicKey = createIdentityPublicKey(manifest.authenticationKey, loadPublicKey(rootDirectory, manifest.authenticationKey, adapter));
    const privateKey = createIdentityPrivateKey(manifest.authenticationKey, loadPrivateKey(rootDirectory, manifest.authenticationKey, adapter));
    if (!keyObjectsMatch(publicKey.key, privateKey.key)) {
      return fail("OPS_IDENTITY_KEYPAIR_MISMATCH", manifest.authenticationKey.keyId);
    }
    return Object.freeze({
      component: "egress-agent",
      config: parsedConfig,
      identity: createEgressAgentIdentity({ agentId: parsedConfig.agentId, authenticationKey: publicKey }),
      authenticationPrivateKey: privateKey,
      serverIdentity: loadServerVerificationIdentity(rootDirectory, manifest.serverId, manifest.serverCapabilityVerificationKey, adapter)
    });
  }
  if (manifest.component === "edge-client" && parsedConfig.component === "edge-client") {
    if (parsedConfig.listenPort < PRODUCTION_LISTEN_PORT_MIN || parsedConfig.listenPort > PRODUCTION_LISTEN_PORT_MAX) {
      return fail("OPS_LISTEN_PORT_OUTSIDE_APPROVED_RANGE", manifest.configPath);
    }
    const publicKey = createIdentityPublicKey(manifest.authenticationKey, loadPublicKey(rootDirectory, manifest.authenticationKey, adapter));
    const privateKey = createIdentityPrivateKey(manifest.authenticationKey, loadPrivateKey(rootDirectory, manifest.authenticationKey, adapter));
    if (!keyObjectsMatch(publicKey.key, privateKey.key)) {
      return fail("OPS_IDENTITY_KEYPAIR_MISMATCH", manifest.authenticationKey.keyId);
    }
    return Object.freeze({
      component: "edge-client",
      config: parsedConfig,
      identity: createEdgeDeviceIdentity({
        edgeUserId: parsedConfig.edgeUserId,
        edgeDeviceId: parsedConfig.edgeDeviceId,
        authenticationKey: publicKey
      }),
      authenticationPrivateKey: privateKey,
      serverIdentity: loadServerVerificationIdentity(rootDirectory, manifest.serverId, manifest.serverCapabilityVerificationKey, adapter)
    });
  }
  return fail("OPS_CONFIG_COMPONENT_MISMATCH", manifest.configPath);
}
