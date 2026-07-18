import { lstatSync } from "node:fs";
import { join } from "node:path";

import {
  AuthorizationRegistry,
  AuthorizationStatus,
  parseAuthorizationRegistryJson,
  type AuthorizationQuota,
  type AuthorizationRegistration,
  type AuthorizationRegistryDocument,
  type ServerPeerIdentityRegistration
} from "@remote-codex/server";

import { fail } from "./errors.js";
import { loadPeerIdentityRegistryWithSecurity } from "./production-loader.js";
import {
  acquireFileLock,
  atomicReplaceOwnerOnly,
  createOwnerOnlyDirectory,
  deploymentRoot,
  readDeploymentFileWithSecurity,
  resolveDeploymentFileWithSecurity,
  writeNewFile
} from "./secure-files.js";
import type { FileSecurityAdapter } from "./secure-files.js";

export type AuthorizationChange =
  | {
      readonly operation: "grant";
      readonly edgeUserId: string;
      readonly edgeDeviceId: string;
      readonly agentId: string;
      readonly quota: AuthorizationQuota;
      readonly nowMs: number;
    }
  | {
      readonly operation: "tighten-quota";
      readonly edgeUserId: string;
      readonly edgeDeviceId: string;
      readonly agentId: string;
      readonly quota: AuthorizationQuota;
    }
  | {
      readonly operation: "revoke";
      readonly selector: "edge-user" | "edge-device" | "agent";
      readonly id: string;
      readonly nowMs: number;
    };

export interface AuthorizationFileOptions {
  readonly rootDirectory: string;
  readonly authorizationPath: string;
  readonly peerIdentityRegistryPath: string;
  readonly historyDirectory: string;
}

function serialize(document: AuthorizationRegistryDocument): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}

function auditFileName(version: number): string {
  return `authorization-v${version.toString().padStart(12, "0")}.json`;
}

function nextVersion(document: AuthorizationRegistryDocument): number {
  if (document.auditVersion >= Number.MAX_SAFE_INTEGER) {
    return fail("OPS_AUTHORIZATION_VERSION_EXHAUSTED");
  }
  return document.auditVersion + 1;
}

function validateCandidate(
  peerIdentities: readonly ServerPeerIdentityRegistration[],
  document: AuthorizationRegistryDocument
): AuthorizationRegistryDocument {
  return new AuthorizationRegistry({ peerIdentities, document }).getSnapshot();
}

function grant(
  current: AuthorizationRegistryDocument,
  change: Extract<AuthorizationChange, { operation: "grant" }>,
  peerIdentities: readonly ServerPeerIdentityRegistration[]
): AuthorizationRegistryDocument {
  const activeRoute = current.authorizations.find(
    (entry) => entry.edgeUserId === change.edgeUserId && entry.edgeDeviceId === change.edgeDeviceId && entry.status === AuthorizationStatus.ACTIVE
  );
  if (activeRoute !== undefined) {
    return fail(activeRoute.agentId === change.agentId ? "OPS_AUTHORIZATION_ALREADY_ACTIVE" : "OPS_AUTHORIZATION_ACTIVE_ROUTE_CONFLICT");
  }
  const auditVersion = nextVersion(current);
  const existingIndex = current.authorizations.findIndex(
    (entry) => entry.edgeUserId === change.edgeUserId && entry.edgeDeviceId === change.edgeDeviceId && entry.agentId === change.agentId
  );
  const active: AuthorizationRegistration = {
    edgeUserId: change.edgeUserId,
    edgeDeviceId: change.edgeDeviceId,
    agentId: change.agentId,
    status: AuthorizationStatus.ACTIVE,
    quota: change.quota,
    createdAtMs: change.nowMs,
    auditVersion
  };
  const authorizations = [...current.authorizations];
  if (existingIndex === -1) {
    authorizations.push(active);
  } else {
    authorizations[existingIndex] = active;
  }
  return validateCandidate(peerIdentities, { auditVersion, authorizations });
}

function tightenQuota(
  current: AuthorizationRegistryDocument,
  change: Extract<AuthorizationChange, { operation: "tighten-quota" }>,
  peerIdentities: readonly ServerPeerIdentityRegistration[]
): AuthorizationRegistryDocument {
  const index = current.authorizations.findIndex(
    (entry) =>
      entry.edgeUserId === change.edgeUserId &&
      entry.edgeDeviceId === change.edgeDeviceId &&
      entry.agentId === change.agentId &&
      entry.status === AuthorizationStatus.ACTIVE
  );
  if (index === -1) {
    return fail("OPS_AUTHORIZATION_ACTIVE_ROUTE_NOT_FOUND");
  }
  const existing = current.authorizations[index]!;
  if (
    change.quota.maxConcurrentStreams > existing.quota.maxConcurrentStreams ||
    change.quota.maxBufferedBytes > existing.quota.maxBufferedBytes
  ) {
    return fail("OPS_AUTHORIZATION_QUOTA_INCREASE_FORBIDDEN");
  }
  if (
    change.quota.maxConcurrentStreams === existing.quota.maxConcurrentStreams &&
    change.quota.maxBufferedBytes === existing.quota.maxBufferedBytes
  ) {
    return fail("OPS_AUTHORIZATION_NO_CHANGE");
  }
  const auditVersion = nextVersion(current);
  const authorizations = [...current.authorizations];
  authorizations[index] = { ...existing, quota: change.quota, auditVersion };
  return validateCandidate(peerIdentities, { auditVersion, authorizations });
}

function revoke(
  current: AuthorizationRegistryDocument,
  change: Extract<AuthorizationChange, { operation: "revoke" }>,
  peerIdentities: readonly ServerPeerIdentityRegistration[]
): AuthorizationRegistryDocument {
  const registry = new AuthorizationRegistry({ peerIdentities, document: current });
  const result = change.selector === "edge-user"
    ? registry.revokeByEdgeUser(change.id, change.nowMs)
    : change.selector === "edge-device"
      ? registry.revokeByEdgeDevice(change.id, change.nowMs)
      : registry.revokeByAgent(change.id, change.nowMs);
  if (!result.changed) {
    return fail("OPS_AUTHORIZATION_NO_CHANGE");
  }
  return registry.getSnapshot();
}

function historyRelativePath(historyDirectory: string, version: number): string {
  return `${historyDirectory}/${auditFileName(version)}`;
}

function pathEntryExists(filePath: string): boolean {
  try {
    lstatSync(filePath);
    return true;
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function archive(
  rootDirectory: string,
  historyDirectory: string,
  directory: string,
  document: AuthorizationRegistryDocument,
  adapter?: FileSecurityAdapter
): void {
  const relativePath = historyRelativePath(historyDirectory, document.auditVersion);
  const filePath = join(directory, auditFileName(document.auditVersion));
  const contents = serialize(document);
  if (pathEntryExists(filePath)) {
    if (readDeploymentFileWithSecurity(rootDirectory, relativePath, "owner-only", adapter) !== contents) {
      fail("OPS_AUTHORIZATION_AUDIT_CONFLICT");
    }
    return;
  }
  writeNewFile(filePath, contents, "owner-only", adapter);
}

export function changeAuthorizationFile(
  options: AuthorizationFileOptions,
  change: AuthorizationChange
): AuthorizationRegistryDocument {
  return changeAuthorizationFileWithSecurity(options, change);
}

export function changeAuthorizationFileWithSecurity(
  options: AuthorizationFileOptions,
  change: AuthorizationChange,
  adapter?: FileSecurityAdapter
): AuthorizationRegistryDocument {
  const root = deploymentRoot(options.rootDirectory, adapter);
  const authorizationFile = resolveDeploymentFileWithSecurity(root, options.authorizationPath, adapter);
  const release = acquireFileLock(`${authorizationFile}.lock`, adapter);
  try {
    const peerIdentities = loadPeerIdentityRegistryWithSecurity(root, options.peerIdentityRegistryPath, adapter);
    const current = parseAuthorizationRegistryJson(
      readDeploymentFileWithSecurity(root, options.authorizationPath, "owner-only", adapter)
    );
    const candidate = change.operation === "grant"
      ? grant(current, change, peerIdentities)
      : change.operation === "tighten-quota"
        ? tightenQuota(current, change, peerIdentities)
        : revoke(current, change, peerIdentities);
    const history = createOwnerOnlyDirectory(root, options.historyDirectory, adapter);
    archive(root, options.historyDirectory, history, current, adapter);
    archive(root, options.historyDirectory, history, candidate, adapter);
    atomicReplaceOwnerOnly(authorizationFile, serialize(candidate), adapter);
    return candidate;
  } finally {
    release();
  }
}

export function verifyAuthorizationAuditTrail(options: AuthorizationFileOptions): {
  readonly auditVersion: number;
  readonly archivedVersions: readonly number[];
} {
  return verifyAuthorizationAuditTrailWithSecurity(options);
}

export function verifyAuthorizationAuditTrailWithSecurity(
  options: AuthorizationFileOptions,
  adapter?: FileSecurityAdapter
): {
  readonly auditVersion: number;
  readonly archivedVersions: readonly number[];
} {
  const root = deploymentRoot(options.rootDirectory, adapter);
  const peerIdentities = loadPeerIdentityRegistryWithSecurity(root, options.peerIdentityRegistryPath, adapter);
  const current = parseAuthorizationRegistryJson(
    readDeploymentFileWithSecurity(root, options.authorizationPath, "owner-only", adapter)
  );
  validateCandidate(peerIdentities, current);
  const historyPath = createOwnerOnlyDirectory(root, options.historyDirectory, adapter);
  const versions: number[] = [];
  for (let version = 1; version <= current.auditVersion; version += 1) {
    const relativePath = historyRelativePath(options.historyDirectory, version);
    const filePath = join(historyPath, auditFileName(version));
    if (!pathEntryExists(filePath)) {
      if (version === current.auditVersion && versions.length === 0) {
        continue;
      }
      return fail("OPS_AUTHORIZATION_AUDIT_GAP");
    }
    const document = parseAuthorizationRegistryJson(
      readDeploymentFileWithSecurity(root, relativePath, "owner-only", adapter)
    );
    if (document.auditVersion !== version) {
      return fail("OPS_AUTHORIZATION_AUDIT_VERSION_MISMATCH");
    }
    validateCandidate(peerIdentities, document);
    versions.push(version);
  }
  if (versions.length > 0) {
    const latest = parseAuthorizationRegistryJson(
      readDeploymentFileWithSecurity(
        root,
        historyRelativePath(options.historyDirectory, current.auditVersion),
        "owner-only",
        adapter
      )
    );
    if (serialize(latest) !== serialize(current)) {
      return fail("OPS_AUTHORIZATION_CURRENT_NOT_ARCHIVED");
    }
  }
  return Object.freeze({ auditVersion: current.auditVersion, archivedVersions: Object.freeze(versions) });
}
