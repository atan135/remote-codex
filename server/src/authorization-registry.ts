import { DEFAULT_RESOURCE_LIMITS } from "@remote-codex/shared";

import type { ServerPeerIdentityRegistration } from "./peer-session.js";

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export const AuthorizationStatus = {
  ACTIVE: "active",
  REVOKED: "revoked"
} as const;

export type AuthorizationStatus = (typeof AuthorizationStatus)[keyof typeof AuthorizationStatus];

export interface AuthorizationQuota {
  readonly maxConcurrentStreams: number;
  readonly maxBufferedBytes: number;
}

/** 一条 edge user/device 到唯一 agent 的显式授权；不包含任何密钥或请求内容。 */
export interface AuthorizationRegistration {
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
  readonly agentId: string;
  readonly status: AuthorizationStatus;
  readonly quota: AuthorizationQuota;
  readonly createdAtMs: number;
  readonly revokedAtMs?: number;
  readonly auditVersion: number;
}

/** 授权文件的顶层审计版本必须在热更新时单调递增。 */
export interface AuthorizationRegistryDocument {
  readonly auditVersion: number;
  readonly authorizations: readonly AuthorizationRegistration[];
}

export interface AuthorizedAgentRoute {
  readonly agentId: string;
  readonly quota: AuthorizationQuota;
  readonly authorizationAuditVersion: number;
}

export interface AuthorizationRevocation {
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
  readonly agentId: string;
  readonly authorizationAuditVersion: number;
  readonly reason: "configuration-update" | "edge-user" | "edge-device" | "agent";
  /** 后续 stream 层必须依此关闭已归属该授权的活跃流。 */
  readonly closeExistingStreams: true;
}

export interface AuthorizationRegistryUpdateResult {
  readonly auditVersion: number;
  readonly changed: boolean;
  readonly revocations: readonly AuthorizationRevocation[];
}

export type AuthorizationRevocationListener = (result: AuthorizationRegistryUpdateResult) => void;

export interface AuthorizationRegistryOptions {
  /** 已注册 peer 是授权文件唯一可信的身份目录。 */
  readonly peerIdentities: readonly ServerPeerIdentityRegistration[];
  readonly document?: AuthorizationRegistryDocument;
  readonly onRevocation?: AuthorizationRevocationListener;
}

export class AuthorizationRegistryError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "AuthorizationRegistryError";
  }
}

interface KnownPeerIdentities {
  readonly edgeUserIdByDeviceId: ReadonlyMap<string, string>;
  readonly agentIds: ReadonlySet<string>;
}

interface RegistryState {
  readonly document: AuthorizationRegistryDocument;
  readonly registrationsByKey: ReadonlyMap<string, AuthorizationRegistration>;
  readonly activeRoutesByEdgeIdentity: ReadonlyMap<string, AuthorizedAgentRoute>;
}

type AuthorizationRevocationReason = AuthorizationRevocation["reason"];
type UnknownRecord = Record<string, unknown>;

function fail(code: string): never {
  throw new AuthorizationRegistryError(code);
}

function isRecord(value: unknown): value is UnknownRecord {
  return (
    value !== null &&
    typeof value === "object" &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

function hasOwn(record: UnknownRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function expectExactKeys(record: UnknownRecord, allowedKeys: readonly string[], code: string): void {
  const allowed = new Set(allowedKeys);

  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      fail(code);
    }
  }
}

function assertIdentifier(value: unknown, code: string): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    fail(code);
  }
}

function assertPositiveInteger(value: unknown, code: string, maximum = Number.MAX_SAFE_INTEGER): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) {
    fail(code);
  }
}

function assertTimestamp(value: unknown, code: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail(code);
  }
}

function authorizationKey(edgeUserId: string, edgeDeviceId: string, agentId: string): string {
  return `${edgeUserId}\u0000${edgeDeviceId}\u0000${agentId}`;
}

function edgeIdentityKey(edgeUserId: string, edgeDeviceId: string): string {
  return `${edgeUserId}\u0000${edgeDeviceId}`;
}

function freezeQuota(quota: AuthorizationQuota): AuthorizationQuota {
  return Object.freeze({
    maxConcurrentStreams: quota.maxConcurrentStreams,
    maxBufferedBytes: quota.maxBufferedBytes
  });
}

function freezeRegistration(registration: AuthorizationRegistration): AuthorizationRegistration {
  return Object.freeze({
    edgeUserId: registration.edgeUserId,
    edgeDeviceId: registration.edgeDeviceId,
    agentId: registration.agentId,
    status: registration.status,
    quota: freezeQuota(registration.quota),
    createdAtMs: registration.createdAtMs,
    ...(registration.revokedAtMs === undefined ? {} : { revokedAtMs: registration.revokedAtMs }),
    auditVersion: registration.auditVersion
  });
}

function freezeDocument(document: AuthorizationRegistryDocument): AuthorizationRegistryDocument {
  return Object.freeze({
    auditVersion: document.auditVersion,
    authorizations: Object.freeze(document.authorizations.map(freezeRegistration))
  });
}

function emptyDocument(): AuthorizationRegistryDocument {
  return Object.freeze({ auditVersion: 1, authorizations: Object.freeze([]) });
}

function parseQuota(value: unknown): AuthorizationQuota {
  if (!isRecord(value)) {
    fail("SERVER_AUTHORIZATION_QUOTA_INVALID");
  }

  expectExactKeys(value, ["maxConcurrentStreams", "maxBufferedBytes"], "SERVER_AUTHORIZATION_QUOTA_UNKNOWN_FIELD");
  assertPositiveInteger(
    value.maxConcurrentStreams,
    "SERVER_AUTHORIZATION_QUOTA_CONCURRENT_STREAMS_INVALID",
    DEFAULT_RESOURCE_LIMITS.maxConcurrentStreams
  );
  assertPositiveInteger(
    value.maxBufferedBytes,
    "SERVER_AUTHORIZATION_QUOTA_BUFFERED_BYTES_INVALID",
    DEFAULT_RESOURCE_LIMITS.maxAggregateBufferedBytes
  );

  return freezeQuota({
    maxConcurrentStreams: value.maxConcurrentStreams,
    maxBufferedBytes: value.maxBufferedBytes
  });
}

function parseAuthorizationRegistration(value: unknown, documentAuditVersion: number): AuthorizationRegistration {
  if (!isRecord(value)) {
    fail("SERVER_AUTHORIZATION_RECORD_INVALID");
  }

  expectExactKeys(
    value,
    ["edgeUserId", "edgeDeviceId", "agentId", "status", "quota", "createdAtMs", "revokedAtMs", "auditVersion"],
    "SERVER_AUTHORIZATION_RECORD_UNKNOWN_FIELD"
  );

  assertIdentifier(value.edgeUserId, "SERVER_AUTHORIZATION_EDGE_USER_INVALID");
  assertIdentifier(value.edgeDeviceId, "SERVER_AUTHORIZATION_EDGE_DEVICE_INVALID");
  assertIdentifier(value.agentId, "SERVER_AUTHORIZATION_AGENT_INVALID");
  assertTimestamp(value.createdAtMs, "SERVER_AUTHORIZATION_CREATED_AT_INVALID");
  assertPositiveInteger(value.auditVersion, "SERVER_AUTHORIZATION_AUDIT_VERSION_INVALID", documentAuditVersion);

  if (value.status !== AuthorizationStatus.ACTIVE && value.status !== AuthorizationStatus.REVOKED) {
    fail("SERVER_AUTHORIZATION_STATUS_INVALID");
  }

  const hasRevokedAt = hasOwn(value, "revokedAtMs");
  if (value.status === AuthorizationStatus.ACTIVE && hasRevokedAt) {
    fail("SERVER_AUTHORIZATION_ACTIVE_HAS_REVOCATION_TIME");
  }

  if (value.status === AuthorizationStatus.REVOKED && !hasRevokedAt) {
    fail("SERVER_AUTHORIZATION_REVOKED_AT_REQUIRED");
  }

  if (hasRevokedAt) {
    assertTimestamp(value.revokedAtMs, "SERVER_AUTHORIZATION_REVOKED_AT_INVALID");
    if (value.revokedAtMs < value.createdAtMs) {
      fail("SERVER_AUTHORIZATION_REVOKED_BEFORE_CREATED");
    }
  }

  return freezeRegistration({
    edgeUserId: value.edgeUserId,
    edgeDeviceId: value.edgeDeviceId,
    agentId: value.agentId,
    status: value.status,
    quota: parseQuota(value.quota),
    createdAtMs: value.createdAtMs,
    ...(hasRevokedAt ? { revokedAtMs: value.revokedAtMs as number } : {}),
    auditVersion: value.auditVersion
  });
}

function parseDocumentShape(value: unknown): AuthorizationRegistryDocument {
  if (!isRecord(value)) {
    fail("SERVER_AUTHORIZATION_DOCUMENT_INVALID");
  }

  expectExactKeys(value, ["auditVersion", "authorizations"], "SERVER_AUTHORIZATION_DOCUMENT_UNKNOWN_FIELD");
  assertPositiveInteger(value.auditVersion, "SERVER_AUTHORIZATION_DOCUMENT_AUDIT_VERSION_INVALID");
  const auditVersion = value.auditVersion;

  if (!Array.isArray(value.authorizations)) {
    fail("SERVER_AUTHORIZATION_DOCUMENT_AUTHORIZATIONS_INVALID");
  }

  return freezeDocument({
    auditVersion,
    authorizations: value.authorizations.map((registration) => parseAuthorizationRegistration(registration, auditVersion))
  });
}

function getKnownPeerIdentities(
  peerIdentities: readonly ServerPeerIdentityRegistration[]
): KnownPeerIdentities {
  const edgeUserIdByDeviceId = new Map<string, string>();
  const agentIds = new Set<string>();

  for (const registration of peerIdentities) {
    const identity = registration?.identity;
    if (identity === undefined || identity === null || typeof identity !== "object") {
      fail("SERVER_AUTHORIZATION_PEER_IDENTITY_INVALID");
    }

    if (identity.kind === "edge-device") {
      assertIdentifier(identity.edgeUserId, "SERVER_AUTHORIZATION_PEER_EDGE_USER_INVALID");
      assertIdentifier(identity.edgeDeviceId, "SERVER_AUTHORIZATION_PEER_EDGE_DEVICE_INVALID");
      const existingEdgeUserId = edgeUserIdByDeviceId.get(identity.edgeDeviceId);
      if (existingEdgeUserId !== undefined) {
        fail("SERVER_AUTHORIZATION_PEER_EDGE_DEVICE_DUPLICATE");
      }

      edgeUserIdByDeviceId.set(identity.edgeDeviceId, identity.edgeUserId);
      continue;
    }

    if (identity.kind === "egress-agent") {
      assertIdentifier(identity.agentId, "SERVER_AUTHORIZATION_PEER_AGENT_INVALID");
      if (agentIds.has(identity.agentId)) {
        fail("SERVER_AUTHORIZATION_PEER_AGENT_DUPLICATE");
      }

      agentIds.add(identity.agentId);
      continue;
    }

    fail("SERVER_AUTHORIZATION_PEER_IDENTITY_INVALID");
  }

  return Object.freeze({ edgeUserIdByDeviceId, agentIds });
}

function validateReferences(document: AuthorizationRegistryDocument, knownPeers: KnownPeerIdentities): void {
  const registrationKeys = new Set<string>();
  const agentIdByEdgeIdentity = new Map<string, string>();

  for (const registration of document.authorizations) {
    const registeredEdgeUserId = knownPeers.edgeUserIdByDeviceId.get(registration.edgeDeviceId);
    if (registeredEdgeUserId === undefined) {
      fail("SERVER_AUTHORIZATION_EDGE_DEVICE_UNKNOWN");
    }

    if (registeredEdgeUserId !== registration.edgeUserId) {
      fail("SERVER_AUTHORIZATION_EDGE_IDENTITY_MISMATCH");
    }

    if (!knownPeers.agentIds.has(registration.agentId)) {
      fail("SERVER_AUTHORIZATION_AGENT_UNKNOWN");
    }

    const key = authorizationKey(registration.edgeUserId, registration.edgeDeviceId, registration.agentId);
    if (registrationKeys.has(key)) {
      fail("SERVER_AUTHORIZATION_DUPLICATE");
    }
    registrationKeys.add(key);

    if (registration.status === AuthorizationStatus.ACTIVE) {
      const edgeKey = edgeIdentityKey(registration.edgeUserId, registration.edgeDeviceId);
      const existingAgentId = agentIdByEdgeIdentity.get(edgeKey);
      if (existingAgentId !== undefined && existingAgentId !== registration.agentId) {
        fail("SERVER_AUTHORIZATION_EDGE_AGENT_CONFLICT");
      }
      agentIdByEdgeIdentity.set(edgeKey, registration.agentId);
    }
  }
}

function createState(document: AuthorizationRegistryDocument, knownPeers: KnownPeerIdentities): RegistryState {
  validateReferences(document, knownPeers);
  const registrationsByKey = new Map<string, AuthorizationRegistration>();
  const activeRoutesByEdgeIdentity = new Map<string, AuthorizedAgentRoute>();

  for (const registration of document.authorizations) {
    registrationsByKey.set(
      authorizationKey(registration.edgeUserId, registration.edgeDeviceId, registration.agentId),
      registration
    );

    if (registration.status === AuthorizationStatus.ACTIVE) {
      activeRoutesByEdgeIdentity.set(
        edgeIdentityKey(registration.edgeUserId, registration.edgeDeviceId),
        Object.freeze({
          agentId: registration.agentId,
          quota: freezeQuota(registration.quota),
          authorizationAuditVersion: registration.auditVersion
        })
      );
    }
  }

  return Object.freeze({
    document,
    registrationsByKey,
    activeRoutesByEdgeIdentity
  });
}

function statesMatch(left: RegistryState, right: RegistryState): boolean {
  if (left.document.auditVersion !== right.document.auditVersion || left.registrationsByKey.size !== right.registrationsByKey.size) {
    return false;
  }

  for (const [key, registration] of left.registrationsByKey) {
    const other = right.registrationsByKey.get(key);
    if (
      other === undefined ||
      other.status !== registration.status ||
      other.createdAtMs !== registration.createdAtMs ||
      other.revokedAtMs !== registration.revokedAtMs ||
      other.auditVersion !== registration.auditVersion ||
      other.quota.maxConcurrentStreams !== registration.quota.maxConcurrentStreams ||
      other.quota.maxBufferedBytes !== registration.quota.maxBufferedBytes
    ) {
      return false;
    }
  }

  return true;
}

function detectRevocations(
  previous: RegistryState,
  next: RegistryState,
  reason: AuthorizationRevocationReason
): readonly AuthorizationRevocation[] {
  const revocations: AuthorizationRevocation[] = [];

  for (const [key, registration] of previous.registrationsByKey) {
    if (registration.status !== AuthorizationStatus.ACTIVE) {
      continue;
    }

    const replacement = next.registrationsByKey.get(key);
    if (replacement?.status === AuthorizationStatus.ACTIVE) {
      continue;
    }

    revocations.push(
      Object.freeze({
        edgeUserId: registration.edgeUserId,
        edgeDeviceId: registration.edgeDeviceId,
        agentId: registration.agentId,
        authorizationAuditVersion: replacement?.auditVersion ?? registration.auditVersion,
        reason,
        closeExistingStreams: true
      })
    );
  }

  return Object.freeze(revocations);
}

function freezeUpdateResult(
  auditVersion: number,
  changed: boolean,
  revocations: readonly AuthorizationRevocation[]
): AuthorizationRegistryUpdateResult {
  return Object.freeze({ auditVersion, changed, revocations: Object.freeze([...revocations]) });
}

/** 严格解析 JSON 授权文件；身份引用仍由 `AuthorizationRegistry` 构造时验证。 */
export function parseAuthorizationRegistryJson(serializedDocument: string): AuthorizationRegistryDocument {
  if (typeof serializedDocument !== "string" || serializedDocument.length === 0) {
    fail("SERVER_AUTHORIZATION_DOCUMENT_JSON_INVALID");
  }

  try {
    return parseDocumentShape(JSON.parse(serializedDocument) as unknown);
  } catch (error: unknown) {
    if (error instanceof AuthorizationRegistryError) {
      throw error;
    }

    return fail("SERVER_AUTHORIZATION_DOCUMENT_JSON_INVALID");
  }
}

/**
 * 仅从受信任的已认证 edge 会话身份解析 agent。调用方没有任何可传入的 agentId，
 * 因而无法通过请求参数选择未经授权的 agent。
 */
export class AuthorizationRegistry {
  private readonly knownPeers: KnownPeerIdentities;
  private readonly revocationListeners = new Set<AuthorizationRevocationListener>();
  private state: RegistryState;

  public constructor(options: AuthorizationRegistryOptions) {
    this.knownPeers = getKnownPeerIdentities(options.peerIdentities);
    this.state = createState(
      parseDocumentShape(options.document ?? emptyDocument()),
      this.knownPeers
    );

    if (options.onRevocation !== undefined) {
      this.revocationListeners.add(options.onRevocation);
    }
  }

  public getSnapshot(): AuthorizationRegistryDocument {
    return freezeDocument(this.state.document);
  }

  public resolveAgentForEdge(identity: {
    readonly kind: "edge-device" | "egress-agent";
    readonly edgeUserId?: string;
    readonly edgeDeviceId?: string;
  }): AuthorizedAgentRoute | undefined {
    if (
      identity.kind !== "edge-device" ||
      typeof identity.edgeUserId !== "string" ||
      typeof identity.edgeDeviceId !== "string" ||
      !IDENTIFIER_PATTERN.test(identity.edgeUserId) ||
      !IDENTIFIER_PATTERN.test(identity.edgeDeviceId)
    ) {
      return undefined;
    }

    const route = this.state.activeRoutesByEdgeIdentity.get(edgeIdentityKey(identity.edgeUserId, identity.edgeDeviceId));
    return route === undefined
      ? undefined
      : Object.freeze({
          agentId: route.agentId,
          quota: freezeQuota(route.quota),
          authorizationAuditVersion: route.authorizationAuditVersion
        });
  }

  /** 注册后续 stream 层的关闭回调；取消订阅函数可安全重复调用。 */
  public subscribeRevocations(listener: AuthorizationRevocationListener): () => void {
    this.revocationListeners.add(listener);
    return (): void => {
      this.revocationListeners.delete(listener);
    };
  }

  /** 候选配置全部验证成功后才替换当前索引；失败时旧授权完全保留。 */
  public replaceDocument(document: AuthorizationRegistryDocument): AuthorizationRegistryUpdateResult {
    const next = createState(parseDocumentShape(document), this.knownPeers);
    if (next.document.auditVersion < this.state.document.auditVersion) {
      fail("SERVER_AUTHORIZATION_DOCUMENT_VERSION_STALE");
    }

    if (next.document.auditVersion === this.state.document.auditVersion) {
      if (!statesMatch(this.state, next)) {
        fail("SERVER_AUTHORIZATION_DOCUMENT_VERSION_CONFLICT");
      }

      return freezeUpdateResult(this.state.document.auditVersion, false, []);
    }

    const revocations = detectRevocations(this.state, next, "configuration-update");
    this.state = next;
    const result = freezeUpdateResult(next.document.auditVersion, true, revocations);
    this.notifyRevocations(result);
    return result;
  }

  public replaceJson(serializedDocument: string): AuthorizationRegistryUpdateResult {
    return this.replaceDocument(parseAuthorizationRegistryJson(serializedDocument));
  }

  public revokeByEdgeUser(edgeUserId: string, revokedAtMs = Date.now()): AuthorizationRegistryUpdateResult {
    assertIdentifier(edgeUserId, "SERVER_AUTHORIZATION_EDGE_USER_INVALID");
    return this.revokeMatching((registration) => registration.edgeUserId === edgeUserId, "edge-user", revokedAtMs);
  }

  public revokeByEdgeDevice(edgeDeviceId: string, revokedAtMs = Date.now()): AuthorizationRegistryUpdateResult {
    assertIdentifier(edgeDeviceId, "SERVER_AUTHORIZATION_EDGE_DEVICE_INVALID");
    return this.revokeMatching((registration) => registration.edgeDeviceId === edgeDeviceId, "edge-device", revokedAtMs);
  }

  public revokeByAgent(agentId: string, revokedAtMs = Date.now()): AuthorizationRegistryUpdateResult {
    assertIdentifier(agentId, "SERVER_AUTHORIZATION_AGENT_INVALID");
    return this.revokeMatching((registration) => registration.agentId === agentId, "agent", revokedAtMs);
  }

  private revokeMatching(
    matches: (registration: AuthorizationRegistration) => boolean,
    reason: AuthorizationRevocationReason,
    revokedAtMs: number
  ): AuthorizationRegistryUpdateResult {
    assertTimestamp(revokedAtMs, "SERVER_AUTHORIZATION_REVOKED_AT_INVALID");
    const affected = this.state.document.authorizations.filter(
      (registration) => registration.status === AuthorizationStatus.ACTIVE && matches(registration)
    );

    if (affected.length === 0) {
      return freezeUpdateResult(this.state.document.auditVersion, false, []);
    }

    if (this.state.document.auditVersion >= Number.MAX_SAFE_INTEGER) {
      fail("SERVER_AUTHORIZATION_DOCUMENT_AUDIT_VERSION_EXHAUSTED");
    }

    const nextAuditVersion = this.state.document.auditVersion + 1;
    const nextDocument = freezeDocument({
      auditVersion: nextAuditVersion,
      authorizations: this.state.document.authorizations.map((registration) => {
        if (!affected.includes(registration)) {
          return registration;
        }

        return {
          ...registration,
          status: AuthorizationStatus.REVOKED,
          revokedAtMs,
          auditVersion: nextAuditVersion
        };
      })
    });
    const next = createState(nextDocument, this.knownPeers);
    const revocations = detectRevocations(this.state, next, reason);
    this.state = next;
    const result = freezeUpdateResult(nextAuditVersion, true, revocations);
    this.notifyRevocations(result);
    return result;
  }

  private notifyRevocations(result: AuthorizationRegistryUpdateResult): void {
    if (result.revocations.length === 0) {
      return;
    }

    for (const listener of this.revocationListeners) {
      try {
        listener(result);
      } catch {
        // 回调属于后续 stream 清理层；它失败不能让已提交的授权撤销回滚。
      }
    }
  }
}
