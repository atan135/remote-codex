import { randomUUID } from "node:crypto";

import {
  connectionFrame,
  decodeFrame,
  decodeFramePayload,
  encodeChallengePayload,
  encodeFrame,
  encodeHeartbeatPayload,
  FrameType,
  MAX_AUTHENTICATION_WINDOW_MS,
  NonceReplayProtector,
  PROTOCOL_VERSION,
  TunnelErrorCode,
  verifyAuthenticationChallenge,
  issueAuthenticationChallenge,
  type IssuedAuthenticationChallenge,
  type PeerAuthenticationIdentity,
  type PeerRole,
  type RegisterPayload
} from "@remote-codex/shared";
import { WebSocket, type RawData } from "ws";

export interface ServerPeerIdentityRegistration {
  readonly identity: PeerAuthenticationIdentity;
  readonly expiresAtMs?: number;
}

export interface PeerAuthenticationMetadata {
  readonly kind: "edge-device" | "egress-agent";
  readonly authenticationKeyId: string;
  readonly edgeUserId?: string;
  readonly edgeDeviceId?: string;
  readonly agentId?: string;
}

export interface AuthenticatedPeerSession {
  readonly peerId: string;
  readonly role: PeerRole;
  readonly identity: PeerAuthenticationMetadata;
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly establishedAtMs: number;
  readonly lastHeartbeatAtMs: number;
  readonly lastHeartbeatSequence: number | undefined;
}

export interface PeerSessionManagerOptions {
  readonly peerIdentities?: readonly ServerPeerIdentityRegistration[];
  readonly heartbeatTimeoutMs: number;
  readonly authenticationTimeoutMs?: number;
  readonly now?: () => number;
}

export class PeerSessionError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "PeerSessionError";
  }
}

interface PendingPeerRegistration {
  readonly connectedAtMs: number;
  readonly registration?: RegisterPayload;
  readonly identityRegistration?: ServerPeerIdentityRegistration;
  readonly challenge?: IssuedAuthenticationChallenge;
}

interface SessionRecord {
  readonly peerId: string;
  readonly role: PeerRole;
  readonly identity: PeerAuthenticationMetadata;
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly establishedAtMs: number;
  lastHeartbeatAtMs: number;
  lastHeartbeatSequence: number | undefined;
  readonly identityExpiresAtMs: number | undefined;
  readonly socket: WebSocket;
}

const CLOSE_CODE_PROTOCOL = 1002;
const CLOSE_CODE_POLICY = 1008;

function fail(code: string): never {
  throw new PeerSessionError(code);
}

function identityRole(identity: PeerAuthenticationIdentity): PeerRole {
  return identity.kind === "edge-device" ? "edge-client" : "egress-agent";
}

function identityRegistrationPeerId(identity: PeerAuthenticationIdentity): string {
  return identity.kind === "edge-device" ? identity.edgeDeviceId : identity.agentId;
}

function identityMetadata(identity: PeerAuthenticationIdentity): PeerAuthenticationMetadata {
  if (identity.kind === "edge-device") {
    return Object.freeze({
      kind: "edge-device",
      authenticationKeyId: identity.authenticationKey.keyId,
      edgeUserId: identity.edgeUserId,
      edgeDeviceId: identity.edgeDeviceId
    });
  }

  return Object.freeze({
    kind: "egress-agent",
    authenticationKeyId: identity.authenticationKey.keyId,
    agentId: identity.agentId
  });
}

function registrationKey(role: PeerRole, peerId: string): string {
  return `${role}:${peerId}`;
}

function assertTimestamp(value: number, code: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(code);
  }
}

function snapshot(record: SessionRecord): AuthenticatedPeerSession {
  return Object.freeze({
    peerId: record.peerId,
    role: record.role,
    identity: record.identity,
    protocolVersion: record.protocolVersion,
    establishedAtMs: record.establishedAtMs,
    lastHeartbeatAtMs: record.lastHeartbeatAtMs,
    lastHeartbeatSequence: record.lastHeartbeatSequence
  });
}

function rawDataToBytes(data: RawData): Uint8Array | undefined {
  if (data instanceof Buffer) {
    return Uint8Array.from(data);
  }

  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data.slice(0));
  }

  if (Array.isArray(data)) {
    return Uint8Array.from(Buffer.concat(data));
  }

  return undefined;
}

function isExpired(registration: ServerPeerIdentityRegistration, nowMs: number): boolean {
  return registration.expiresAtMs !== undefined && registration.expiresAtMs <= nowMs;
}

/**
 * 服务端维护的认证会话。它不持有私钥、不转发 stream 帧，也不会记录 WebSocket
 * payload；对外仅暴露已经认证的不可预测 peer ID 与必要元数据。
 */
export class PeerSessionManager {
  private readonly identitiesByRegistrationKey = new Map<string, ServerPeerIdentityRegistration>();
  private readonly pendingBySocket = new Map<WebSocket, PendingPeerRegistration>();
  private readonly sessionsBySocket = new Map<WebSocket, SessionRecord>();
  private readonly sessionsByPeerId = new Map<string, SessionRecord>();
  private readonly agentSessionsByAgentId = new Map<string, SessionRecord>();
  private readonly challengeReplayProtector = new NonceReplayProtector();
  private readonly registrationNonceReplayProtector = new NonceReplayProtector();
  private readonly now: () => number;
  private readonly authenticationTimeoutMs: number;
  private readonly heartbeatTimeoutMs: number;
  private readonly expirationTimer: NodeJS.Timeout;

  public constructor(options: PeerSessionManagerOptions) {
    if (!Number.isSafeInteger(options.heartbeatTimeoutMs) || options.heartbeatTimeoutMs < 1) {
      fail("SERVER_PEER_HEARTBEAT_TIMEOUT_INVALID");
    }

    const authenticationTimeoutMs = options.authenticationTimeoutMs ?? MAX_AUTHENTICATION_WINDOW_MS;
    if (
      !Number.isSafeInteger(authenticationTimeoutMs) ||
      authenticationTimeoutMs < 1 ||
      authenticationTimeoutMs > MAX_AUTHENTICATION_WINDOW_MS
    ) {
      fail("SERVER_PEER_AUTHENTICATION_TIMEOUT_INVALID");
    }

    this.now = options.now ?? Date.now;
    this.authenticationTimeoutMs = authenticationTimeoutMs;
    this.heartbeatTimeoutMs = options.heartbeatTimeoutMs;

    for (const registration of options.peerIdentities ?? []) {
      const role = identityRole(registration.identity);
      const peerId = identityRegistrationPeerId(registration.identity);
      const key = registrationKey(role, peerId);

      if (this.identitiesByRegistrationKey.has(key)) {
        fail("SERVER_PEER_IDENTITY_DUPLICATE");
      }

      if (registration.expiresAtMs !== undefined) {
        assertTimestamp(registration.expiresAtMs, "SERVER_PEER_IDENTITY_EXPIRY_INVALID");
      }

      this.identitiesByRegistrationKey.set(key, Object.freeze({ ...registration }));
    }

    const expirationIntervalMs = Math.max(10, Math.min(options.heartbeatTimeoutMs, authenticationTimeoutMs) / 2);
    this.expirationTimer = setInterval(() => this.expireInactivePeers(), expirationIntervalMs);
    this.expirationTimer.unref();
  }

  public attach(socket: WebSocket): void {
    if (this.pendingBySocket.has(socket) || this.sessionsBySocket.has(socket)) {
      this.revokeSocket(socket, CLOSE_CODE_POLICY, "SESSION_ALREADY_ATTACHED");
      return;
    }

    this.pendingBySocket.set(socket, { connectedAtMs: this.now() });
    socket.on("message", (data: RawData, isBinary: boolean) => this.handleMessage(socket, data, isBinary));
    socket.once("close", () => this.removeSocket(socket));
  }

  public getActiveSessions(): readonly AuthenticatedPeerSession[] {
    return Object.freeze([...this.sessionsByPeerId.values()].map(snapshot));
  }

  public getSession(peerId: string): AuthenticatedPeerSession | undefined {
    const session = this.sessionsByPeerId.get(peerId);
    return session === undefined ? undefined : snapshot(session);
  }

  public getPendingConnectionCount(): number {
    return this.pendingBySocket.size;
  }

  public expireInactivePeers(): void {
    const nowMs = this.now();

    for (const [socket, pending] of this.pendingBySocket) {
      const expiresAtMs = Math.min(
        pending.challenge?.payload.expiresAtMs ?? pending.connectedAtMs + this.authenticationTimeoutMs,
        pending.identityRegistration?.expiresAtMs ?? Number.MAX_SAFE_INTEGER
      );
      if (expiresAtMs <= nowMs) {
        this.reject(socket, TunnelErrorCode.AUTH_EXPIRED);
      }
    }

    for (const session of this.sessionsByPeerId.values()) {
      if (session.identityExpiresAtMs !== undefined && session.identityExpiresAtMs <= nowMs) {
        this.revokeSession(session, CLOSE_CODE_POLICY, TunnelErrorCode.AUTH_EXPIRED);
        continue;
      }

      if (session.lastHeartbeatAtMs + this.heartbeatTimeoutMs <= nowMs) {
        this.revokeSession(session, CLOSE_CODE_POLICY, "HEARTBEAT_TIMEOUT");
      }
    }
  }

  public close(): void {
    clearInterval(this.expirationTimer);

    for (const socket of [...this.pendingBySocket.keys()]) {
      this.revokeSocket(socket, CLOSE_CODE_POLICY, "SERVER_SHUTDOWN");
    }

    for (const session of [...this.sessionsByPeerId.values()]) {
      this.revokeSession(session, CLOSE_CODE_POLICY, "SERVER_SHUTDOWN");
    }
  }

  private handleMessage(socket: WebSocket, data: RawData, isBinary: boolean): void {
    if (!isBinary) {
      this.revokeSocket(socket, CLOSE_CODE_PROTOCOL, "BINARY_FRAME_REQUIRED");
      return;
    }

    const bytes = rawDataToBytes(data);
    if (bytes === undefined) {
      this.revokeSocket(socket, CLOSE_CODE_PROTOCOL, "BINARY_FRAME_REQUIRED");
      return;
    }

    let frame;
    try {
      frame = decodeFrame(bytes);
    } catch {
      this.revokeSocket(socket, CLOSE_CODE_PROTOCOL, "PROTOCOL_VIOLATION");
      return;
    }

    const pending = this.pendingBySocket.get(socket);
    if (pending !== undefined) {
      this.handlePendingFrame(socket, pending, frame.type, frame);
      return;
    }

    const session = this.sessionsBySocket.get(socket);
    if (session === undefined || frame.type !== FrameType.HEARTBEAT) {
      this.revokeSocket(socket, CLOSE_CODE_PROTOCOL, "PROTOCOL_VIOLATION");
      return;
    }

    try {
      const payload = decodeFramePayload(frame);
      if (payload === undefined || !("sequence" in payload)) {
        throw new Error("invalid heartbeat");
      }

      session.lastHeartbeatAtMs = this.now();
      session.lastHeartbeatSequence = payload.sequence;
    } catch {
      this.revokeSession(session, CLOSE_CODE_PROTOCOL, "PROTOCOL_VIOLATION");
    }
  }

  private handlePendingFrame(
    socket: WebSocket,
    pending: PendingPeerRegistration,
    frameType: number,
    frame: ReturnType<typeof decodeFrame>
  ): void {
    if (pending.registration === undefined) {
      if (frameType !== FrameType.REGISTER) {
        this.reject(socket, TunnelErrorCode.AUTH_FAILED);
        return;
      }

      this.handleRegistration(socket, pending, frame);
      return;
    }

    if (frameType !== FrameType.AUTHENTICATE || pending.identityRegistration === undefined || pending.challenge === undefined) {
      this.reject(socket, TunnelErrorCode.AUTH_FAILED);
      return;
    }

    try {
      if (isExpired(pending.identityRegistration, this.now())) {
        this.reject(socket, TunnelErrorCode.AUTH_EXPIRED);
        return;
      }

      const response = decodeFramePayload(frame);
      if (response === undefined || !("challengeNonce" in response)) {
        throw new Error("invalid authentication response");
      }

      const verification = verifyAuthenticationChallenge({
        identity: pending.identityRegistration.identity,
        registration: pending.registration,
        challenge: pending.challenge,
        response,
        replayProtector: this.challengeReplayProtector,
        nowMs: this.now()
      });

      if (!verification.ok) {
        this.reject(socket, verification.errorCode);
        return;
      }

      if (
        !this.registrationNonceReplayProtector.consume(
          pending.registration.nonce,
          pending.challenge.payload.expiresAtMs,
          this.now()
        )
      ) {
        this.reject(socket, TunnelErrorCode.AUTH_REPLAYED);
        return;
      }

      this.establishSession(socket, pending.registration.role, pending.identityRegistration);
    } catch {
      this.reject(socket, TunnelErrorCode.AUTH_FAILED);
    }
  }

  private handleRegistration(socket: WebSocket, pending: PendingPeerRegistration, frame: ReturnType<typeof decodeFrame>): void {
    try {
      const registration = decodeFramePayload(frame);
      if (registration === undefined || !("role" in registration) || !("peerId" in registration)) {
        throw new Error("invalid registration");
      }

      const registeredIdentity = this.identitiesByRegistrationKey.get(registrationKey(registration.role, registration.peerId));
      if (registeredIdentity === undefined) {
        this.reject(socket, TunnelErrorCode.AUTH_UNAUTHORIZED);
        return;
      }

      if (isExpired(registeredIdentity, this.now())) {
        this.reject(socket, TunnelErrorCode.AUTH_EXPIRED);
        return;
      }

      if (
        identityRole(registeredIdentity.identity) !== registration.role ||
        identityRegistrationPeerId(registeredIdentity.identity) !== registration.peerId
      ) {
        this.reject(socket, TunnelErrorCode.AUTH_UNAUTHORIZED);
        return;
      }

      const challenge = issueAuthenticationChallenge({ nowMs: this.now(), ttlMs: this.authenticationTimeoutMs });
      this.pendingBySocket.set(socket, {
        ...pending,
        registration,
        identityRegistration: registeredIdentity,
        challenge
      });
      this.send(socket, connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(challenge.payload)));
    } catch {
      this.reject(socket, TunnelErrorCode.AUTH_FAILED);
    }
  }

  private establishSession(
    socket: WebSocket,
    role: PeerRole,
    identityRegistration: ServerPeerIdentityRegistration
  ): void {
    const nowMs = this.now();
    const identity = identityRegistration.identity;
    const session: SessionRecord = {
      peerId: randomUUID(),
      role,
      identity: identityMetadata(identity),
      protocolVersion: PROTOCOL_VERSION,
      establishedAtMs: nowMs,
      lastHeartbeatAtMs: nowMs,
      lastHeartbeatSequence: undefined,
      identityExpiresAtMs: identityRegistration.expiresAtMs,
      socket
    };

    this.pendingBySocket.delete(socket);
    this.sessionsBySocket.set(socket, session);
    this.sessionsByPeerId.set(session.peerId, session);

    if (identity.kind === "egress-agent") {
      const existingSession = this.agentSessionsByAgentId.get(identity.agentId);
      this.agentSessionsByAgentId.set(identity.agentId, session);
      if (existingSession !== undefined && existingSession !== session) {
        this.revokeSession(existingSession, CLOSE_CODE_POLICY, "AGENT_SESSION_REPLACED");
      }
    }

    this.send(socket, connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 0 })));
  }

  private reject(socket: WebSocket, errorCode: TunnelErrorCode): void {
    this.pendingBySocket.delete(socket);
    this.revokeSocket(socket, CLOSE_CODE_POLICY, errorCode);
  }

  private revokeSession(session: SessionRecord, closeCode: number, reason: string): void {
    this.sessionsBySocket.delete(session.socket);
    this.sessionsByPeerId.delete(session.peerId);
    const agentId = session.identity.agentId;
    if (session.identity.kind === "egress-agent" && agentId !== undefined && this.agentSessionsByAgentId.get(agentId) === session) {
      this.agentSessionsByAgentId.delete(agentId);
    }
    this.revokeSocket(session.socket, closeCode, reason);
  }

  private revokeSocket(socket: WebSocket, closeCode: number, reason: string): void {
    this.pendingBySocket.delete(socket);
    const session = this.sessionsBySocket.get(socket);
    if (session !== undefined) {
      this.sessionsBySocket.delete(socket);
      this.sessionsByPeerId.delete(session.peerId);
      const agentId = session.identity.agentId;
      if (session.identity.kind === "egress-agent" && agentId !== undefined && this.agentSessionsByAgentId.get(agentId) === session) {
        this.agentSessionsByAgentId.delete(agentId);
      }
    }

    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
      socket.close(closeCode, reason);
    }
  }

  private removeSocket(socket: WebSocket): void {
    this.pendingBySocket.delete(socket);
    const session = this.sessionsBySocket.get(socket);
    if (session !== undefined) {
      this.sessionsBySocket.delete(socket);
      this.sessionsByPeerId.delete(session.peerId);
      const agentId = session.identity.agentId;
      if (session.identity.kind === "egress-agent" && agentId !== undefined && this.agentSessionsByAgentId.get(agentId) === session) {
        this.agentSessionsByAgentId.delete(agentId);
      }
    }
  }

  private send(socket: WebSocket, frame: ReturnType<typeof connectionFrame>): void {
    if (socket.readyState !== WebSocket.OPEN) {
      this.revokeSocket(socket, CLOSE_CODE_POLICY, "PEER_DISCONNECTED");
      return;
    }

    try {
      socket.send(Buffer.from(encodeFrame(frame)), { binary: true });
    } catch {
      this.revokeSocket(socket, CLOSE_CODE_POLICY, "PEER_DISCONNECTED");
    }
  }
}
