import { generateKeyPairSync } from "node:crypto";

import {
  createEdgeDeviceIdentity,
  createEgressAgentIdentity,
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  decodeFramePayload,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
  encodeStreamErrorPayload,
  encodeStreamOpenPayload,
  FrameType,
  IdentityKeyRole,
  StreamCloseCode,
  streamFrame,
  TunnelErrorCode,
  verifyCapability,
  CapabilityReplayProtector,
  DEFAULT_ALLOWED_DESTINATION,
  DEFAULT_RESOURCE_LIMITS,
  type EdgeDeviceIdentity,
  type EgressAgentIdentity,
  type ServerSigningCredentials,
  type StreamOpenPayload,
  type TunnelFrame
} from "@remote-codex/shared";
import { describe, expect, it } from "vitest";

import {
  AuthorizationRegistry,
  AuthorizationStatus,
  StreamOpenCoordinator,
  type AuthenticatedPeerSession,
  type AuthorizationRegistryDocument,
  type PeerSessionRemovalListener,
  type PeerSessionStreamFrameListener,
  type ServerPeerIdentityRegistration,
  type StreamPeerSessionGateway
} from "./index.js";

interface StreamFixture {
  readonly alice: EdgeDeviceIdentity;
  readonly bob: EdgeDeviceIdentity;
  readonly sharedAgent: EgressAgentIdentity;
  readonly otherAgent: EgressAgentIdentity;
  readonly signingCredentials: ServerSigningCredentials;
  readonly peerIdentities: readonly ServerPeerIdentityRegistration[];
}

interface SentFrame {
  readonly peerId: string;
  readonly frame: TunnelFrame;
}

class FakePeerSessions implements StreamPeerSessionGateway {
  private readonly sessions = new Map<string, AuthenticatedPeerSession>();
  private readonly streamListeners = new Set<PeerSessionStreamFrameListener>();
  private readonly removalListeners = new Set<PeerSessionRemovalListener>();
  private readonly sendAvailabilityListeners = new Set<(peerId: string) => void>();
  private readonly bufferedBytesByPeer = new Map<string, number>();
  private readonly failNextSendByPeer = new Set<string>();
  public readonly sent: SentFrame[] = [];

  public connect(session: AuthenticatedPeerSession): void {
    this.sessions.set(session.peerId, session);
  }

  public getAgentSession(agentId: string): AuthenticatedPeerSession | undefined {
    for (const session of this.sessions.values()) {
      if (session.role === "egress-agent" && session.identity.agentId === agentId) {
        return session;
      }
    }
    return undefined;
  }

  public getActiveSessions(): readonly AuthenticatedPeerSession[] {
    return Object.freeze([...this.sessions.values()]);
  }

  public sendFrame(peerId: string, frame: TunnelFrame): boolean {
    if (!this.sessions.has(peerId)) {
      return false;
    }
    if (this.failNextSendByPeer.delete(peerId)) {
      return false;
    }
    this.sent.push(
      Object.freeze({
        peerId,
        frame: Object.freeze({
          type: frame.type,
          flags: frame.flags,
          streamId: Uint8Array.from(frame.streamId),
          payload: Uint8Array.from(frame.payload)
        })
      })
    );
    return true;
  }

  public subscribeStreamFrames(listener: PeerSessionStreamFrameListener): () => void {
    this.streamListeners.add(listener);
    return (): void => {
      this.streamListeners.delete(listener);
    };
  }

  public subscribeSessionRemovals(listener: PeerSessionRemovalListener): () => void {
    this.removalListeners.add(listener);
    return (): void => {
      this.removalListeners.delete(listener);
    };
  }

  public subscribeSendAvailability(listener: (peerId: string) => void): () => void {
    this.sendAvailabilityListeners.add(listener);
    return (): void => {
      this.sendAvailabilityListeners.delete(listener);
    };
  }

  public getSendBufferedBytes(peerId: string): number | undefined {
    return this.sessions.has(peerId) ? (this.bufferedBytesByPeer.get(peerId) ?? 0) : undefined;
  }

  public setSendBufferedBytes(peerId: string, bytes: number): void {
    this.bufferedBytesByPeer.set(peerId, bytes);
  }

  public notifySendAvailable(peerId: string): void {
    for (const listener of this.sendAvailabilityListeners) {
      listener(peerId);
    }
  }

  public failNextSend(peerId: string): void {
    this.failNextSendByPeer.add(peerId);
  }

  public emit(peerId: string, frame: TunnelFrame): void {
    const session = this.sessions.get(peerId);
    if (session === undefined) {
      throw new Error("peer is offline");
    }
    for (const listener of this.streamListeners) {
      listener(session, frame);
    }
  }

  public disconnect(peerId: string): void {
    const session = this.sessions.get(peerId);
    if (session === undefined) {
      return;
    }
    this.sessions.delete(peerId);
    for (const listener of this.removalListeners) {
      listener(session);
    }
  }

  public framesFor(peerId: string, type?: FrameType): readonly TunnelFrame[] {
    return this.sent
      .filter((sent) => sent.peerId === peerId && (type === undefined || sent.frame.type === type))
      .map((sent) => sent.frame);
  }
}

function createEdgeIdentity(edgeUserId: string, edgeDeviceId: string): EdgeDeviceIdentity {
  const keys = generateKeyPairSync("ed25519");
  return createEdgeDeviceIdentity({
    edgeUserId,
    edgeDeviceId,
    authenticationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: `${edgeDeviceId}-auth` },
      keys.publicKey
    )
  });
}

function createAgentIdentity(agentId: string): EgressAgentIdentity {
  const keys = generateKeyPairSync("ed25519");
  return createEgressAgentIdentity({
    agentId,
    authenticationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: `${agentId}-auth` },
      keys.publicKey
    )
  });
}

function createFixture(): StreamFixture {
  const signingKeys = generateKeyPairSync("ed25519");
  const signingKey = createIdentityPrivateKey(
    { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: "server-capability-key" },
    signingKeys.privateKey
  );
  const signingIdentity = createServerSigningIdentity({
    serverId: "server-test",
    capabilityVerificationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: "server-capability-key" },
      signingKeys.publicKey
    )
  });
  const alice = createEdgeIdentity("edge-user-alice", "edge-device-alice");
  const bob = createEdgeIdentity("edge-user-bob", "edge-device-bob");
  const sharedAgent = createAgentIdentity("company-agent-shared");
  const otherAgent = createAgentIdentity("company-agent-other");

  return {
    alice,
    bob,
    sharedAgent,
    otherAgent,
    signingCredentials: createServerSigningCredentials({ identity: signingIdentity, capabilitySigningKey: signingKey }),
    peerIdentities: Object.freeze([
      { identity: alice },
      { identity: bob },
      { identity: sharedAgent },
      { identity: otherAgent }
    ])
  };
}

function registration(
  edge: EdgeDeviceIdentity,
  agent: EgressAgentIdentity,
  maxConcurrentStreams = 2
): AuthorizationRegistryDocument["authorizations"][number] {
  return {
    edgeUserId: edge.edgeUserId,
    edgeDeviceId: edge.edgeDeviceId,
    agentId: agent.agentId,
    status: AuthorizationStatus.ACTIVE,
    quota: { maxConcurrentStreams, maxBufferedBytes: 16 * 1024 },
    createdAtMs: 1,
    auditVersion: 1
  };
}

function createRegistry(fixture: StreamFixture, maxConcurrentStreams = 2): AuthorizationRegistry {
  return new AuthorizationRegistry({
    peerIdentities: fixture.peerIdentities,
    document: {
      auditVersion: 1,
      authorizations: [
        registration(fixture.alice, fixture.sharedAgent, maxConcurrentStreams),
        registration(fixture.bob, fixture.sharedAgent, maxConcurrentStreams)
      ]
    }
  });
}

function edgeSession(peerId: string, identity: EdgeDeviceIdentity): AuthenticatedPeerSession {
  return Object.freeze({
    peerId,
    role: "edge-client",
    identity: Object.freeze({
      kind: "edge-device",
      authenticationKeyId: identity.authenticationKey.keyId,
      edgeUserId: identity.edgeUserId,
      edgeDeviceId: identity.edgeDeviceId
    }),
    protocolVersion: 2,
    establishedAtMs: 1,
    lastHeartbeatAtMs: 1,
    lastHeartbeatSequence: undefined
  });
}

function agentSession(peerId: string, identity: EgressAgentIdentity): AuthenticatedPeerSession {
  return Object.freeze({
    peerId,
    role: "egress-agent",
    identity: Object.freeze({
      kind: "egress-agent",
      authenticationKeyId: identity.authenticationKey.keyId,
      agentId: identity.agentId
    }),
    protocolVersion: 2,
    establishedAtMs: 1,
    lastHeartbeatAtMs: 1,
    lastHeartbeatSequence: undefined
  });
}

function streamId(seed: number): Uint8Array {
  return Uint8Array.from({ length: 16 }, (_, index) => (seed + index) % 256);
}

function edgeOpen(id: Uint8Array, hostname = DEFAULT_ALLOWED_DESTINATION.hostname): TunnelFrame {
  return streamFrame(
    FrameType.STREAM_OPEN,
    id,
    encodeStreamOpenPayload({ hostname, port: 443, capability: Uint8Array.of(1) })
  );
}

function rawEdgeOpen(id: Uint8Array, hostname: string, port: number): TunnelFrame {
  const hostnameBytes = new TextEncoder().encode(hostname);
  const capability = Uint8Array.of(1);
  const payload = new Uint8Array(5 + hostnameBytes.byteLength + capability.byteLength);
  payload[0] = hostnameBytes.byteLength;
  payload.set(hostnameBytes, 1);
  const view = new DataView(payload.buffer);
  view.setUint16(1 + hostnameBytes.byteLength, port);
  view.setUint16(3 + hostnameBytes.byteLength, capability.byteLength);
  payload.set(capability, 5 + hostnameBytes.byteLength);
  return {
    type: FrameType.STREAM_OPEN,
    flags: 0,
    streamId: Uint8Array.from(id),
    payload
  };
}

function credit(id: Uint8Array, bytes: number): TunnelFrame {
  return streamFrame(FrameType.STREAM_CREDIT, id, encodeStreamCreditPayload({ bytes }));
}

function errorCode(frame: TunnelFrame): TunnelErrorCode {
  const payload = decodeFramePayload(frame);
  if (payload === undefined || payload instanceof Uint8Array || !("code" in payload)) {
    throw new Error("expected stream error payload");
  }
  return payload.code as TunnelErrorCode;
}

function openPayload(frame: TunnelFrame): StreamOpenPayload {
  const payload = decodeFramePayload(frame);
  if (payload === undefined || payload instanceof Uint8Array || !("capability" in payload)) {
    throw new Error("expected stream.open payload");
  }
  return payload as StreamOpenPayload;
}

describe("server stream.open 授权与 capability 签发", () => {
  it("让两个授权 edge 用户并行使用同一 agent，并把 capability 精确绑定到各自身份", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      now: () => 1_000
    });
    const aliceStreamId = streamId(1);
    const bobStreamId = streamId(33);

    peers.emit(alicePeer.peerId, edgeOpen(aliceStreamId));
    peers.emit(bobPeer.peerId, edgeOpen(bobStreamId));

    const forwarded = peers.framesFor(agentPeer.peerId, FrameType.STREAM_OPEN);
    expect(forwarded).toHaveLength(2);
    const firstPayload = openPayload(forwarded[0]!);
    const secondPayload = openPayload(forwarded[1]!);

    const ownership = coordinator.getActiveStreams();
    expect(ownership).toHaveLength(2);
    expect(new Set(ownership.map((item) => Buffer.from(item.streamId).toString("hex"))).size).toBe(2);
    const firstOwnership = ownership.find((item) => item.edgeUserId === fixture.alice.edgeUserId)!;
    const secondOwnership = ownership.find((item) => item.edgeUserId === fixture.bob.edgeUserId)!;
    expect(
      verifyCapability({
        capability: firstPayload.capability,
        serverIdentity: fixture.signingCredentials.identity,
        expectedBinding: {
          edgeUserId: fixture.alice.edgeUserId,
          edgeDeviceId: fixture.alice.edgeDeviceId,
          agentId: fixture.sharedAgent.agentId,
          streamId: firstOwnership.streamId,
          destination: DEFAULT_ALLOWED_DESTINATION
        },
        allowedDestination: DEFAULT_ALLOWED_DESTINATION,
        replayProtector: new CapabilityReplayProtector(),
        nowMs: 1_000
      }).ok
    ).toBe(true);
    expect(
      verifyCapability({
        capability: firstPayload.capability,
        serverIdentity: fixture.signingCredentials.identity,
        expectedBinding: {
          edgeUserId: fixture.alice.edgeUserId,
          edgeDeviceId: fixture.alice.edgeDeviceId,
          agentId: fixture.otherAgent.agentId,
          streamId: firstOwnership.streamId,
          destination: DEFAULT_ALLOWED_DESTINATION
        },
        allowedDestination: DEFAULT_ALLOWED_DESTINATION,
        replayProtector: new CapabilityReplayProtector(),
        nowMs: 1_000
      }).ok
    ).toBe(false);
    expect(Buffer.from(secondPayload.capability)).not.toEqual(Buffer.from(firstPayload.capability));
    expect(firstOwnership.authorizationAuditVersion).toBe(1);
    expect(firstOwnership.quota).toEqual({ maxConcurrentStreams: 2, maxBufferedBytes: 16 * 1024 });
    expect(secondOwnership.agentPeerId).toBe(agentPeer.peerId);

    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, firstOwnership.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, secondOwnership.streamId, new Uint8Array()));
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_OPENED)[0]?.streamId).toEqual(aliceStreamId);
    expect(peers.framesFor(bobPeer.peerId, FrameType.STREAM_OPENED)[0]?.streamId).toEqual(bobStreamId);
    expect(coordinator.getActiveStreams().every((item) => item.state === "open")).toBe(true);
    coordinator.close();
  });

  it("按 user/device 授权分别计数，单一用户耗尽配额不影响共享 agent 上另一个用户", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture, 1),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });

    peers.emit(alicePeer.peerId, edgeOpen(streamId(1)));
    peers.emit(alicePeer.peerId, edgeOpen(streamId(2)));
    peers.emit(bobPeer.peerId, edgeOpen(streamId(33)));

    const rejection = peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED)[0]!;
    expect(errorCode(rejection)).toBe(TunnelErrorCode.STREAM_LIMIT_EXCEEDED);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(2);
    expect(coordinator.getActiveStreams().map((item) => item.edgeUserId).sort()).toEqual([
      fixture.alice.edgeUserId,
      fixture.bob.edgeUserId
    ]);
    coordinator.close();
  });

  it("拒绝离线 agent、未允许目标和重复 edge stream ID，且不签发 capability", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    peers.connect(alicePeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });

    peers.emit(alicePeer.peerId, edgeOpen(streamId(1)));
    peers.emit(alicePeer.peerId, edgeOpen(streamId(2), "not-allowed.example.test"));
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).map(errorCode)).toEqual([
      TunnelErrorCode.PEER_DISCONNECTED,
      TunnelErrorCode.DESTINATION_REJECTED
    ]);

    peers.connect(agentSession("agent-peer-shared", fixture.sharedAgent));
    const repeated = streamId(9);
    peers.emit(alicePeer.peerId, edgeOpen(repeated));
    peers.emit(alicePeer.peerId, edgeOpen(repeated));
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).at(-1)).toSatisfy(
      (frame) => errorCode(frame as TunnelFrame) === TunnelErrorCode.PROTOCOL_VIOLATION
    );
    expect(coordinator.getActiveStreams()).toHaveLength(1);
    coordinator.close();
  });

  it("阶段 6 绕过 edge 的 raw STREAM_OPEN 在 server 早拒绝且绝不发往错误 agent", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const wrongAgentPeer = agentSession("agent-peer-other", fixture.otherAgent);
    peers.connect(alicePeer);
    peers.connect(wrongAgentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });

    peers.emit(alicePeer.peerId, edgeOpen(streamId(1)));
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.PEER_DISCONNECTED
    );
    expect(peers.framesFor(wrongAgentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(0);

    const correctAgentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(correctAgentPeer);
    const hostname = DEFAULT_ALLOWED_DESTINATION.hostname;
    const deniedFrames = [
      edgeOpen(streamId(17), "other.example.test"),
      edgeOpen(streamId(33), `sub.${hostname}`),
      edgeOpen(streamId(49), `${hostname}.example.test`),
      edgeOpen(streamId(65), `prefix-${hostname}`),
      edgeOpen(streamId(81), `${hostname}.`),
      edgeOpen(streamId(97), "127.0.0.1"),
      edgeOpen(streamId(113), "127.1"),
      edgeOpen(streamId(129), "2130706433"),
      edgeOpen(streamId(145), "[::1]"),
      edgeOpen(streamId(161), "[2001:db8::1]"),
      rawEdgeOpen(streamId(177), hostname, 80),
      rawEdgeOpen(streamId(193), hostname, 444),
      rawEdgeOpen(streamId(209), hostname, 8_443)
    ];

    for (const frame of deniedFrames) {
      peers.emit(alicePeer.peerId, frame);
    }

    expect(peers.framesFor(correctAgentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(0);
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED)).toHaveLength(deniedFrames.length + 1);

    peers.emit(alicePeer.peerId, edgeOpen(streamId(225), hostname.toUpperCase()));
    expect(peers.framesFor(correctAgentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(1);
    expect(openPayload(peers.framesFor(correctAgentPeer.peerId, FrameType.STREAM_OPEN)[0]!).hostname).toBe(hostname);
    coordinator.close();
  });

  it("在 capability 到期、agent 拒绝、会话断开和授权撤销时清理单一所有权映射", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    let nowMs = 1_000;
    const registry = createRegistry(fixture);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: registry,
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, connectTimeoutMs: 100, openTimeoutMs: 100 },
      capabilityTtlMs: 50,
      now: () => nowMs
    });

    peers.emit(alicePeer.peerId, edgeOpen(streamId(1)));
    nowMs = 1_050;
    coordinator.expireOpenStreams();
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR)[0]!)).toBe(TunnelErrorCode.CAPABILITY_INVALID);
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    peers.emit(alicePeer.peerId, edgeOpen(streamId(33)));
    const rejected = coordinator.getActiveStreams()[0]!;
    peers.emit(
      agentPeer.peerId,
      streamFrame(
        FrameType.STREAM_REJECTED,
        rejected.streamId,
        encodeStreamErrorPayload({ code: TunnelErrorCode.CONNECT_FAILED })
      )
    );
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(TunnelErrorCode.CONNECT_FAILED);
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    peers.emit(alicePeer.peerId, edgeOpen(streamId(65)));
    peers.disconnect(agentPeer.peerId);
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(TunnelErrorCode.PEER_DISCONNECTED);
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    peers.connect(agentPeer);
    peers.emit(alicePeer.peerId, edgeOpen(streamId(97)));
    registry.revokeByEdgeDevice(fixture.alice.edgeDeviceId, 2_000);
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(TunnelErrorCode.AUTH_UNAUTHORIZED);
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    coordinator.close();
  });

  it("在 agent opened 前或本阶段 data/credit 期间拒绝字节，绝不向另一端转发 data", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    const requestedId = streamId(1);
    peers.emit(alicePeer.peerId, edgeOpen(requestedId));
    const ownership = coordinator.getActiveStreams()[0]!;

    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, requestedId, Uint8Array.of(1, 2, 3)));

    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR)[0]!)).toBe(TunnelErrorCode.PROTOCOL_VIOLATION);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_DATA)).toHaveLength(0);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_CLOSE)[0]?.streamId).toEqual(ownership.streamId);
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    coordinator.close();
  });

  it("只接受所有者的 agent 控制帧，并将 close、打开超时和未授权路由稳定地反馈到对应 edge", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    const otherAgentPeer = agentSession("agent-peer-other", fixture.otherAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    peers.connect(otherAgentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });

    peers.emit(alicePeer.peerId, edgeOpen(streamId(1)));
    const first = coordinator.getActiveStreams()[0]!;
    peers.emit(otherAgentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, first.streamId, new Uint8Array()));
    expect(errorCode(peers.framesFor(otherAgentPeer.peerId, FrameType.STREAM_ERROR)[0]!)).toBe(
      TunnelErrorCode.PROTOCOL_VIOLATION
    );
    peers.emit(
      agentPeer.peerId,
      streamFrame(FrameType.STREAM_CLOSE, first.streamId, encodeStreamClosePayload({ code: StreamCloseCode.NORMAL }))
    );
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_CLOSE)[0]?.streamId).toEqual(streamId(1));
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    // agent close 与 edge credit 是两条独立 WSS 的反向消息，credit 可以在
    // server 终结 stream 后迟到。它不能重新打开 stream，也不能关闭 edge WSS。
    const errorsBeforeLateCredit = peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).length;
    peers.emit(alicePeer.peerId, credit(streamId(1), 1));
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR)).toHaveLength(errorsBeforeLateCredit);
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_CREDIT, streamId(99), new Uint8Array([0, 0, 0, 1])));
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.PROTOCOL_VIOLATION
    );

    peers.emit(alicePeer.peerId, edgeOpen(streamId(33)));
    const second = coordinator.getActiveStreams()[0]!;
    peers.emit(
      alicePeer.peerId,
      streamFrame(FrameType.STREAM_CLOSE, streamId(33), encodeStreamClosePayload({ code: StreamCloseCode.NORMAL }))
    );
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_CLOSE).at(-1)?.streamId).toEqual(second.streamId);
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    coordinator.close();

    let nowMs = 1_000;
    const timedPeers = new FakePeerSessions();
    timedPeers.connect(alicePeer);
    timedPeers.connect(agentPeer);
    const timed = new StreamOpenCoordinator({
      peerSessions: timedPeers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, connectTimeoutMs: 100, openTimeoutMs: 100 },
      capabilityTtlMs: 200,
      now: () => nowMs
    });
    timedPeers.emit(alicePeer.peerId, edgeOpen(streamId(65)));
    nowMs = 1_100;
    timed.expireOpenStreams();
    expect(errorCode(timedPeers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR)[0]!)).toBe(TunnelErrorCode.OPEN_TIMEOUT);
    timed.close();

    const deniedPeers = new FakePeerSessions();
    deniedPeers.connect(alicePeer);
    deniedPeers.connect(agentPeer);
    const denied = new StreamOpenCoordinator({
      peerSessions: deniedPeers,
      authorizationRegistry: new AuthorizationRegistry({
        peerIdentities: fixture.peerIdentities,
        document: { auditVersion: 1, authorizations: [] }
      }),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    deniedPeers.emit(alicePeer.peerId, edgeOpen(streamId(97)));
    expect(errorCode(deniedPeers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED)[0]!)).toBe(
      TunnelErrorCode.AUTH_UNAUTHORIZED
    );
    denied.close();
  });

  it("在 opened 后按所有权双向转发 data 与 credit，并保持 edge 和内部 stream ID 隔离及字节顺序", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    const edgeId = streamId(1);

    peers.emit(alicePeer.peerId, edgeOpen(edgeId));
    const ownership = coordinator.getActiveStreams()[0]!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, ownership.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, credit(ownership.streamId, 64 * 1024));
    peers.emit(alicePeer.peerId, credit(edgeId, 64 * 1024));
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, edgeId, Uint8Array.of(1, 2, 3)));
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_DATA, ownership.streamId, Uint8Array.of(4, 5)));

    const agentData = peers.framesFor(agentPeer.peerId, FrameType.STREAM_DATA);
    const edgeData = peers.framesFor(alicePeer.peerId, FrameType.STREAM_DATA);
    expect(agentData).toHaveLength(1);
    expect(agentData[0]?.streamId).toEqual(ownership.streamId);
    expect(agentData[0]?.payload).toEqual(Uint8Array.of(1, 2, 3));
    expect(edgeData).toHaveLength(1);
    expect(edgeData[0]?.streamId).toEqual(edgeId);
    expect(edgeData[0]?.payload).toEqual(Uint8Array.of(4, 5));
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_CREDIT).at(-1)?.streamId).toEqual(edgeId);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_CREDIT).at(-1)?.streamId).toEqual(ownership.streamId);

    peers.emit(agentPeer.peerId, credit(ownership.streamId, 3));
    peers.emit(alicePeer.peerId, credit(edgeId, 2));
    expect(coordinator.getActiveStreams()[0]?.bufferedBytes).toBe(0);
    coordinator.close();
  });

  it("拒绝同一共享 agent 上另一 edge 用户伪造的 stream ID，且不影响真实所有者", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    const aliceId = streamId(17);
    const bobId = streamId(49);

    peers.emit(alicePeer.peerId, edgeOpen(aliceId));
    peers.emit(bobPeer.peerId, edgeOpen(bobId));
    const aliceStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.alice.edgeUserId)!;
    const bobStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.bob.edgeUserId)!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, aliceStream.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, bobStream.streamId, new Uint8Array()));

    peers.emit(bobPeer.peerId, credit(aliceId, 1));
    expect(errorCode(peers.framesFor(bobPeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.PROTOCOL_VIOLATION
    );
    expect(coordinator.getActiveStreams().map((stream) => stream.edgeUserId).sort()).toEqual([
      fixture.alice.edgeUserId,
      fixture.bob.edgeUserId
    ]);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_CREDIT)).toHaveLength(0);
    coordinator.close();
  });

  it("畸形 stream payload 只拒绝未建流请求或关闭对应流，不影响 WSS peer 会话", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    const malformedEdgeId = streamId(25);
    const malformedOpen = {
      type: FrameType.STREAM_OPEN,
      flags: 0,
      streamId: malformedEdgeId,
      payload: new Uint8Array()
    } as unknown as TunnelFrame;

    peers.emit(alicePeer.peerId, malformedOpen);
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.PROTOCOL_VIOLATION
    );
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    const edgeId = streamId(73);
    peers.emit(alicePeer.peerId, edgeOpen(edgeId));
    const ownership = coordinator.getActiveStreams()[0]!;
    const malformedCredit = {
      type: FrameType.STREAM_CREDIT,
      flags: 0,
      streamId: ownership.streamId,
      payload: Uint8Array.of(1)
    } as unknown as TunnelFrame;
    peers.emit(agentPeer.peerId, malformedCredit);

    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.PROTOCOL_VIOLATION
    );
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    coordinator.close();
  });

  it("edge 断开时关闭 agent 侧对应 stream，agent 断开时仅通知存活 edge，其他 edge 流保持隔离", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    const aliceId = streamId(29);
    const bobId = streamId(45);

    peers.emit(alicePeer.peerId, edgeOpen(aliceId));
    peers.emit(bobPeer.peerId, edgeOpen(bobId));
    const aliceStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.alice.edgeUserId)!;
    const bobStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.bob.edgeUserId)!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, aliceStream.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, bobStream.streamId, new Uint8Array()));

    peers.disconnect(alicePeer.peerId);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_CLOSE).at(-1)?.streamId).toEqual(aliceStream.streamId);
    expect(coordinator.getActiveStreams()).toHaveLength(1);
    expect(coordinator.getActiveStreams()[0]?.edgeUserId).toBe(fixture.bob.edgeUserId);
    expect(peers.framesFor(bobPeer.peerId, FrameType.STREAM_ERROR)).toHaveLength(0);

    peers.disconnect(agentPeer.peerId);
    expect(errorCode(peers.framesFor(bobPeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.PEER_DISCONNECTED
    );
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    coordinator.close();
  });

  it("在慢 WSS 消费者上延迟 credit 与 data，恢复后按单流顺序刷新且不放宽窗口", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    const edgeId = streamId(33);

    peers.emit(alicePeer.peerId, edgeOpen(edgeId));
    const ownership = coordinator.getActiveStreams()[0]!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, ownership.streamId, new Uint8Array()));
    peers.setSendBufferedBytes(agentPeer.peerId, DEFAULT_RESOURCE_LIMITS.maxBufferedBytesPerStream);
    peers.emit(alicePeer.peerId, credit(edgeId, 64 * 1024));
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_CREDIT)).toHaveLength(0);

    peers.emit(agentPeer.peerId, credit(ownership.streamId, 64 * 1024));
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, edgeId, Uint8Array.of(7, 8, 9)));
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_DATA)).toHaveLength(0);
    expect(coordinator.getActiveStreams()[0]?.bufferedBytes).toBe(3);

    peers.setSendBufferedBytes(agentPeer.peerId, 0);
    peers.notifySendAvailable(agentPeer.peerId);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_CREDIT)).toHaveLength(1);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_DATA)[0]?.payload).toEqual(Uint8Array.of(7, 8, 9));
    coordinator.close();
  });

  it("在慢 edge WSS 上延迟 agent credit，并在发送可用时仅向该 edge 恢复窗口", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    const edgeId = streamId(41);

    peers.emit(alicePeer.peerId, edgeOpen(edgeId));
    const ownership = coordinator.getActiveStreams()[0]!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, ownership.streamId, new Uint8Array()));
    peers.setSendBufferedBytes(alicePeer.peerId, DEFAULT_RESOURCE_LIMITS.maxBufferedBytesPerStream);
    peers.emit(agentPeer.peerId, credit(ownership.streamId, 64 * 1024));
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_CREDIT)).toHaveLength(0);

    peers.setSendBufferedBytes(alicePeer.peerId, 0);
    peers.notifySendAvailable(alicePeer.peerId);
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_CREDIT)[0]?.streamId).toEqual(edgeId);
    coordinator.close();
  });

  it("下游 WSS 发送失败时仅清理所属 stream，不保留可继续转发的映射", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    });
    const edgeId = streamId(57);

    peers.emit(alicePeer.peerId, edgeOpen(edgeId));
    const ownership = coordinator.getActiveStreams()[0]!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, ownership.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, credit(ownership.streamId, 64 * 1024));
    peers.failNextSend(agentPeer.peerId);
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, edgeId, Uint8Array.of(1)));

    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.PEER_DISCONNECTED
    );
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    coordinator.close();
  });

  it("按用户授权隔离慢流缓冲，单一用户超额仅关闭自身流，聚合上限不会泄漏映射", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(agentPeer);
    const registry = new AuthorizationRegistry({
      peerIdentities: fixture.peerIdentities,
      document: {
        auditVersion: 1,
        authorizations: [
          { ...registration(fixture.alice, fixture.sharedAgent), quota: { maxConcurrentStreams: 2, maxBufferedBytes: 4 } },
          { ...registration(fixture.bob, fixture.sharedAgent), quota: { maxConcurrentStreams: 2, maxBufferedBytes: 4 } }
        ]
      }
    });
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: registry,
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      resourceLimits: {
        ...DEFAULT_RESOURCE_LIMITS,
        maxConcurrentStreams: 2,
        maxBufferedBytesPerStream: 8,
        maxAggregateBufferedBytes: 8
      }
    });
    const aliceId = streamId(65);
    const bobId = streamId(97);

    peers.emit(alicePeer.peerId, edgeOpen(aliceId));
    peers.emit(bobPeer.peerId, edgeOpen(bobId));
    const aliceStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.alice.edgeUserId)!;
    const bobStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.bob.edgeUserId)!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, aliceStream.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, bobStream.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, credit(aliceStream.streamId, 4));
    peers.emit(agentPeer.peerId, credit(bobStream.streamId, 4));
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, aliceId, new Uint8Array(4)));
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, aliceId, Uint8Array.of(1)));
    peers.emit(bobPeer.peerId, streamFrame(FrameType.STREAM_DATA, bobId, new Uint8Array(4)));

    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.FLOW_CONTROL_VIOLATION
    );
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_DATA).at(-1)?.streamId).toEqual(bobStream.streamId);
    expect(coordinator.getActiveStreams()).toHaveLength(1);
    expect(coordinator.getActiveStreams()[0]).toMatchObject({ edgeUserId: fixture.bob.edgeUserId, bufferedBytes: 4 });

    peers.emit(bobPeer.peerId, streamFrame(FrameType.STREAM_CLOSE, bobId, encodeStreamClosePayload({ code: StreamCloseCode.NORMAL })));
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    coordinator.close();
  });

  it("在共享 agent 的聚合缓冲达到上限时只关闭触发超限的 stream，并保留另一用户的有界流", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(agentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      resourceLimits: {
        ...DEFAULT_RESOURCE_LIMITS,
        maxConcurrentStreams: 2,
        maxBufferedBytesPerStream: 8,
        maxAggregateBufferedBytes: 8
      }
    });
    const aliceId = streamId(129);
    const bobId = streamId(161);

    peers.emit(alicePeer.peerId, edgeOpen(aliceId));
    peers.emit(bobPeer.peerId, edgeOpen(bobId));
    const aliceStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.alice.edgeUserId)!;
    const bobStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.bob.edgeUserId)!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, aliceStream.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, bobStream.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, credit(aliceStream.streamId, 4));
    peers.emit(agentPeer.peerId, credit(bobStream.streamId, 4));
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, aliceId, new Uint8Array(4)));
    peers.emit(bobPeer.peerId, streamFrame(FrameType.STREAM_DATA, bobId, new Uint8Array(4)));
    expect(coordinator.getActiveStreams().reduce((total, stream) => total + stream.bufferedBytes, 0)).toBe(8);

    peers.emit(alicePeer.peerId, credit(aliceId, 4));
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_DATA, aliceStream.streamId, Uint8Array.of(1)));
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.FLOW_CONTROL_VIOLATION
    );
    expect(coordinator.getActiveStreams()).toHaveLength(1);
    expect(coordinator.getActiveStreams()[0]).toMatchObject({ edgeUserId: fixture.bob.edgeUserId, bufferedBytes: 4 });
    coordinator.close();
  });

  it("空闲超时仅向关联 edge 和 agent 发送 close，并清理该 stream", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    let nowMs = 1_000;
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, maxIdleMs: 10 },
      capabilityTtlMs: 100,
      now: () => nowMs
    });
    const edgeId = streamId(193);

    peers.emit(alicePeer.peerId, edgeOpen(edgeId));
    const ownership = coordinator.getActiveStreams()[0]!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, ownership.streamId, new Uint8Array()));
    nowMs = 1_010;
    coordinator.expireOpenStreams();

    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_CLOSE).at(-1)?.streamId).toEqual(edgeId);
    expect(peers.framesFor(agentPeer.peerId, FrameType.STREAM_CLOSE).at(-1)?.streamId).toEqual(ownership.streamId);
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    coordinator.close();
  });

  it("agent error 释放未确认字节和用户配额，后续同一用户 stream 可重新保留缓冲", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    const registry = new AuthorizationRegistry({
      peerIdentities: fixture.peerIdentities,
      document: {
        auditVersion: 1,
        authorizations: [
          { ...registration(fixture.alice, fixture.sharedAgent), quota: { maxConcurrentStreams: 2, maxBufferedBytes: 4 } }
        ]
      }
    });
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: registry,
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      resourceLimits: {
        ...DEFAULT_RESOURCE_LIMITS,
        maxConcurrentStreams: 2,
        maxBufferedBytesPerStream: 8,
        maxAggregateBufferedBytes: 8
      }
    });
    const firstEdgeId = streamId(209);
    const secondEdgeId = streamId(225);

    peers.emit(alicePeer.peerId, edgeOpen(firstEdgeId));
    const first = coordinator.getActiveStreams()[0]!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, first.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, credit(first.streamId, 4));
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, firstEdgeId, new Uint8Array(4)));
    expect(coordinator.getActiveStreams()[0]?.bufferedBytes).toBe(4);
    peers.emit(
      agentPeer.peerId,
      streamFrame(
        FrameType.STREAM_ERROR,
        first.streamId,
        encodeStreamErrorPayload({ code: TunnelErrorCode.CONNECT_FAILED })
      )
    );
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    peers.emit(alicePeer.peerId, edgeOpen(secondEdgeId));
    const second = coordinator.getActiveStreams()[0]!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, second.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, credit(second.streamId, 4));
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, secondEdgeId, new Uint8Array(4)));
    expect(coordinator.getActiveStreams()[0]).toMatchObject({ bufferedBytes: 4, edgeStreamId: secondEdgeId });
    coordinator.close();
  });

  it("按 user、device、共享 agent 与全局并发限额拒绝开流，并在断线后清理全部计数", () => {
    const fixture = createFixture();
    const charlie = createEdgeIdentity("edge-user-charlie", "edge-device-charlie");
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const charliePeer = edgeSession("edge-peer-charlie", charlie);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(charliePeer);
    peers.connect(agentPeer);
    const registry = new AuthorizationRegistry({
      peerIdentities: [...fixture.peerIdentities, { identity: charlie }],
      document: {
        auditVersion: 1,
        authorizations: [
          registration(fixture.alice, fixture.sharedAgent, 4),
          registration(fixture.bob, fixture.sharedAgent, 4),
          registration(charlie, fixture.sharedAgent, 4)
        ]
      }
    });
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: registry,
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      quotaLimits: {
        maxConcurrentStreamsPerUser: 1,
        maxConcurrentStreamsPerDevice: 1,
        maxConcurrentStreamsPerAgent: 2,
        maxConcurrentStreamsGlobal: 2,
        maxBufferedBytesPerUser: 4,
        maxBufferedBytesPerDevice: 4,
        maxBufferedBytesPerAgent: 4,
        maxBufferedBytesGlobal: 4,
        maxOpenAttemptsPerWindow: 16,
        openRateWindowMs: 1_000
      }
    });

    peers.emit(alicePeer.peerId, edgeOpen(streamId(1)));
    peers.emit(alicePeer.peerId, edgeOpen(streamId(17)));
    peers.emit(bobPeer.peerId, edgeOpen(streamId(33)));
    peers.emit(charliePeer.peerId, edgeOpen(streamId(49)));

    expect(coordinator.getActiveStreams()).toHaveLength(2);
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.STREAM_LIMIT_EXCEEDED
    );
    expect(errorCode(peers.framesFor(charliePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.STREAM_LIMIT_EXCEEDED
    );
    expect(coordinator.getMetrics()).toMatchObject({
      authenticatedEdgePeers: 3,
      authenticatedAgentPeers: 1,
      activeStreamsByAgent: { [fixture.sharedAgent.agentId]: 2 },
      rejectedStreamsByEdgeUser: {
        [fixture.alice.edgeUserId]: 1,
        [charlie.edgeUserId]: 1
      }
    });

    const aliceOwnership = coordinator.getActiveStreams().find((stream) => stream.edgePeerId === alicePeer.peerId)!;
    const bobOwnership = coordinator.getActiveStreams().find((stream) => stream.edgePeerId === bobPeer.peerId)!;
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, aliceOwnership.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, bobOwnership.streamId, new Uint8Array()));
    peers.emit(agentPeer.peerId, credit(aliceOwnership.streamId, 4));
    peers.emit(agentPeer.peerId, credit(bobOwnership.streamId, 4));
    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, streamId(1), new Uint8Array(4)));
    peers.emit(bobPeer.peerId, streamFrame(FrameType.STREAM_DATA, streamId(33), Uint8Array.of(1)));
    expect(coordinator.getMetrics().bufferWatermark).toMatchObject({ currentBytes: 4, peakBytes: 4, limitBytes: 4 });
    expect(coordinator.getActiveStreams()).toHaveLength(1);

    peers.disconnect(alicePeer.peerId);
    expect(coordinator.getActiveStreams()).toHaveLength(0);
    expect(coordinator.getMetrics().bufferWatermark.currentBytes).toBe(0);
    expect(coordinator.getMetrics().activeStreamsByAgent).toEqual({});
    coordinator.close();
  });

  it("在 user/device、共享 agent 与全局开流频率窗口内拒绝，并在窗口到期后恢复", () => {
    const fixture = createFixture();
    const charlie = createEdgeIdentity("edge-user-charlie", "edge-device-charlie");
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const charliePeer = edgeSession("edge-peer-charlie", charlie);
    const sharedAgentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    const otherAgentPeer = agentSession("agent-peer-other", fixture.otherAgent);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(charliePeer);
    peers.connect(sharedAgentPeer);
    peers.connect(otherAgentPeer);
    const registry = new AuthorizationRegistry({
      peerIdentities: [...fixture.peerIdentities, { identity: charlie }],
      document: {
        auditVersion: 1,
        authorizations: [
          registration(fixture.alice, fixture.sharedAgent, 4),
          registration(fixture.bob, fixture.sharedAgent, 4),
          registration(charlie, fixture.otherAgent, 4)
        ]
      }
    });
    let nowMs = 1_000;
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: registry,
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      quotaLimits: { maxOpenAttemptsPerWindow: 1, openRateWindowMs: 100 },
      now: () => nowMs
    });

    const firstAliceId = streamId(1);
    peers.emit(alicePeer.peerId, edgeOpen(firstAliceId));
    peers.emit(
      alicePeer.peerId,
      streamFrame(FrameType.STREAM_CLOSE, firstAliceId, encodeStreamClosePayload({ code: StreamCloseCode.NORMAL }))
    );
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    // 同一 user/device 的第二次开流命中其自身频率窗口。
    peers.emit(alicePeer.peerId, edgeOpen(streamId(17)));
    // Bob 是独立 user/device；其拒绝不能由 Alice 的 user/device 限额造成，必须保留 shared-agent/global 限制。
    peers.emit(bobPeer.peerId, edgeOpen(streamId(33)));
    // Charlie 使用另一 agent，证明全局频率限制没有被 user 或 shared-agent 测试掩盖。
    peers.emit(charliePeer.peerId, edgeOpen(streamId(49)));

    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.STREAM_LIMIT_EXCEEDED
    );
    expect(errorCode(peers.framesFor(bobPeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.STREAM_LIMIT_EXCEEDED
    );
    expect(errorCode(peers.framesFor(charliePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.STREAM_LIMIT_EXCEEDED
    );
    expect(peers.framesFor(sharedAgentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(1);
    expect(peers.framesFor(otherAgentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(0);

    nowMs = 1_100;
    coordinator.expireOpenStreams();
    peers.emit(charliePeer.peerId, edgeOpen(streamId(65)));
    expect(coordinator.getActiveStreams()).toHaveLength(1);
    expect(coordinator.getActiveStreams()[0]).toMatchObject({
      edgeUserId: charlie.edgeUserId,
      agentId: fixture.otherAgent.agentId
    });
    expect(peers.framesFor(otherAgentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(1);
    coordinator.close();
  });

  it("频率窗口、异常帧与断线反复清理后不残留 stream 映射、缓冲或审计 payload", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const agentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    peers.connect(alicePeer);
    peers.connect(agentPeer);
    let nowMs = 1_000;
    const auditLogs: string[] = [];
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: createRegistry(fixture),
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      quotaLimits: { maxOpenAttemptsPerWindow: 32, openRateWindowMs: 100 },
      auditLogger: (event) => auditLogs.push(event),
      now: () => nowMs
    });

    for (let index = 0; index < 12; index += 1) {
      const edgeId = streamId(index * 16 + 1);
      peers.emit(alicePeer.peerId, edgeOpen(edgeId));
      const ownership = coordinator.getActiveStreams()[0]!;
      peers.emit(agentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, ownership.streamId, new Uint8Array()));
      peers.emit(agentPeer.peerId, credit(ownership.streamId, 64 * 1024));
      peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, edgeId, Uint8Array.of(1, 2, 3, 4)));
      peers.emit(
        agentPeer.peerId,
        {
          type: FrameType.STREAM_CREDIT,
          flags: 0,
          streamId: ownership.streamId,
          payload: Uint8Array.of(1)
        } as unknown as TunnelFrame
      );

      expect(coordinator.getActiveStreams()).toHaveLength(0);
      expect(coordinator.getMetrics().bufferWatermark.currentBytes).toBe(0);
      nowMs += 1;
    }

    expect(coordinator.getMetrics()).toMatchObject({
      activeStreamsByAgent: {},
      closedStreamsByReason: { [TunnelErrorCode.PROTOCOL_VIOLATION]: 12 }
    });
    expect(auditLogs).toHaveLength(36);
    expect(auditLogs.every((event) => !event.includes("payload") && !event.includes("capability"))).toBe(true);
    coordinator.close();
  });

  it("在共享 agent 上隔离用户、credit、关闭、撤销和审计，且拒绝所有越权中继", () => {
    const fixture = createFixture();
    const peers = new FakePeerSessions();
    const alicePeer = edgeSession("edge-peer-alice", fixture.alice);
    const bobPeer = edgeSession("edge-peer-bob", fixture.bob);
    const unauthorizedPeer = edgeSession("edge-peer-unauthorized", createEdgeIdentity("edge-user-unauthorized", "edge-device-unauthorized"));
    const sharedAgentPeer = agentSession("agent-peer-shared", fixture.sharedAgent);
    const wrongAgentPeer = agentSession("agent-peer-other", fixture.otherAgent);
    const auditLogs: string[] = [];
    const requestPayload = Buffer.from("Authorization: Bearer test-token; Cookie: test-cookie");
    const responsePayload = Buffer.from("upstream-response-without-secrets");
    const registry = createRegistry(fixture, 1);
    peers.connect(alicePeer);
    peers.connect(bobPeer);
    peers.connect(unauthorizedPeer);
    peers.connect(sharedAgentPeer);
    peers.connect(wrongAgentPeer);
    const coordinator = new StreamOpenCoordinator({
      peerSessions: peers,
      authorizationRegistry: registry,
      signingCredentials: fixture.signingCredentials,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      auditLogger: (event) => auditLogs.push(event),
      now: () => 1_000
    });
    const aliceId = streamId(1);
    const bobId = streamId(33);

    peers.emit(alicePeer.peerId, edgeOpen(aliceId));
    peers.emit(bobPeer.peerId, edgeOpen(bobId));
    const aliceStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.alice.edgeUserId)!;
    const bobStream = coordinator.getActiveStreams().find((stream) => stream.edgeUserId === fixture.bob.edgeUserId)!;
    const agentOpens = peers.framesFor(sharedAgentPeer.peerId, FrameType.STREAM_OPEN);
    expect(agentOpens).toHaveLength(2);
    expect(peers.framesFor(wrongAgentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(0);

    const aliceCapability = openPayload(agentOpens.find((frame) => frame.streamId.every((value, index) => value === aliceStream.streamId[index]))!);
    expect(
      verifyCapability({
        capability: aliceCapability.capability,
        serverIdentity: fixture.signingCredentials.identity,
        expectedBinding: {
          edgeUserId: fixture.bob.edgeUserId,
          edgeDeviceId: fixture.bob.edgeDeviceId,
          agentId: fixture.sharedAgent.agentId,
          streamId: aliceStream.streamId,
          destination: DEFAULT_ALLOWED_DESTINATION
        },
        allowedDestination: DEFAULT_ALLOWED_DESTINATION,
        replayProtector: new CapabilityReplayProtector(),
        nowMs: 1_000
      }).ok
    ).toBe(false);

    peers.emit(sharedAgentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, aliceStream.streamId, new Uint8Array()));
    peers.emit(sharedAgentPeer.peerId, streamFrame(FrameType.STREAM_OPENED, bobStream.streamId, new Uint8Array()));
    peers.emit(sharedAgentPeer.peerId, credit(aliceStream.streamId, 64));
    peers.emit(sharedAgentPeer.peerId, credit(bobStream.streamId, 64));
    peers.emit(alicePeer.peerId, credit(aliceId, 64));
    peers.emit(bobPeer.peerId, credit(bobId, 64));

    peers.emit(alicePeer.peerId, streamFrame(FrameType.STREAM_DATA, aliceId, requestPayload));
    peers.emit(sharedAgentPeer.peerId, streamFrame(FrameType.STREAM_DATA, aliceStream.streamId, responsePayload));
    const forwardedRequest = peers.framesFor(sharedAgentPeer.peerId, FrameType.STREAM_DATA).at(-1)!;
    const forwardedResponse = peers.framesFor(alicePeer.peerId, FrameType.STREAM_DATA).at(-1)!;
    expect(forwardedRequest.streamId).toEqual(aliceStream.streamId);
    expect(forwardedRequest.payload).toEqual(Uint8Array.from(requestPayload));
    expect(forwardedResponse.streamId).toEqual(aliceId);
    expect(forwardedResponse.payload).toEqual(Uint8Array.from(responsePayload));
    expect(peers.framesFor(bobPeer.peerId, FrameType.STREAM_DATA)).toHaveLength(0);

    // Bob cannot target Alice's edge-local ID; each attempt only returns an error to Bob.
    peers.emit(bobPeer.peerId, credit(aliceId, 1));
    peers.emit(bobPeer.peerId, streamFrame(FrameType.STREAM_DATA, aliceId, Uint8Array.of(9)));
    peers.emit(
      bobPeer.peerId,
      streamFrame(FrameType.STREAM_CLOSE, aliceId, encodeStreamClosePayload({ code: StreamCloseCode.NORMAL }))
    );
    expect(peers.framesFor(bobPeer.peerId, FrameType.STREAM_ERROR).slice(-3).map(errorCode)).toEqual([
      TunnelErrorCode.PROTOCOL_VIOLATION,
      TunnelErrorCode.PROTOCOL_VIOLATION,
      TunnelErrorCode.PROTOCOL_VIOLATION
    ]);
    expect(coordinator.getActiveStreams().map((stream) => stream.edgeUserId).sort()).toEqual([
      fixture.alice.edgeUserId,
      fixture.bob.edgeUserId
    ]);

    peers.emit(wrongAgentPeer.peerId, streamFrame(FrameType.STREAM_DATA, aliceStream.streamId, Uint8Array.of(7)));
    expect(errorCode(peers.framesFor(wrongAgentPeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.PROTOCOL_VIOLATION
    );
    expect(peers.framesFor(alicePeer.peerId, FrameType.STREAM_DATA)).toHaveLength(1);

    peers.emit(unauthorizedPeer.peerId, edgeOpen(streamId(65)));
    expect(errorCode(peers.framesFor(unauthorizedPeer.peerId, FrameType.STREAM_REJECTED)[0]!)).toBe(
      TunnelErrorCode.AUTH_UNAUTHORIZED
    );
    peers.emit(alicePeer.peerId, edgeOpen(streamId(81)));
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.STREAM_LIMIT_EXCEEDED
    );
    expect(peers.framesFor(sharedAgentPeer.peerId, FrameType.STREAM_OPEN)).toHaveLength(2);

    registry.revokeByEdgeDevice(fixture.bob.edgeDeviceId, 1_001);
    expect(errorCode(peers.framesFor(bobPeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(TunnelErrorCode.AUTH_UNAUTHORIZED);
    expect(peers.framesFor(sharedAgentPeer.peerId, FrameType.STREAM_CLOSE).at(-1)?.streamId).toEqual(bobStream.streamId);
    expect(coordinator.getActiveStreams().map((stream) => stream.edgeUserId)).toEqual([fixture.alice.edgeUserId]);

    peers.disconnect(sharedAgentPeer.peerId);
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_ERROR).at(-1)!)).toBe(
      TunnelErrorCode.PEER_DISCONNECTED
    );
    peers.emit(alicePeer.peerId, edgeOpen(streamId(97)));
    expect(errorCode(peers.framesFor(alicePeer.peerId, FrameType.STREAM_REJECTED).at(-1)!)).toBe(
      TunnelErrorCode.PEER_DISCONNECTED
    );
    expect(coordinator.getActiveStreams()).toHaveLength(0);

    expect(auditLogs.join("\n")).not.toContain("test-token");
    expect(auditLogs.join("\n")).not.toContain("test-cookie");
    expect(auditLogs.every((event) => !event.includes("capability") && !event.includes("authorization"))).toBe(true);
    coordinator.close();
  });
});
