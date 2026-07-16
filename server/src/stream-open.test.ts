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

  public sendFrame(peerId: string, frame: TunnelFrame): boolean {
    if (!this.sessions.has(peerId)) {
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
    protocolVersion: 1,
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
    protocolVersion: 1,
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
});
