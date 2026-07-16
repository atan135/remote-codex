import { once } from "node:events";
import { generateKeyPairSync } from "node:crypto";
import type { AddressInfo } from "node:net";

import {
  connectionFrame,
  createServerSigningCredentials,
  createServerSigningIdentity,
  createEdgeDeviceIdentity,
  createEgressAgentIdentity,
  createIdentityPrivateKey,
  createIdentityPublicKey,
  decodeChallengePayload,
  decodeFrame,
  DEFAULT_ALLOWED_DESTINATION,
  encodeAuthenticatePayload,
  encodeFrame,
  encodeHeartbeatPayload,
  encodeRegisterPayload,
  encodeStreamOpenPayload,
  FrameType,
  IdentityKeyRole,
  signAuthenticationChallenge,
  streamFrame,
  type EdgeDeviceIdentity,
  type EgressAgentIdentity,
  type IdentityPrivateKey,
  type PeerRole,
  type RegisterPayload,
  type ServerSigningCredentials
} from "@remote-codex/shared";
import selfsigned from "selfsigned";
import WebSocket from "ws";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  createTunnelServer,
  type ServerPeerIdentityRegistration,
  type TlsCredentials,
  type TunnelServer
} from "./index.js";

const TEST_ORIGIN = "https://edge.example.test";
let testTlsCredentials: TlsCredentials;
let runningServer: TunnelServer | undefined;
const initialTlsVerificationSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

interface AuthenticationFixture {
  readonly edgeIdentity: EdgeDeviceIdentity;
  readonly edgePrivateKey: IdentityPrivateKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
  readonly agentIdentity: EgressAgentIdentity;
  readonly agentPrivateKey: IdentityPrivateKey<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
  readonly signingCredentials: ServerSigningCredentials;
}

interface ConnectedPeer {
  readonly socket: WebSocket;
  readonly registration: RegisterPayload;
}

beforeAll(() => {
  delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const certificate = selfsigned.generate([{ name: "commonName", value: "localhost" }], {
    algorithm: "sha256",
    days: 1,
    keySize: 2048
  });
  testTlsCredentials = {
    certificate: Buffer.from(certificate.cert),
    privateKey: Buffer.from(certificate.private)
  };
});

afterAll(() => {
  if (initialTlsVerificationSetting === undefined) {
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    return;
  }

  process.env.NODE_TLS_REJECT_UNAUTHORIZED = initialTlsVerificationSetting;
});

afterEach(async () => {
  await runningServer?.close();
  runningServer = undefined;
});

function nonce(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => (seed + index) % 256);
}

function createFixture(suffix = 1): AuthenticationFixture {
  const edgeKeys = generateKeyPairSync("ed25519");
  const agentKeys = generateKeyPairSync("ed25519");
  const signingKeys = generateKeyPairSync("ed25519");
  const edgePrivateKey = createIdentityPrivateKey(
    { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: `edge-key-${suffix}` },
    edgeKeys.privateKey
  );
  const agentPrivateKey = createIdentityPrivateKey(
    { role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: `agent-key-${suffix}` },
    agentKeys.privateKey
  );

  return {
    edgeIdentity: createEdgeDeviceIdentity({
      edgeUserId: `edge-user-${suffix}`,
      edgeDeviceId: `edge-device-${suffix}`,
      authenticationKey: createIdentityPublicKey(
        { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: `edge-key-${suffix}` },
        edgeKeys.publicKey
      )
    }),
    edgePrivateKey,
    agentIdentity: createEgressAgentIdentity({
      agentId: `company-agent-${suffix}`,
      authenticationKey: createIdentityPublicKey(
        { role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: `agent-key-${suffix}` },
        agentKeys.publicKey
      )
    }),
    agentPrivateKey,
    signingCredentials: createServerSigningCredentials({
      identity: createServerSigningIdentity({
        serverId: `server-${suffix}`,
        capabilityVerificationKey: createIdentityPublicKey(
          { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: `server-key-${suffix}` },
          signingKeys.publicKey
        )
      }),
      capabilitySigningKey: createIdentityPrivateKey(
        { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: `server-key-${suffix}` },
        signingKeys.privateKey
      )
    })
  };
}

async function startServer(
  peerIdentities: readonly ServerPeerIdentityRegistration[],
  overrides: Partial<
    Pick<
      Parameters<typeof createTunnelServer>[0],
      "heartbeatTimeoutMs" | "authenticationTimeoutMs" | "authorizationDocument" | "streamAuthorization"
    >
  > = {}
): Promise<string> {
  runningServer = createTunnelServer({
    tls: testTlsCredentials,
    allowedOrigins: [TEST_ORIGIN],
    peerIdentities,
    heartbeatTimeoutMs: 500,
    authenticationTimeoutMs: 500,
    ...overrides
  });
  runningServer.httpsServer.listen(0, "127.0.0.1");
  await once(runningServer.httpsServer, "listening");
  const address = runningServer.httpsServer.address() as AddressInfo;
  return `wss://127.0.0.1:${address.port}`;
}

function openSocket(url: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(`${url}/tunnel`, { origin: TEST_ORIGIN, rejectUnauthorized: false });
    socket.once("open", () => resolve(socket));
    socket.once("error", reject);
  });
}

function nextFrame(socket: WebSocket): Promise<ReturnType<typeof decodeFrame>> {
  return new Promise((resolve, reject) => {
    socket.once("message", (data, isBinary) => {
      if (!isBinary || !Buffer.isBuffer(data)) {
        reject(new Error("expected a binary frame"));
        return;
      }

      try {
        resolve(decodeFrame(data));
      } catch (error: unknown) {
        reject(error);
      }
    });
    socket.once("error", reject);
  });
}

function closeResult(socket: WebSocket): Promise<readonly [number, Buffer]> {
  return new Promise((resolve) => {
    socket.once("close", (code, reason) => resolve([code, reason]));
  });
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  while (!predicate()) {
    if (Date.now() >= deadline) {
      throw new Error("timed out waiting for condition");
    }

    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
}

async function authenticate(
  url: string,
  identity: EdgeDeviceIdentity | EgressAgentIdentity,
  privateKey:
    | IdentityPrivateKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>
    | IdentityPrivateKey<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>,
  role: PeerRole,
  registrationNonce: Uint8Array
): Promise<ConnectedPeer> {
  const socket = await openSocket(url);
  const registration: RegisterPayload = {
    role,
    peerId: identity.kind === "edge-device" ? identity.edgeDeviceId : identity.agentId,
    nonce: registrationNonce
  };
  const challengePromise = nextFrame(socket);
  socket.send(encodeFrame(connectionFrame(FrameType.REGISTER, encodeRegisterPayload(registration))), { binary: true });
  const challengeFrame = await challengePromise;
  expect(challengeFrame.type).toBe(FrameType.CHALLENGE);
  const challenge = {
    issuedAtMs: 0,
    payload: decodeChallengePayload(challengeFrame.payload)
  };
  challenge.issuedAtMs = challenge.payload.expiresAtMs - 500;
  const response = signAuthenticationChallenge({ identity, signingKey: privateKey, registration, challenge });
  const confirmationPromise = nextFrame(socket);
  socket.send(
    encodeFrame(connectionFrame(FrameType.AUTHENTICATE, encodeAuthenticatePayload(response))),
    { binary: true }
  );
  const confirmation = await confirmationPromise;
  expect(confirmation.type).toBe(FrameType.HEARTBEAT);
  expect(encodeFrame(confirmation)).toEqual(
    encodeFrame(connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 0 })))
  );
  return { socket, registration };
}

describe("WSS peer registration and session management", () => {
  it("maps two authenticated edge users to one explicitly shared agent", async () => {
    const firstFixture = createFixture();
    const secondFixture = createFixture(2);
    const url = await startServer(
      [
        { identity: firstFixture.edgeIdentity },
        { identity: secondFixture.edgeIdentity },
        { identity: firstFixture.agentIdentity }
      ],
      {
        authorizationDocument: {
          auditVersion: 1,
          authorizations: [
            {
              edgeUserId: firstFixture.edgeIdentity.edgeUserId,
              edgeDeviceId: firstFixture.edgeIdentity.edgeDeviceId,
              agentId: firstFixture.agentIdentity.agentId,
              status: "active",
              quota: { maxConcurrentStreams: 2, maxBufferedBytes: 16 * 1024 },
              createdAtMs: 0,
              auditVersion: 1
            },
            {
              edgeUserId: secondFixture.edgeIdentity.edgeUserId,
              edgeDeviceId: secondFixture.edgeIdentity.edgeDeviceId,
              agentId: firstFixture.agentIdentity.agentId,
              status: "active",
              quota: { maxConcurrentStreams: 2, maxBufferedBytes: 16 * 1024 },
              createdAtMs: 0,
              auditVersion: 1
            }
          ]
        }
      }
    );
    await authenticate(url, firstFixture.edgeIdentity, firstFixture.edgePrivateKey, "edge-client", nonce(1));
    await authenticate(url, secondFixture.edgeIdentity, secondFixture.edgePrivateKey, "edge-client", nonce(2));
    await authenticate(url, firstFixture.agentIdentity, firstFixture.agentPrivateKey, "egress-agent", nonce(3));
    await waitFor(() => runningServer?.peerSessions.getActiveSessions().length === 3);

    const edgeSessions = (runningServer?.peerSessions.getActiveSessions() ?? []).filter(
      (session) => session.identity.kind === "edge-device"
    );
    expect(edgeSessions).toHaveLength(2);
    expect(
      edgeSessions.map((session) => runningServer?.authorizationRegistry.resolveAgentForEdge(session.identity)?.agentId)
    ).toEqual([firstFixture.agentIdentity.agentId, firstFixture.agentIdentity.agentId]);
  });

  it("通过受控 WSS 会话将 server 签发的 open 仅发送给授权 agent，并把 opened 映射回 edge 请求 ID", async () => {
    const fixture = createFixture();
    const url = await startServer(
      [{ identity: fixture.edgeIdentity }, { identity: fixture.agentIdentity }],
      {
        authorizationDocument: {
          auditVersion: 1,
          authorizations: [
            {
              edgeUserId: fixture.edgeIdentity.edgeUserId,
              edgeDeviceId: fixture.edgeIdentity.edgeDeviceId,
              agentId: fixture.agentIdentity.agentId,
              status: "active",
              quota: { maxConcurrentStreams: 1, maxBufferedBytes: 16 * 1024 },
              createdAtMs: 0,
              auditVersion: 1
            }
          ]
        },
        streamAuthorization: {
          signingCredentials: fixture.signingCredentials,
          allowedDestination: DEFAULT_ALLOWED_DESTINATION,
          capabilityTtlMs: 500
        }
      }
    );
    const edge = await authenticate(url, fixture.edgeIdentity, fixture.edgePrivateKey, "edge-client", nonce(60));
    const agent = await authenticate(url, fixture.agentIdentity, fixture.agentPrivateKey, "egress-agent", nonce(61));
    const edgeStreamId = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
    const agentOpen = nextFrame(agent.socket);
    edge.socket.send(
      encodeFrame(
        streamFrame(
          FrameType.STREAM_OPEN,
          edgeStreamId,
          encodeStreamOpenPayload({
            hostname: DEFAULT_ALLOWED_DESTINATION.hostname,
            port: 443,
            capability: Uint8Array.of(1)
          })
        )
      ),
      { binary: true }
    );
    const forwardedOpen = await agentOpen;
    expect(forwardedOpen.type).toBe(FrameType.STREAM_OPEN);
    expect(forwardedOpen.streamId).not.toEqual(edgeStreamId);
    expect(runningServer?.streamOpenCoordinator?.getActiveStreams()).toHaveLength(1);

    const edgeOpened = nextFrame(edge.socket);
    agent.socket.send(encodeFrame(streamFrame(FrameType.STREAM_OPENED, forwardedOpen.streamId, new Uint8Array())), {
      binary: true
    });
    const opened = await edgeOpened;
    expect(opened.type).toBe(FrameType.STREAM_OPENED);
    expect(opened.streamId).toEqual(edgeStreamId);
  });

  it("authenticates independently registered edge and agent peers and retains metadata only", async () => {
    const fixture = createFixture();
    const url = await startServer([{ identity: fixture.edgeIdentity }, { identity: fixture.agentIdentity }]);
    const edge = await authenticate(url, fixture.edgeIdentity, fixture.edgePrivateKey, "edge-client", nonce(1));
    const agent = await authenticate(url, fixture.agentIdentity, fixture.agentPrivateKey, "egress-agent", nonce(2));

    await waitFor(() => runningServer?.peerSessions.getActiveSessions().length === 2);
    const sessions = runningServer?.peerSessions.getActiveSessions() ?? [];
    const edgeSession = sessions.find((session) => session.role === "edge-client");
    const agentSession = sessions.find((session) => session.role === "egress-agent");

    expect(edgeSession).toMatchObject({
      identity: { kind: "edge-device", edgeUserId: "edge-user-1", edgeDeviceId: "edge-device-1" },
      protocolVersion: 1
    });
    expect(agentSession).toMatchObject({ identity: { kind: "egress-agent", agentId: "company-agent-1" }, protocolVersion: 1 });
    expect(edgeSession?.peerId).not.toBe(edge.registration.peerId);
    expect(agentSession?.peerId).not.toBe(agent.registration.peerId);

    edge.socket.send(
      encodeFrame(connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 7 }))),
      { binary: true }
    );
    await waitFor(() => runningServer?.peerSessions.getSession(edgeSession?.peerId ?? "")?.lastHeartbeatSequence === 7);
  });

  it("仅暴露已认证 peer 的 WSS 队列元数据，并在发送完成后通知 relay 监听器", async () => {
    const fixture = createFixture();
    const url = await startServer([{ identity: fixture.agentIdentity }]);
    const connected = await authenticate(url, fixture.agentIdentity, fixture.agentPrivateKey, "egress-agent", nonce(8));
    const manager = runningServer!.peerSessions;
    const peerId = manager.getActiveSessions()[0]!.peerId;
    const availability: string[] = [];
    const unsubscribeThrowingListener = manager.subscribeSendAvailability(() => {
      throw new Error("listener failure must not affect the session");
    });
    const unsubscribe = manager.subscribeSendAvailability((availablePeerId) => availability.push(availablePeerId));

    expect(manager.getSendBufferedBytes("unknown-peer")).toBeUndefined();
    expect(manager.getSendBufferedBytes(peerId)).toBe(0);
    const received = nextFrame(connected.socket);
    expect(
      manager.sendFrame(peerId, streamFrame(FrameType.STREAM_OPENED, Uint8Array.from({ length: 16 }, () => 1), new Uint8Array()))
    ).toBe(true);
    expect((await received).type).toBe(FrameType.STREAM_OPENED);
    await waitFor(() => availability.includes(peerId));

    unsubscribeThrowingListener();
    unsubscribe();
  });

  it("rejects role mismatches, expired identities, bad signatures, and unsupported protocol versions", async () => {
    const fixture = createFixture();
    const expiredFixture = createFixture();
    const url = await startServer([
      { identity: fixture.agentIdentity },
      { identity: expiredFixture.edgeIdentity, expiresAtMs: Date.now() - 1 }
    ]);

    const wrongRoleSocket = await openSocket(url);
    const wrongRoleClose = closeResult(wrongRoleSocket);
    wrongRoleSocket.send(
      encodeFrame(
        connectionFrame(
          FrameType.REGISTER,
          encodeRegisterPayload({ role: "edge-client", peerId: fixture.agentIdentity.agentId, nonce: nonce(10) })
        )
      ),
      { binary: true }
    );
    await expect(wrongRoleClose).resolves.toEqual([1008, Buffer.from("AUTH_UNAUTHORIZED")]);

    const expiredSocket = await openSocket(url);
    const expiredClose = closeResult(expiredSocket);
    expiredSocket.send(
      encodeFrame(
        connectionFrame(
          FrameType.REGISTER,
          encodeRegisterPayload({
            role: "edge-client",
            peerId: expiredFixture.edgeIdentity.edgeDeviceId,
            nonce: nonce(11)
          })
        )
      ),
      { binary: true }
    );
    await expect(expiredClose).resolves.toEqual([1008, Buffer.from("AUTH_EXPIRED")]);

    const badSignatureSocket = await openSocket(url);
    const registration: RegisterPayload = {
      role: "egress-agent",
      peerId: fixture.agentIdentity.agentId,
      nonce: nonce(12)
    };
    const challengePromise = nextFrame(badSignatureSocket);
    badSignatureSocket.send(
      encodeFrame(connectionFrame(FrameType.REGISTER, encodeRegisterPayload(registration))),
      { binary: true }
    );
    const challengeFrame = await challengePromise;
    const challenge = { issuedAtMs: decodeChallengePayload(challengeFrame.payload).expiresAtMs - 500, payload: decodeChallengePayload(challengeFrame.payload) };
    const response = signAuthenticationChallenge({
      identity: fixture.agentIdentity,
      signingKey: fixture.agentPrivateKey,
      registration,
      challenge
    });
    const signature = Uint8Array.from(response.signature);
    signature[0] = (signature[0] ?? 0) ^ 1;
    const badSignatureClose = closeResult(badSignatureSocket);
    badSignatureSocket.send(
      encodeFrame(
        connectionFrame(
          FrameType.AUTHENTICATE,
          encodeAuthenticatePayload({ challengeNonce: response.challengeNonce, signature })
        )
      ),
      { binary: true }
    );
    await expect(badSignatureClose).resolves.toEqual([1008, Buffer.from("AUTH_FAILED")]);

    const incompatibleSocket = await openSocket(url);
    const incompatibleClose = closeResult(incompatibleSocket);
    const incompatibleFrame = encodeFrame(
      connectionFrame(
        FrameType.REGISTER,
        encodeRegisterPayload({ role: "egress-agent", peerId: fixture.agentIdentity.agentId, nonce: nonce(13) })
      )
    );
    incompatibleFrame[0] = 2;
    incompatibleSocket.send(incompatibleFrame, { binary: true });
    await expect(incompatibleClose).resolves.toEqual([1002, Buffer.from("PROTOCOL_VIOLATION")]);
    expect(runningServer?.peerSessions.getPendingConnectionCount()).toBe(0);
  });

  it("rejects a reused registration nonce after a valid second challenge", async () => {
    const fixture = createFixture();
    const url = await startServer([{ identity: fixture.agentIdentity }]);
    await authenticate(url, fixture.agentIdentity, fixture.agentPrivateKey, "egress-agent", nonce(20));
    await waitFor(() => runningServer?.peerSessions.getActiveSessions().length === 1);

    const replaySocket = await openSocket(url);
    const registration: RegisterPayload = {
      role: "egress-agent",
      peerId: fixture.agentIdentity.agentId,
      nonce: nonce(20)
    };
    const challengePromise = nextFrame(replaySocket);
    replaySocket.send(
      encodeFrame(connectionFrame(FrameType.REGISTER, encodeRegisterPayload(registration))),
      { binary: true }
    );
    const challengeFrame = await challengePromise;
    const challengePayload = decodeChallengePayload(challengeFrame.payload);
    const response = signAuthenticationChallenge({
      identity: fixture.agentIdentity,
      signingKey: fixture.agentPrivateKey,
      registration,
      challenge: { issuedAtMs: challengePayload.expiresAtMs - 500, payload: challengePayload }
    });
    const replayClose = closeResult(replaySocket);
    replaySocket.send(
      encodeFrame(connectionFrame(FrameType.AUTHENTICATE, encodeAuthenticatePayload(response))),
      { binary: true }
    );
    await expect(replayClose).resolves.toEqual([1008, Buffer.from("AUTH_REPLAYED")]);
    expect(runningServer?.peerSessions.getActiveSessions()).toHaveLength(1);
  });

  it("rejects an identity that expires after registration but before its signed response", async () => {
    const fixture = createFixture();
    const url = await startServer([{ identity: fixture.edgeIdentity, expiresAtMs: Date.now() + 100 }]);
    const socket = await openSocket(url);
    const registration: RegisterPayload = {
      role: "edge-client",
      peerId: fixture.edgeIdentity.edgeDeviceId,
      nonce: nonce(25)
    };
    const challengePromise = nextFrame(socket);
    socket.send(
      encodeFrame(connectionFrame(FrameType.REGISTER, encodeRegisterPayload(registration))),
      { binary: true }
    );
    const challengeFrame = await challengePromise;
    const challengePayload = decodeChallengePayload(challengeFrame.payload);
    await new Promise<void>((resolve) => setTimeout(resolve, 120));
    const response = signAuthenticationChallenge({
      identity: fixture.edgeIdentity,
      signingKey: fixture.edgePrivateKey,
      registration,
      challenge: { issuedAtMs: challengePayload.expiresAtMs - 500, payload: challengePayload }
    });
    const closed = closeResult(socket);
    socket.send(
      encodeFrame(connectionFrame(FrameType.AUTHENTICATE, encodeAuthenticatePayload(response))),
      { binary: true }
    );

    await expect(closed).resolves.toEqual([1008, Buffer.from("AUTH_EXPIRED")]);
    expect(runningServer?.peerSessions.getPendingConnectionCount()).toBe(0);
  });

  it("revokes sessions that miss the heartbeat deadline", async () => {
    const fixture = createFixture();
    const url = await startServer([{ identity: fixture.edgeIdentity }], { heartbeatTimeoutMs: 25 });
    const edge = await authenticate(url, fixture.edgeIdentity, fixture.edgePrivateKey, "edge-client", nonce(30));
    const closed = closeResult(edge.socket);

    await expect(closed).resolves.toEqual([1008, Buffer.from("HEARTBEAT_TIMEOUT")]);
    expect(runningServer?.peerSessions.getActiveSessions()).toHaveLength(0);
  });

  it("replaces an authenticated agent connection only after the new session succeeds", async () => {
    const fixture = createFixture();
    const url = await startServer([{ identity: fixture.agentIdentity }]);
    const first = await authenticate(url, fixture.agentIdentity, fixture.agentPrivateKey, "egress-agent", nonce(40));
    await waitFor(() => runningServer?.peerSessions.getActiveSessions().length === 1);
    const firstPeerId = runningServer?.peerSessions.getActiveSessions()[0]?.peerId;
    const firstClosed = closeResult(first.socket);

    await authenticate(url, fixture.agentIdentity, fixture.agentPrivateKey, "egress-agent", nonce(41));
    await expect(firstClosed).resolves.toEqual([1008, Buffer.from("AGENT_SESSION_REPLACED")]);
    await waitFor(() => runningServer?.peerSessions.getActiveSessions().length === 1);
    const replacement = runningServer?.peerSessions.getActiveSessions()[0];

    expect(replacement?.peerId).not.toBe(firstPeerId);
    expect(replacement?.identity.agentId).toBe("company-agent-1");
  });
});
