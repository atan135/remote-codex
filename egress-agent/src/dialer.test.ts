import { generateKeyPairSync } from "node:crypto";

import {
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  createStreamId,
  decodeFramePayload,
  encodeStreamClosePayload,
  encodeStreamOpenPayload,
  FrameType,
  IdentityKeyRole,
  issueCapability,
  parseEgressAgentConfig,
  streamFrame,
  TunnelErrorCode,
  type ServerSigningCredentials,
  type ServerSigningIdentity,
  type TunnelFrame
} from "@remote-codex/shared";
import { describe, expect, it } from "vitest";

import {
  EgressAgentDialer,
  type AgentTcpConnector,
  type AgentTcpSocket,
  type EgressAgentStreamSession
} from "./dialer.js";

const NOW_MS = 1_784_562_400_000;
const HOSTNAME = "ai-coding-bj-pub.singularity-ai.com";

class FakeTcpSocket implements AgentTcpSocket {
  public endCalls = 0;
  public destroyCalls = 0;
  private readonly timeoutListeners: Array<() => void> = [];
  private readonly listeners = new Map<"connect" | "error" | "end" | "close", () => void>();

  public end(): void {
    this.endCalls += 1;
  }

  public destroy(): void {
    this.destroyCalls += 1;
  }

  public setTimeout(_timeoutMs: number, listener: () => void): void {
    this.timeoutListeners.push(listener);
  }

  public once(event: "connect" | "error" | "end" | "close", listener: () => void): void {
    this.listeners.set(event, listener);
  }

  public emit(event: "connect" | "error" | "end" | "close"): void {
    const listener = this.listeners.get(event);
    this.listeners.delete(event);
    listener?.();
  }

  public emitTimeout(): void {
    for (const listener of this.timeoutListeners) {
      listener();
    }
  }
}

class FakeConnector implements AgentTcpConnector {
  public readonly calls: Array<Readonly<{ hostname: string; port: 443 }>> = [];
  public readonly sockets: FakeTcpSocket[] = [];

  public connect(destination: Readonly<{ hostname: string; port: 443 }>): AgentTcpSocket {
    this.calls.push({ ...destination });
    const socket = new FakeTcpSocket();
    this.sockets.push(socket);
    return socket;
  }
}

function createConfig(maxConcurrentStreams = 2) {
  return parseEgressAgentConfig({
    component: "egress-agent",
    agentId: "company-agent-1",
    serverUrl: "wss://tunnel.example.test/tunnel",
    allowedDestination: { hostname: HOSTNAME, port: 443 },
    limits: {
      maxConcurrentStreams,
      maxBufferedBytesPerStream: 1_024,
      maxAggregateBufferedBytes: 2_048,
      maxFramePayloadBytes: 1_024,
      maxIdleMs: 1_000,
      connectTimeoutMs: 100,
      openTimeoutMs: 100,
      heartbeatIntervalMs: 100,
      heartbeatTimeoutMs: 200,
      reconnectInitialMs: 100,
      reconnectMaxMs: 400,
      maxReconnectAttempts: 2
    }
  });
}

function createServerFixture(): { readonly identity: ServerSigningIdentity; readonly credentials: ServerSigningCredentials } {
  const keys = generateKeyPairSync("ed25519");
  const keyId = "server-capability-key-1";
  const identity = createServerSigningIdentity({
    serverId: "public-server-1",
    capabilityVerificationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId },
      keys.publicKey
    )
  });
  const credentials = createServerSigningCredentials({
    identity,
    capabilitySigningKey: createIdentityPrivateKey(
      { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId },
      keys.privateKey
    )
  });
  return { identity, credentials };
}

function issueOpenCapability(credentials: ServerSigningCredentials, streamId: Uint8Array): Uint8Array {
  return issueCapability({
    credentials,
    binding: {
      edgeUserId: "edge-user-1",
      edgeDeviceId: "edge-device-1",
      agentId: "company-agent-1",
      streamId,
      destination: { hostname: HOSTNAME, port: 443 }
    },
    allowedDestination: { hostname: HOSTNAME, port: 443 },
    nowMs: NOW_MS,
    ttlMs: 5_000,
    randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => (streamId[index % streamId.byteLength] ?? 0) ^ index)
  });
}

function createSession(): { readonly session: EgressAgentStreamSession; readonly sent: TunnelFrame[] } {
  const sent: TunnelFrame[] = [];
  const session: EgressAgentStreamSession = {
    id: {},
    nowMs: NOW_MS + 1,
    send: (frame) => {
      sent.push(frame);
      return true;
    }
  };
  return { session, sent };
}

function openFrame(streamId: Uint8Array, capability: Uint8Array, hostname = HOSTNAME): TunnelFrame {
  return streamFrame(
    FrameType.STREAM_OPEN,
    streamId,
    encodeStreamOpenPayload({ hostname, port: 443, capability })
  );
}

function malformedPortFrame(streamId: Uint8Array, capability: Uint8Array): TunnelFrame {
  const hostname = new TextEncoder().encode(HOSTNAME);
  const payload = new Uint8Array(5 + hostname.byteLength + capability.byteLength);
  payload[0] = hostname.byteLength;
  payload.set(hostname, 1);
  const view = new DataView(payload.buffer);
  view.setUint16(1 + hostname.byteLength, 444);
  view.setUint16(3 + hostname.byteLength, capability.byteLength);
  payload.set(capability, 5 + hostname.byteLength);
  return {
    type: FrameType.STREAM_OPEN,
    flags: 0,
    streamId: Uint8Array.from(streamId),
    payload
  };
}

function missingCapabilityFrame(streamId: Uint8Array): TunnelFrame {
  return {
    type: FrameType.STREAM_OPEN,
    flags: 0,
    streamId: Uint8Array.from(streamId),
    payload: new Uint8Array()
  };
}

function lastErrorCode(sent: readonly TunnelFrame[]): string | undefined {
  const frame = sent.at(-1);

  if (frame === undefined) {
    return undefined;
  }

  const payload = decodeFramePayload(frame);
  return payload !== undefined && !(payload instanceof Uint8Array) && "code" in payload ? payload.code : undefined;
}

describe("egress agent final authorization and restricted TCP dialing", () => {
  it("dials only the exact local hostname:443 after a valid one-time capability", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const { session, sent } = createSession();
    const streamId = createStreamId();

    dialer.handleFrame(session, openFrame(streamId, issueOpenCapability(credentials, streamId)));

    expect(connector.calls).toEqual([{ hostname: HOSTNAME, port: 443 }]);
    expect(dialer.activeStreamCount).toBe(1);
    expect(sent).toEqual([]);
    connector.sockets[0]?.emit("connect");
    expect(dialer.activeStreamCount).toBe(1);
  });

  it("rejects IP literals, near hostnames, other ports, tampered and missing capabilities before dialing", () => {
    const attempts: Array<{
      readonly makeFrame: (streamId: Uint8Array, capability: Uint8Array) => TunnelFrame;
      readonly expected: string;
    }> = [
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "127.0.0.1"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, `other.${HOSTNAME}`), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: malformedPortFrame, expected: TunnelErrorCode.CAPABILITY_INVALID },
      {
        makeFrame: (streamId, capability) => {
          const tampered = Uint8Array.from(capability);
          tampered[tampered.byteLength - 1] = (tampered[tampered.byteLength - 1] ?? 0) ^ 1;
          return openFrame(streamId, tampered);
        },
        expected: TunnelErrorCode.CAPABILITY_INVALID
      },
      { makeFrame: (streamId) => missingCapabilityFrame(streamId), expected: TunnelErrorCode.CAPABILITY_INVALID }
    ];

    for (const attempt of attempts) {
      const config = createConfig();
      const { identity, credentials } = createServerFixture();
      const connector = new FakeConnector();
      const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
      const { session, sent } = createSession();
      const streamId = createStreamId();
      dialer.handleFrame(session, attempt.makeFrame(streamId, issueOpenCapability(credentials, streamId)));

      expect(connector.calls).toEqual([]);
      expect(lastErrorCode(sent)).toBe(attempt.expected);
    }
  });

  it("rejects capabilities bound to another agent or stream before dialing", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const { session, sent } = createSession();
    const streamId = createStreamId();
    const otherStreamId = createStreamId();
    const otherAgentCapability = issueCapability({
      credentials,
      binding: {
        edgeUserId: "edge-user-1",
        edgeDeviceId: "edge-device-1",
        agentId: "other-agent",
        streamId,
        destination: { hostname: HOSTNAME, port: 443 }
      },
      allowedDestination: { hostname: HOSTNAME, port: 443 },
      nowMs: NOW_MS,
      ttlMs: 5_000
    });

    dialer.handleFrame(session, openFrame(streamId, otherAgentCapability));
    dialer.handleFrame(session, openFrame(streamId, issueOpenCapability(credentials, otherStreamId)));

    expect(connector.calls).toEqual([]);
    expect(sent).toHaveLength(2);
    expect(lastErrorCode(sent)).toBe(TunnelErrorCode.CAPABILITY_INVALID);
  });

  it("enforces agent concurrency and maps connect, idle, EOF and close cleanup without socket details", () => {
    const config = createConfig(1);
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const { session, sent } = createSession();
    const firstId = createStreamId();
    const secondId = createStreamId();

    dialer.handleFrame(session, openFrame(firstId, issueOpenCapability(credentials, firstId)));
    dialer.handleFrame(session, openFrame(secondId, issueOpenCapability(credentials, secondId)));
    expect(connector.calls).toHaveLength(1);
    expect(lastErrorCode(sent)).toBe(TunnelErrorCode.STREAM_LIMIT_EXCEEDED);

    connector.sockets[0]?.emitTimeout();
    expect(lastErrorCode(sent)).toBe(TunnelErrorCode.CONNECT_FAILED);
    expect(connector.sockets[0]?.destroyCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(0);

    const thirdId = createStreamId();
    dialer.handleFrame(session, openFrame(thirdId, issueOpenCapability(credentials, thirdId)));
    connector.sockets[1]?.emit("connect");
    connector.sockets[1]?.emitTimeout();
    // node:net 会保留 connect 与 idle 两个 timeout callback；连接后的旧回调
    // 必须无操作，当前空闲回调才会把流映射为 IDLE_TIMEOUT。
    expect(lastErrorCode(sent)).toBe(TunnelErrorCode.IDLE_TIMEOUT);
    expect(dialer.activeStreamCount).toBe(0);

    const fourthId = createStreamId();
    dialer.handleFrame(session, openFrame(fourthId, issueOpenCapability(credentials, fourthId)));
    connector.sockets[2]?.emit("connect");
    connector.sockets[2]?.emit("end");
    expect(sent.at(-1)?.type).toBe(FrameType.STREAM_CLOSE);
    expect(lastErrorCode(sent)).toBe("NORMAL");
    expect(dialer.activeStreamCount).toBe(0);

    const fifthId = createStreamId();
    dialer.handleFrame(session, openFrame(fifthId, issueOpenCapability(credentials, fifthId)));
    dialer.closeAll();
    expect(connector.sockets[3]?.destroyCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(0);
  });

  it("keeps a stream bound to its authenticated WSS session and closes TCP in two phases", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const first = createSession();
    const other = createSession();
    const streamId = createStreamId();
    const closeFrame = streamFrame(
      FrameType.STREAM_CLOSE,
      streamId,
      encodeStreamClosePayload({ code: "NORMAL" })
    );

    dialer.handleFrame(first.session, openFrame(streamId, issueOpenCapability(credentials, streamId)));
    dialer.handleFrame(other.session, closeFrame);
    expect(connector.sockets[0]?.endCalls).toBe(0);
    expect(lastErrorCode(other.sent)).toBe(TunnelErrorCode.PROTOCOL_VIOLATION);

    dialer.handleFrame(first.session, closeFrame);
    expect(connector.sockets[0]?.endCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(1);
    connector.sockets[0]?.emit("close");
    expect(dialer.activeStreamCount).toBe(0);

    const errorStreamId = createStreamId();
    dialer.handleFrame(first.session, openFrame(errorStreamId, issueOpenCapability(credentials, errorStreamId)));
    connector.sockets[1]?.emit("error");
    expect(lastErrorCode(first.sent)).toBe(TunnelErrorCode.CONNECT_FAILED);
    expect(dialer.activeStreamCount).toBe(0);
  });
});
