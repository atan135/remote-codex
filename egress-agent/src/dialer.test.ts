import { generateKeyPairSync } from "node:crypto";

import {
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  createStreamId,
  decodeFramePayload,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
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
  public pauseCalls = 0;
  public resumeCalls = 0;
  public readonly writes: Uint8Array[] = [];
  public writeResult = true;
  public throwOnWrite = false;
  public throwOnEnd = false;
  public throwOnDestroy = false;
  public throwOnPause = false;
  public throwOnResume = false;
  private readonly timeoutListeners: Array<() => void> = [];
  private readonly listeners = new Map<"connect" | "error" | "end" | "close", () => void>();
  private dataListener: ((data: Uint8Array) => void) | undefined;
  private drainListener: (() => void) | undefined;

  public end(): void {
    this.endCalls += 1;
    if (this.throwOnEnd) {
      throw new Error("socket end failed");
    }
  }

  public destroy(): void {
    this.destroyCalls += 1;
    if (this.throwOnDestroy) {
      throw new Error("socket destroy failed");
    }
  }

  public write(data: Uint8Array): boolean {
    this.writes.push(Uint8Array.from(data));
    if (this.throwOnWrite) {
      throw new Error("socket write failed");
    }
    return this.writeResult;
  }

  public pause(): void {
    this.pauseCalls += 1;
    if (this.throwOnPause) {
      throw new Error("socket pause failed");
    }
  }

  public resume(): void {
    this.resumeCalls += 1;
    if (this.throwOnResume) {
      throw new Error("socket resume failed");
    }
  }

  public setTimeout(_timeoutMs: number, listener: () => void): void {
    this.timeoutListeners.push(listener);
  }

  public once(event: "connect" | "error" | "end" | "close", listener: () => void): void {
    this.listeners.set(event, listener);
  }

  public on(event: "data", listener: (data: Uint8Array) => void): void;
  public on(event: "drain", listener: () => void): void;
  public on(event: "data" | "drain", listener: ((data: Uint8Array) => void) | (() => void)): void {
    if (event === "data") {
      this.dataListener = listener as (data: Uint8Array) => void;
      return;
    }

    this.drainListener = listener as () => void;
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

  public emitData(data: Uint8Array): void {
    this.dataListener?.(data);
  }

  public emitDrain(): void {
    this.drainListener?.();
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

function issueOpenCapability(
  credentials: ServerSigningCredentials,
  streamId: Uint8Array,
  edgeUserId = "edge-user-1",
  edgeDeviceId = "edge-device-1"
): Uint8Array {
  return issueCapability({
    credentials,
    binding: {
      edgeUserId,
      edgeDeviceId,
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

function createSession(): {
  readonly session: EgressAgentStreamSession;
  readonly sent: TunnelFrame[];
  setBufferedBytes(bytes: number): void;
  emitSendAvailability(): void;
  setSendResult(result: boolean): void;
  setSendFailure(shouldThrow: boolean): void;
} {
  const sent: TunnelFrame[] = [];
  const availabilityListeners = new Set<() => void>();
  let bufferedBytes = 0;
  let sendResult = true;
  let throwOnSend = false;
  const session: EgressAgentStreamSession = {
    id: {},
    nowMs: NOW_MS + 1,
    send: (frame) => {
      if (throwOnSend) {
        throw new Error("WSS send failed");
      }
      sent.push(frame);
      return sendResult;
    },
    getSendBufferedBytes: () => bufferedBytes,
    subscribeSendAvailability: (listener) => {
      availabilityListeners.add(listener);
      return (): void => {
        availabilityListeners.delete(listener);
      };
    }
  };
  return {
    session,
    sent,
    setBufferedBytes: (bytes) => {
      bufferedBytes = bytes;
    },
    emitSendAvailability: () => {
      for (const listener of availabilityListeners) {
        listener();
      }
    },
    setSendResult: (result) => {
      sendResult = result;
    },
    setSendFailure: (shouldThrow) => {
      throwOnSend = shouldThrow;
    }
  };
}

function openFrame(streamId: Uint8Array, capability: Uint8Array, hostname = HOSTNAME): TunnelFrame {
  return streamFrame(
    FrameType.STREAM_OPEN,
    streamId,
    encodeStreamOpenPayload({ hostname, port: 443, capability })
  );
}

function malformedPortFrame(streamId: Uint8Array, capability: Uint8Array, port = 444): TunnelFrame {
  const hostname = new TextEncoder().encode(HOSTNAME);
  const payload = new Uint8Array(5 + hostname.byteLength + capability.byteLength);
  payload[0] = hostname.byteLength;
  payload.set(hostname, 1);
  const view = new DataView(payload.buffer);
  view.setUint16(1 + hostname.byteLength, port);
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

function creditFrame(streamId: Uint8Array, bytes: number): TunnelFrame {
  return streamFrame(FrameType.STREAM_CREDIT, streamId, encodeStreamCreditPayload({ bytes }));
}

function dataFrame(streamId: Uint8Array, payload: Uint8Array): TunnelFrame {
  return streamFrame(FrameType.STREAM_DATA, streamId, payload);
}

function sameStreamId(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
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
  it("仅在 TCP 成功连接后发送 opened、初始 credit 和透明 data 帧", () => {
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
    expect(sent.map((frame) => frame.type)).toEqual([FrameType.STREAM_OPENED, FrameType.STREAM_CREDIT]);
    expect(decodeFramePayload(sent[1] as TunnelFrame)).toEqual({ bytes: 1_024 });
    expect(connector.sockets[0]?.pauseCalls).toBe(1);

    dialer.handleFrame(session, creditFrame(streamId, 3));
    expect(connector.sockets[0]?.resumeCalls).toBe(1);
    connector.sockets[0]?.emitData(Uint8Array.of(4, 5, 6));

    expect(sent.at(-1)?.type).toBe(FrameType.STREAM_DATA);
    expect(decodeFramePayload(sent.at(-1) as TunnelFrame)).toEqual(Uint8Array.of(4, 5, 6));
  });

  it("rejects IP literals, near hostnames, other ports, tampered and missing capabilities before dialing", () => {
    const attempts: Array<{
      readonly makeFrame: (streamId: Uint8Array, capability: Uint8Array) => TunnelFrame;
      readonly expected: string;
    }> = [
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "127.0.0.1"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "127.1"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "2130706433"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "0x7f000001"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "[::1]"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "::1"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "[2001:db8::1]"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      // 最终边界按精确 hostname，而非 DNS 结果授权；即使部署时二者解析到同一 IP 也不可拨号。
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, "same-ip-alias.integration.test"), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, `other.${HOSTNAME}`), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, `${HOSTNAME}.example.test`), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, `prefix-${HOSTNAME}`), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => openFrame(streamId, capability, `${HOSTNAME}.`), expected: TunnelErrorCode.DESTINATION_REJECTED },
      { makeFrame: (streamId, capability) => malformedPortFrame(streamId, capability, 80), expected: TunnelErrorCode.CAPABILITY_INVALID },
      { makeFrame: (streamId, capability) => malformedPortFrame(streamId, capability, 444), expected: TunnelErrorCode.CAPABILITY_INVALID },
      { makeFrame: (streamId, capability) => malformedPortFrame(streamId, capability, 8_443), expected: TunnelErrorCode.CAPABILITY_INVALID },
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

    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const { session } = createSession();
    const streamId = createStreamId();
    dialer.handleFrame(session, openFrame(streamId, issueOpenCapability(credentials, streamId), HOSTNAME.toUpperCase()));
    expect(connector.calls).toEqual([{ hostname: HOSTNAME, port: 443 }]);
  });

  it("阶段 6 在最终 dialer 独立拒绝过期、伪造和 replay capability 且不增加 TCP 拨号", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();

    const expiredConnector = new FakeConnector();
    const expiredDialer = new EgressAgentDialer({
      config,
      capabilityServerIdentity: identity,
      connector: expiredConnector,
      now: () => NOW_MS + 100
    });
    const expiredSession = createSession();
    const expiredId = createStreamId();
    const expiredCapability = issueCapability({
      credentials,
      binding: {
        edgeUserId: "edge-user-1",
        edgeDeviceId: "edge-device-1",
        agentId: "company-agent-1",
        streamId: expiredId,
        destination: { hostname: HOSTNAME, port: 443 }
      },
      allowedDestination: { hostname: HOSTNAME, port: 443 },
      nowMs: NOW_MS,
      ttlMs: 100
    });
    expiredDialer.handleFrame(
      { ...expiredSession.session, nowMs: NOW_MS + 100 },
      openFrame(expiredId, expiredCapability)
    );
    expect(expiredConnector.calls).toHaveLength(0);
    expect(lastErrorCode(expiredSession.sent)).toBe(TunnelErrorCode.CAPABILITY_INVALID);

    const forgedConnector = new FakeConnector();
    const forgedDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: forgedConnector, now: () => NOW_MS + 1 });
    const forgedSession = createSession();
    const forgedId = createStreamId();
    const forged = Uint8Array.from(issueOpenCapability(credentials, forgedId));
    forged[forged.byteLength - 1] = (forged[forged.byteLength - 1] ?? 0) ^ 1;
    forgedDialer.handleFrame(forgedSession.session, openFrame(forgedId, forged));
    expect(forgedConnector.calls).toHaveLength(0);
    expect(lastErrorCode(forgedSession.sent)).toBe(TunnelErrorCode.CAPABILITY_INVALID);

    const replayConnector = new FakeConnector();
    const replayDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: replayConnector, now: () => NOW_MS + 1 });
    const replaySession = createSession();
    const replayId = createStreamId();
    const replayFrame = openFrame(replayId, issueOpenCapability(credentials, replayId));
    replayDialer.handleFrame(replaySession.session, replayFrame);
    replayDialer.handleFrame(replaySession.session, replayFrame);
    expect(replayConnector.calls).toHaveLength(1);
    expect(lastErrorCode(replaySession.sent)).toBe(TunnelErrorCode.CAPABILITY_INVALID);
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

  it("慢 TCP 写入端在 drain 前不返还 credit，并把超出本流窗口的 data 隔离关闭", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const { session, sent } = createSession();
    const streamId = createStreamId();

    dialer.handleFrame(session, openFrame(streamId, issueOpenCapability(credentials, streamId)));
    const socket = connector.sockets[0];
    if (socket === undefined) {
      throw new Error("expected TCP socket");
    }
    socket.emit("connect");
    socket.writeResult = false;

    dialer.handleFrame(session, dataFrame(streamId, Uint8Array.of(1, 2, 3, 4)));
    expect(socket.writes).toEqual([Uint8Array.of(1, 2, 3, 4)]);
    expect(sent.map((frame) => frame.type)).toEqual([FrameType.STREAM_OPENED, FrameType.STREAM_CREDIT]);

    socket.emitDrain();
    expect(sent.at(-1)?.type).toBe(FrameType.STREAM_CREDIT);
    expect(decodeFramePayload(sent.at(-1) as TunnelFrame)).toEqual({ bytes: 4 });

    dialer.handleFrame(session, dataFrame(streamId, new Uint8Array(1_024)));
    dialer.handleFrame(session, dataFrame(streamId, Uint8Array.of(9)));
    expect(lastErrorCode(sent)).toBe(TunnelErrorCode.FLOW_CONTROL_VIOLATION);
    expect(socket.destroyCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(0);
  });

  it("以流为单位调度两个用户的慢 WSS 队列，慢 TCP 流不会阻塞另一用户", () => {
    const config = createConfig(2);
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const transport = createSession();
    const firstId = createStreamId();
    const secondId = createStreamId();

    dialer.handleFrame(
      transport.session,
      openFrame(firstId, issueOpenCapability(credentials, firstId, "edge-user-a", "edge-device-a"))
    );
    dialer.handleFrame(
      transport.session,
      openFrame(secondId, issueOpenCapability(credentials, secondId, "edge-user-b", "edge-device-b"))
    );
    const firstSocket = connector.sockets[0];
    const secondSocket = connector.sockets[1];
    if (firstSocket === undefined || secondSocket === undefined) {
      throw new Error("expected two TCP sockets");
    }
    firstSocket.emit("connect");
    secondSocket.emit("connect");

    firstSocket.writeResult = false;
    dialer.handleFrame(transport.session, dataFrame(firstId, Uint8Array.of(10)));
    dialer.handleFrame(transport.session, dataFrame(secondId, Uint8Array.of(11)));
    expect(firstSocket.writes).toEqual([Uint8Array.of(10)]);
    expect(secondSocket.writes).toEqual([Uint8Array.of(11)]);
    expect(
      transport.sent.filter((frame) => frame.type === FrameType.STREAM_CREDIT && sameStreamId(frame.streamId, secondId))
    ).toHaveLength(2);

    dialer.handleFrame(transport.session, creditFrame(firstId, 4));
    dialer.handleFrame(transport.session, creditFrame(secondId, 4));
    transport.setBufferedBytes(config.limits.maxBufferedBytesPerStream);
    firstSocket.emitData(Uint8Array.of(21, 22));
    secondSocket.emitData(Uint8Array.of(31, 32));
    expect(firstSocket.pauseCalls).toBeGreaterThan(1);
    expect(secondSocket.pauseCalls).toBeGreaterThan(1);

    transport.setBufferedBytes(0);
    transport.emitSendAvailability();
    const forwarded = transport.sent.filter((frame) => frame.type === FrameType.STREAM_DATA);
    expect(forwarded).toHaveLength(2);
    expect(forwarded.map((frame) => Array.from(frame.streamId))).toEqual([
      Array.from(firstId),
      Array.from(secondId)
    ]);
    expect(forwarded.map((frame) => Array.from(frame.payload))).toEqual([
      [21, 22],
      [31, 32]
    ]);
  });

  it("在 WSS 高水位近阈值时保留 data 队列并暂停 TCP，直到完整 payload 可发送", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const transport = createSession();
    const streamId = createStreamId();

    dialer.handleFrame(transport.session, openFrame(streamId, issueOpenCapability(credentials, streamId)));
    const socket = connector.sockets[0];
    if (socket === undefined) {
      throw new Error("expected TCP socket");
    }
    socket.emit("connect");
    dialer.handleFrame(transport.session, creditFrame(streamId, 2));

    transport.setBufferedBytes(config.limits.maxBufferedBytesPerStream - 1);
    socket.emitData(Uint8Array.of(41, 42));
    expect(transport.sent.filter((frame) => frame.type === FrameType.STREAM_DATA)).toHaveLength(0);
    expect(socket.pauseCalls).toBeGreaterThan(1);

    transport.setBufferedBytes(config.limits.maxBufferedBytesPerStream - 3);
    transport.emitSendAvailability();
    expect(transport.sent.filter((frame) => frame.type === FrameType.STREAM_DATA)).toHaveLength(1);
  });

  it("组合 lifecycle 与本地队列的两流水位不能超过 agent 聚合上限", () => {
    const config = createConfig(2);
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const transport = createSession();
    const firstId = createStreamId();
    const secondId = createStreamId();

    dialer.handleFrame(transport.session, openFrame(firstId, issueOpenCapability(credentials, firstId, "edge-user-a", "edge-device-a")));
    dialer.handleFrame(transport.session, openFrame(secondId, issueOpenCapability(credentials, secondId, "edge-user-b", "edge-device-b")));
    const firstSocket = connector.sockets[0];
    const secondSocket = connector.sockets[1];
    if (firstSocket === undefined || secondSocket === undefined) {
      throw new Error("expected two TCP sockets");
    }
    firstSocket.emit("connect");
    secondSocket.emit("connect");

    dialer.handleFrame(transport.session, creditFrame(firstId, 1_024));
    firstSocket.emitData(new Uint8Array(1_024));
    expect(transport.sent.filter((frame) => frame.type === FrameType.STREAM_DATA)).toHaveLength(1);

    dialer.handleFrame(transport.session, creditFrame(secondId, 1_024));
    transport.setBufferedBytes(config.limits.maxBufferedBytesPerStream);
    secondSocket.emitData(new Uint8Array(1_024));
    expect(transport.sent.filter((frame) => frame.type === FrameType.STREAM_DATA)).toHaveLength(1);

    dialer.handleFrame(transport.session, dataFrame(secondId, Uint8Array.of(7)));
    expect(lastErrorCode(transport.sent)).toBe(TunnelErrorCode.FLOW_CONTROL_VIOLATION);
    expect(firstSocket.destroyCalls).toBe(0);
    expect(secondSocket.destroyCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(1);
  });

  it("在 TCP 建连前 EOF 会以连接失败清理该流", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const { session, sent } = createSession();
    const streamId = createStreamId();

    dialer.handleFrame(session, openFrame(streamId, issueOpenCapability(credentials, streamId)));
    connector.sockets[0]?.emit("end");

    expect(lastErrorCode(sent)).toBe(TunnelErrorCode.CONNECT_FAILED);
    expect(connector.sockets[0]?.destroyCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(0);
  });

  it("TCP pause、resume 与 WSS send 失败均会隔离关闭当前流", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();

    const pauseConnector = new FakeConnector();
    const pauseDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: pauseConnector, now: () => NOW_MS + 1 });
    const pauseTransport = createSession();
    const pauseId = createStreamId();
    pauseDialer.handleFrame(pauseTransport.session, openFrame(pauseId, issueOpenCapability(credentials, pauseId)));
    const pauseSocket = pauseConnector.sockets[0];
    if (pauseSocket === undefined) {
      throw new Error("expected pause socket");
    }
    pauseSocket.throwOnPause = true;
    pauseSocket.emit("connect");
    expect(lastErrorCode(pauseTransport.sent)).toBe(TunnelErrorCode.CONNECT_FAILED);
    expect(pauseDialer.activeStreamCount).toBe(0);

    const sendConnector = new FakeConnector();
    const sendDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: sendConnector, now: () => NOW_MS + 1 });
    const sendTransport = createSession();
    const sendId = createStreamId();
    sendDialer.handleFrame(sendTransport.session, openFrame(sendId, issueOpenCapability(credentials, sendId)));
    sendTransport.setSendResult(false);
    sendConnector.sockets[0]?.emit("connect");
    expect(lastErrorCode(sendTransport.sent)).toBe(TunnelErrorCode.PEER_DISCONNECTED);
    expect(sendDialer.activeStreamCount).toBe(0);

    const resumeConnector = new FakeConnector();
    const resumeDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: resumeConnector, now: () => NOW_MS + 1 });
    const resumeTransport = createSession();
    const resumeId = createStreamId();
    resumeDialer.handleFrame(resumeTransport.session, openFrame(resumeId, issueOpenCapability(credentials, resumeId)));
    const resumeSocket = resumeConnector.sockets[0];
    if (resumeSocket === undefined) {
      throw new Error("expected resume socket");
    }
    resumeSocket.emit("connect");
    resumeSocket.throwOnResume = true;
    resumeDialer.handleFrame(resumeTransport.session, creditFrame(resumeId, 1));
    expect(lastErrorCode(resumeTransport.sent)).toBe(TunnelErrorCode.CONNECT_FAILED);
    expect(resumeDialer.activeStreamCount).toBe(0);
  });

  it("慢 WSS 下 EOF 保持 close 队列，发送可用后完成关闭", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const transport = createSession();
    const streamId = createStreamId();

    dialer.handleFrame(transport.session, openFrame(streamId, issueOpenCapability(credentials, streamId)));
    const socket = connector.sockets[0];
    if (socket === undefined) {
      throw new Error("expected TCP socket");
    }
    transport.setBufferedBytes(config.limits.maxBufferedBytesPerStream);
    socket.emit("connect");
    socket.emit("end");
    socket.emit("close");
    expect(dialer.activeStreamCount).toBe(1);

    transport.setBufferedBytes(0);
    transport.emitSendAvailability();
    expect(transport.sent.map((frame) => frame.type)).toEqual([
      FrameType.STREAM_OPENED,
      FrameType.STREAM_CLOSE
    ]);
    expect(dialer.activeStreamCount).toBe(0);
  });

  it("远端 close、TCP 写入异常、无效 data 和超额 credit 都只关闭对应流", () => {
    const config = createConfig(2);
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const transport = createSession();
    const firstId = createStreamId();
    const secondId = createStreamId();

    dialer.handleFrame(transport.session, openFrame(firstId, issueOpenCapability(credentials, firstId)));
    dialer.handleFrame(transport.session, openFrame(secondId, issueOpenCapability(credentials, secondId)));
    const firstSocket = connector.sockets[0];
    const secondSocket = connector.sockets[1];
    if (firstSocket === undefined || secondSocket === undefined) {
      throw new Error("expected two TCP sockets");
    }
    firstSocket.emit("connect");
    secondSocket.emit("connect");

    firstSocket.throwOnWrite = true;
    dialer.handleFrame(transport.session, dataFrame(firstId, Uint8Array.of(1)));
    expect(firstSocket.destroyCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(1);

    dialer.handleFrame(transport.session, creditFrame(secondId, 1_025));
    expect(secondSocket.destroyCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(0);

    const remoteCloseConnector = new FakeConnector();
    const remoteCloseDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: remoteCloseConnector, now: () => NOW_MS + 1 });
    const remoteCloseTransport = createSession();
    const remoteCloseId = createStreamId();
    remoteCloseDialer.handleFrame(remoteCloseTransport.session, openFrame(remoteCloseId, issueOpenCapability(credentials, remoteCloseId)));
    const remoteCloseSocket = remoteCloseConnector.sockets[0];
    if (remoteCloseSocket === undefined) {
      throw new Error("expected close socket");
    }
    remoteCloseSocket.emit("connect");
    remoteCloseSocket.throwOnEnd = true;
    remoteCloseDialer.handleFrame(
      remoteCloseTransport.session,
      streamFrame(FrameType.STREAM_CLOSE, remoteCloseId, encodeStreamClosePayload({ code: "NORMAL" }))
    );
    expect(remoteCloseSocket.destroyCalls).toBe(1);
    expect(remoteCloseDialer.activeStreamCount).toBe(0);
  });

  it("异常帧、TCP close 与 WSS 错误帧发送失败均不会遗留本地资源", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();

    const malformedConnector = new FakeConnector();
    const malformedDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: malformedConnector, now: () => NOW_MS + 1 });
    const malformedTransport = createSession();
    const malformedId = createStreamId();
    malformedDialer.handleFrame(malformedTransport.session, openFrame(malformedId, issueOpenCapability(credentials, malformedId)));
    const malformedSocket = malformedConnector.sockets[0];
    if (malformedSocket === undefined) {
      throw new Error("expected malformed socket");
    }
    malformedSocket.emit("connect");
    malformedSocket.emitData(new Uint8Array());
    malformedSocket.emitDrain();
    malformedSocket.throwOnDestroy = true;
    malformedDialer.handleFrame(malformedTransport.session, {
      type: FrameType.STREAM_DATA,
      flags: 0,
      streamId: malformedId,
      payload: new Uint8Array()
    });
    malformedSocket.emitTimeout();
    expect(lastErrorCode(malformedTransport.sent)).toBe(TunnelErrorCode.PROTOCOL_VIOLATION);
    expect(malformedSocket.destroyCalls).toBe(1);
    expect(malformedDialer.activeStreamCount).toBe(0);

    const closeConnector = new FakeConnector();
    const closeDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: closeConnector, now: () => NOW_MS + 1 });
    const closeTransport = createSession();
    const closeId = createStreamId();
    closeDialer.handleFrame(closeTransport.session, openFrame(closeId, issueOpenCapability(credentials, closeId)));
    closeConnector.sockets[0]?.emit("connect");
    closeConnector.sockets[0]?.emit("close");
    expect(lastErrorCode(closeTransport.sent)).toBe(TunnelErrorCode.CONNECT_FAILED);
    expect(closeDialer.activeStreamCount).toBe(0);

    const sendingConnector = new FakeConnector();
    const sendingDialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector: sendingConnector, now: () => NOW_MS + 1 });
    const sendingTransport = createSession();
    const sendingId = createStreamId();
    sendingDialer.handleFrame(sendingTransport.session, openFrame(sendingId, issueOpenCapability(credentials, sendingId)));
    const sendingSocket = sendingConnector.sockets[0];
    if (sendingSocket === undefined) {
      throw new Error("expected sending socket");
    }
    sendingSocket.emit("connect");
    sendingDialer.handleFrame(sendingTransport.session, creditFrame(sendingId, 1));
    sendingTransport.setSendFailure(true);
    sendingSocket.emitData(Uint8Array.of(6));
    expect(sendingSocket.destroyCalls).toBe(1);
    expect(sendingDialer.activeStreamCount).toBe(0);
  });

  it("模拟进程退出时幂等销毁所有 pending 与已连接 TCP 资源", () => {
    const config = createConfig();
    const { identity, credentials } = createServerFixture();
    const connector = new FakeConnector();
    const dialer = new EgressAgentDialer({ config, capabilityServerIdentity: identity, connector, now: () => NOW_MS + 1 });
    const { session, sent } = createSession();
    const connectedId = createStreamId();
    const pendingId = createStreamId();

    dialer.handleFrame(session, openFrame(connectedId, issueOpenCapability(credentials, connectedId)));
    dialer.handleFrame(session, openFrame(pendingId, issueOpenCapability(credentials, pendingId)));
    const connectedSocket = connector.sockets[0];
    const pendingSocket = connector.sockets[1];
    if (connectedSocket === undefined || pendingSocket === undefined) {
      throw new Error("expected both restricted TCP sockets");
    }
    connectedSocket.emit("connect");

    dialer.closeAll();
    dialer.closeAll();
    connectedSocket.emitData(Uint8Array.of(1));
    pendingSocket.emit("connect");

    expect(connectedSocket.destroyCalls).toBe(1);
    expect(pendingSocket.destroyCalls).toBe(1);
    expect(dialer.activeStreamCount).toBe(0);
    expect(sent.filter((frame) => frame.type === FrameType.STREAM_DATA)).toHaveLength(0);
  });
});
