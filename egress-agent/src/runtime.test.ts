import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  connectionFrame,
  createEgressAgentIdentity,
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  createStreamId,
  decodeFrame,
  decodeFramePayload,
  encodeChallengePayload,
  encodeFrame,
  encodeHeartbeatPayload,
  encodeStreamOpenPayload,
  FrameType,
  IdentityKeyRole,
  issueAuthenticationChallenge,
  issueCapability,
  parseEgressAgentConfig,
  streamFrame
} from "@remote-codex/shared";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  calculateReconnectDelayMs,
  EgressAgentRuntime,
  EgressAgentRuntimeError,
  loadEgressAgentConfig,
  type AgentSocket,
  type AgentSocketFactory
} from "./runtime.js";
import type { AgentTcpConnector, AgentTcpSocket } from "./dialer.js";

const initialTlsVerificationSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

class FakeSocket implements AgentSocket {
  public readonly sent: Uint8Array[] = [];
  public readonly closeCalls: Array<readonly [number | undefined, string | undefined]> = [];
  public sendBufferedBytes = 0;
  public throwOnSend = false;
  public throwOnClose = false;
  public throwOnGetSendBufferedBytes = false;
  public throwOnSubscribeSendAvailability = false;
  private readonly sendAvailabilityListeners = new Set<() => void>();
  private openListener: (() => void) | undefined;
  private messageListener: ((data: Uint8Array | undefined, isBinary: boolean) => void) | undefined;
  private closeListener: ((code: number, reason: string) => void) | undefined;
  private errorListener: (() => void) | undefined;

  public send(data: Uint8Array): void {
    if (this.throwOnSend) {
      throw new Error("WSS send failed");
    }
    this.sent.push(Uint8Array.from(data));
  }

  public close(code?: number, reason?: string): void {
    this.closeCalls.push([code, reason]);
    if (this.throwOnClose) {
      throw new Error("WSS close failed");
    }
    this.emitClose(code ?? 1000, reason ?? "");
  }

  public onOpen(listener: () => void): void {
    this.openListener = listener;
  }

  public onMessage(listener: (data: Uint8Array | undefined, isBinary: boolean) => void): void {
    this.messageListener = listener;
  }

  public onClose(listener: (code: number, reason: string) => void): void {
    this.closeListener = listener;
  }

  public onError(listener: () => void): void {
    this.errorListener = listener;
  }

  public getSendBufferedBytes(): number {
    if (this.throwOnGetSendBufferedBytes) {
      throw new Error("WSS buffered amount unavailable");
    }
    return this.sendBufferedBytes;
  }

  public onSendAvailability(listener: () => void): () => void {
    if (this.throwOnSubscribeSendAvailability) {
      throw new Error("WSS availability unavailable");
    }
    this.sendAvailabilityListeners.add(listener);
    return (): void => {
      this.sendAvailabilityListeners.delete(listener);
    };
  }

  public emitOpen(): void {
    this.openListener?.();
  }

  public emitMessage(data: Uint8Array | undefined, isBinary = true): void {
    this.messageListener?.(data, isBinary);
  }

  public emitClose(code = 1006, reason = ""): void {
    const listener = this.closeListener;
    this.closeListener = undefined;
    listener?.(code, reason);
  }

  public emitError(): void {
    this.errorListener?.();
  }

  public emitSendAvailability(): void {
    for (const listener of this.sendAvailabilityListeners) {
      listener();
    }
  }
}

class FakeSocketFactory implements AgentSocketFactory {
  public readonly sockets: FakeSocket[] = [];
  public readonly connections: Array<readonly [string, string]> = [];

  public connect(serverUrl: URL, origin: string): AgentSocket {
    const socket = new FakeSocket();
    this.sockets.push(socket);
    this.connections.push([serverUrl.href, origin]);
    return socket;
  }
}

class FakeTcpSocket implements AgentTcpSocket {
  private readonly listeners = new Map<"connect" | "error" | "end" | "close", () => void>();

  public end(): void {}

  public destroy(): void {}

  public write(): boolean {
    return true;
  }

  public pause(): void {}

  public resume(): void {}

  public setTimeout(): void {}

  public once(event: "connect" | "error" | "end" | "close", listener: () => void): void {
    this.listeners.set(event, listener);
  }

  public on(event: "data", listener: (data: Uint8Array) => void): void;
  public on(event: "drain", listener: () => void): void;
  public on(event: "data" | "drain", listener: ((data: Uint8Array) => void) | (() => void)): void {
    void event;
    void listener;
  }
}

class FakeTcpConnector implements AgentTcpConnector {
  public readonly calls: Array<Readonly<{ hostname: string; port: 443 }>> = [];

  public connect(destination: Readonly<{ hostname: string; port: 443 }>): AgentTcpSocket {
    this.calls.push({ ...destination });
    return new FakeTcpSocket();
  }
}

function createConfig(maxReconnectAttempts = 2) {
  return parseEgressAgentConfig({
    component: "egress-agent",
    agentId: "company-agent-1",
    serverUrl: "wss://tunnel.example.test/tunnel",
    allowedDestination: { hostname: "ai-coding-bj-pub.singularity-ai.com", port: 443 },
    limits: {
      maxConcurrentStreams: 2,
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
      maxReconnectAttempts
    }
  });
}

function createIdentity() {
  const keys = generateKeyPairSync("ed25519");
  const authenticationKey = createIdentityPrivateKey(
    { role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: "agent-key-1" },
    keys.privateKey
  );
  const authenticationIdentity = createEgressAgentIdentity({
    agentId: "company-agent-1",
    authenticationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: "agent-key-1" },
      keys.publicKey
    )
  });
  return { authenticationIdentity, authenticationKey };
}

function createServerCapabilityCredentials() {
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

function latestFrame(socket: FakeSocket) {
  const bytes = socket.sent.at(-1);
  if (bytes === undefined) {
    throw new Error("expected a sent frame");
  }

  return decodeFrame(bytes);
}

function authenticate(socket: FakeSocket, nowMs: number): void {
  socket.emitOpen();
  const registrationFrame = latestFrame(socket);
  expect(registrationFrame.type).toBe(FrameType.REGISTER);
  const challenge = issueAuthenticationChallenge({
    nowMs,
    ttlMs: 100,
    randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
  });
  socket.emitMessage(
    encodeFrame(connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(challenge.payload)))
  );
  expect(latestFrame(socket).type).toBe(FrameType.AUTHENTICATE);
  socket.emitMessage(encodeFrame(connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 0 }))));
}

afterEach(() => {
  vi.useRealTimers();
});

beforeEach(() => {
  delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
});

afterAll(() => {
  if (initialTlsVerificationSetting === undefined) {
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    return;
  }

  process.env.NODE_TLS_REJECT_UNAUTHORIZED = initialTlsVerificationSetting;
});

describe("egress agent persistent WSS session", () => {
  it("loads strictly local configuration and authenticates a first WSS session", () => {
    const config = createConfig();
    const identity = createIdentity();
    const sockets = new FakeSocketFactory();
    const states: string[] = [];
    const runtime = new EgressAgentRuntime({
      config,
      ...identity,
      origin: "https://agent.example.test",
      socketFactory: sockets,
      now: () => 1_000,
      randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
    });
    runtime.subscribeStatus((status) => states.push(status.state));
    runtime.subscribeStatus(() => {
      throw new Error("status observer cannot affect the runtime");
    });

    runtime.start();
    expect(sockets.connections).toEqual([["wss://tunnel.example.test/tunnel", "https://agent.example.test"]]);
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected the first socket");
    }
    authenticate(socket, 1_000);

    expect(runtime.getStatus()).toEqual({ state: "online", reconnectAttempts: 0 });
    expect(states).toEqual(["offline", "connecting", "authenticating", "online"]);
    expect(runtime.getLocalPolicy()).toEqual({
      agentId: "company-agent-1",
      maxConcurrentStreams: 2,
      allowedDestination: { hostname: "ai-coding-bj-pub.singularity-ai.com", port: 443 }
    });
    expect(decodeFramePayload(latestFrame(socket))).toHaveProperty("challengeNonce");

    expect(() => loadEgressAgentConfig('{"component":"egress-agent","secret":"not-for-logs"}')).toThrow(
      EgressAgentRuntimeError
    );
  });

  it("routes only an authenticated, capability-bound stream.open to the local restricted connector", () => {
    const config = createConfig();
    const sockets = new FakeSocketFactory();
    const connector = new FakeTcpConnector();
    const { identity: capabilityServerIdentity, credentials } = createServerCapabilityCredentials();
    const runtime = new EgressAgentRuntime({
      config,
      ...createIdentity(),
      origin: "https://agent.example.test",
      capabilityServerIdentity,
      connector,
      socketFactory: sockets,
      now: () => 1_000,
      randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
    });
    const streamId = createStreamId();
    const capability = issueCapability({
      credentials,
      binding: {
        edgeUserId: "edge-user-1",
        edgeDeviceId: "edge-device-1",
        agentId: config.agentId,
        streamId,
        destination: config.allowedDestination
      },
      allowedDestination: config.allowedDestination,
      nowMs: 1_000,
      ttlMs: 100,
      randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 10)
    });

    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected the first socket");
    }
    authenticate(socket, 1_000);
    socket.emitMessage(
      encodeFrame(
        streamFrame(
          FrameType.STREAM_OPEN,
          streamId,
          encodeStreamOpenPayload({
            hostname: config.allowedDestination.hostname,
            port: 443,
            capability
          })
        )
      )
    );

    expect(connector.calls).toEqual([{ hostname: config.allowedDestination.hostname, port: 443 }]);
    expect(runtime.getStatus()).toEqual({ state: "online", reconnectAttempts: 0 });
  });

  it("向 stream 资源暴露当前 WSS 缓冲和受当前会话约束的发送可用通知", () => {
    const sockets = new FakeSocketFactory();
    const streamResources = {
      closeAll: vi.fn(),
      handleFrame: vi.fn()
    };
    const runtime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: sockets,
      streamResources,
      now: () => 1_000,
      random: () => 1,
      randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
    });

    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    socket.sendBufferedBytes = 512;
    socket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_OPENED, createStreamId(), new Uint8Array()))
    );

    const call = streamResources.handleFrame.mock.calls[0];
    if (call === undefined) {
      throw new Error("expected stream frame dispatch");
    }
    const session = call[0];
    if (session === undefined || typeof session !== "object" || !("getSendBufferedBytes" in session)) {
      throw new Error("expected WSS-aware stream session");
    }
    const getSendBufferedBytes = session.getSendBufferedBytes;
    const subscribeSendAvailability = "subscribeSendAvailability" in session ? session.subscribeSendAvailability : undefined;
    if (typeof getSendBufferedBytes !== "function" || typeof subscribeSendAvailability !== "function") {
      throw new Error("expected WSS backpressure methods");
    }
    expect(getSendBufferedBytes()).toBe(512);

    const available = vi.fn();
    subscribeSendAvailability(available);
    socket.emitSendAvailability();
    expect(available).toHaveBeenCalledTimes(1);

    socket.sendBufferedBytes = -1;
    expect(getSendBufferedBytes()).toBeUndefined();
    socket.throwOnGetSendBufferedBytes = true;
    expect(getSendBufferedBytes()).toBeUndefined();
    socket.throwOnSubscribeSendAvailability = true;
    const unavailable = vi.fn();
    subscribeSendAvailability(unavailable);
    socket.emitSendAvailability();
    expect(unavailable).not.toHaveBeenCalled();

    socket.emitClose();
    socket.emitSendAvailability();
    expect(available).toHaveBeenCalledTimes(2);
  });

  it("将 WSS send、close 和认证随机源异常收敛为受限断线状态", () => {
    vi.useFakeTimers();
    const heartbeatSockets = new FakeSocketFactory();
    const heartbeatResources = { closeAll: vi.fn() };
    const heartbeatRuntime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: heartbeatSockets,
      streamResources: heartbeatResources,
      now: () => 1_000,
      random: () => 1,
      randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
    });
    heartbeatRuntime.start();
    const heartbeatSocket = heartbeatSockets.sockets[0];
    if (heartbeatSocket === undefined) {
      throw new Error("expected heartbeat socket");
    }
    authenticate(heartbeatSocket, 1_000);
    heartbeatSocket.throwOnSend = true;
    vi.advanceTimersByTime(100);
    expect(heartbeatResources.closeAll).toHaveBeenCalledTimes(1);
    expect(heartbeatRuntime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });

    const closeSockets = new FakeSocketFactory();
    const closeResources = { closeAll: vi.fn() };
    const closeRuntime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: closeSockets,
      streamResources: closeResources,
      random: () => 1
    });
    closeRuntime.start();
    const closeSocket = closeSockets.sockets[0];
    if (closeSocket === undefined) {
      throw new Error("expected close socket");
    }
    closeSocket.throwOnClose = true;
    closeSocket.emitError();
    expect(closeResources.closeAll).toHaveBeenCalledTimes(1);
    expect(closeRuntime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });

    const authenticationSockets = new FakeSocketFactory();
    const authenticationRuntime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: authenticationSockets,
      randomBytes: () => {
        throw new Error("random source failed");
      }
    });
    authenticationRuntime.start();
    authenticationSockets.sockets[0]?.emitOpen();
    expect(authenticationRuntime.getStatus()).toEqual({ state: "offline", reconnectAttempts: 0, lastErrorCode: "AUTH_FAILED" });
  });

  it("拒绝冲突依赖，并在重复 start、停止和取消状态订阅时保持单一连接", () => {
    const identity = createIdentity();
    const sockets = new FakeSocketFactory();
    expect(
      () =>
        new EgressAgentRuntime({
          config: createConfig(),
          ...identity,
          origin: "https://agent.example.test",
          socketFactory: sockets,
          streamResources: { closeAll: () => undefined },
          capabilityServerIdentity: createServerCapabilityCredentials().identity
        })
    ).toThrow("AGENT_STREAM_RESOURCES_CONFLICT");
    expect(
      () =>
        new EgressAgentRuntime({
          config: createConfig(),
          ...identity,
          origin: "https://agent.example.test",
          socketFactory: sockets,
          connector: new FakeTcpConnector()
        })
    ).toThrow("AGENT_CAPABILITY_IDENTITY_REQUIRED");

    const streamResources = { closeAll: vi.fn() };
    const runtime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: sockets,
      streamResources
    });
    const states = vi.fn();
    const unsubscribe = runtime.subscribeStatus(states);
    runtime.start();
    runtime.start();
    expect(sockets.sockets).toHaveLength(1);
    unsubscribe();
    sockets.sockets[0]!.throwOnClose = true;
    runtime.stop();
    runtime.stop();
    expect(streamResources.closeAll).toHaveBeenCalledTimes(1);
    expect(runtime.getStatus()).toEqual({ state: "stopped", reconnectAttempts: 0 });
    expect(states).toHaveBeenCalledTimes(2);
    expect(() => runtime.start()).toThrow("AGENT_RUNTIME_STOPPED");
  });

  it("does not retry an authentication failure", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const runtime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: sockets,
      random: () => 1
    });

    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected the first socket");
    }
    socket.emitOpen();
    socket.emitClose(1008, "AUTH_FAILED");
    vi.advanceTimersByTime(10_000);

    expect(runtime.getStatus()).toEqual({ state: "offline", reconnectAttempts: 0, lastErrorCode: "AUTH_FAILED" });
    expect(sockets.sockets).toHaveLength(1);
  });

  it("sends heartbeats, cleans local stream resources, and only accepts a new connection after a disconnect", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const streamResources = { closeAll: vi.fn() };
    const runtime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: sockets,
      streamResources,
      now: () => 1_000,
      random: () => 1,
      randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
    });

    runtime.start();
    const firstSocket = sockets.sockets[0];
    if (firstSocket === undefined) {
      throw new Error("expected the first socket");
    }
    authenticate(firstSocket, 1_000);
    vi.advanceTimersByTime(100);
    expect(latestFrame(firstSocket).type).toBe(FrameType.HEARTBEAT);
    expect(decodeFramePayload(latestFrame(firstSocket))).toEqual({ sequence: 1 });

    firstSocket.emitClose(1008, "HEARTBEAT_TIMEOUT");
    expect(streamResources.closeAll).toHaveBeenCalledTimes(1);
    expect(runtime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_DISCONNECTED" });
    firstSocket.emitMessage(encodeFrame(connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 99 }))));
    expect(runtime.getStatus().state).toBe("backoff");

    vi.advanceTimersByTime(100);
    expect(sockets.sockets).toHaveLength(2);
    expect(sockets.sockets[1]?.sent).toHaveLength(0);
  });

  it("caps jittered exponential backoff and stops reconnecting after the configured retry count", () => {
    const limits = createConfig().limits;
    expect(calculateReconnectDelayMs(1, limits, () => 0)).toBe(50);
    expect(calculateReconnectDelayMs(1, limits, () => 1)).toBe(100);
    expect(calculateReconnectDelayMs(3, limits, () => 0)).toBe(200);
    expect(calculateReconnectDelayMs(4, limits, () => 1)).toBe(400);
    expect(() => calculateReconnectDelayMs(0, limits)).toThrow("AGENT_RECONNECT_ATTEMPT_INVALID");

    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const streamResources = { closeAll: vi.fn() };
    const runtime = new EgressAgentRuntime({
      config: createConfig(2),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: sockets,
      streamResources,
      random: () => 1
    });

    runtime.start();
    sockets.sockets[0]?.emitClose();
    vi.advanceTimersByTime(100);
    sockets.sockets[1]?.emitClose();
    vi.advanceTimersByTime(200);
    sockets.sockets[2]?.emitClose();
    vi.advanceTimersByTime(400);

    expect(sockets.sockets).toHaveLength(3);
    expect(streamResources.closeAll).toHaveBeenCalledTimes(3);
    expect(runtime.getStatus()).toEqual({
      state: "offline",
      reconnectAttempts: 2,
      lastErrorCode: "RECONNECT_LIMIT_EXCEEDED"
    });
  });

  it("rejects mismatched local service identities before attempting a connection", () => {
    const identity = createIdentity();
    const sockets = new FakeSocketFactory();
    const mismatchedIdentity = createEgressAgentIdentity({
      agentId: "other-agent",
      authenticationKey: identity.authenticationIdentity.authenticationKey
    });

    expect(
      () =>
        new EgressAgentRuntime({
          config: createConfig(),
          authenticationIdentity: mismatchedIdentity,
          authenticationKey: identity.authenticationKey,
          origin: "https://agent.example.test",
          socketFactory: sockets
        })
    ).toThrow("AGENT_SERVICE_IDENTITY_INVALID");
    expect(sockets.sockets).toHaveLength(0);
  });

  it("rejects expired challenges and non-binary or stream frames without changing local policy", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const runtime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: sockets,
      now: () => 10_000,
      random: () => 1
    });

    runtime.start();
    const firstSocket = sockets.sockets[0];
    if (firstSocket === undefined) {
      throw new Error("expected the first socket");
    }
    firstSocket.emitOpen();
    const expiredChallenge = issueAuthenticationChallenge({
      nowMs: 800,
      ttlMs: 100,
      randomBytes: (size) => Uint8Array.from({ length: size }, () => 1)
    });
    firstSocket.emitMessage(
      encodeFrame(connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(expiredChallenge.payload)))
    );
    expect(runtime.getStatus()).toEqual({ state: "offline", reconnectAttempts: 0, lastErrorCode: "AUTH_EXPIRED" });

    runtime.start();
    const secondSocket = sockets.sockets[1];
    if (secondSocket === undefined) {
      throw new Error("expected the replacement socket");
    }
    authenticate(secondSocket, 10_000);
    const policy = runtime.getLocalPolicy();
    secondSocket.emitMessage(undefined, false);
    expect(runtime.getStatus()).toEqual({
      state: "backoff",
      reconnectAttempts: 1,
      lastErrorCode: "PROTOCOL_VIOLATION"
    });
    expect(runtime.getLocalPolicy()).toEqual(policy);

    vi.advanceTimersByTime(100);
    const thirdSocket = sockets.sockets[2];
    if (thirdSocket === undefined) {
      throw new Error("expected the next socket");
    }
    authenticate(thirdSocket, 10_000);
    thirdSocket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_OPENED, Uint8Array.from({ length: 16 }, () => 1), new Uint8Array()))
    );
    expect(runtime.getStatus().lastErrorCode).toBe("PROTOCOL_VIOLATION");
  });

  it("仅容忍五秒内的 Server challenge 时钟偏差", () => {
    const localNowMs = 1_000;
    const acceptedSockets = new FakeSocketFactory();
    const acceptedRuntime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: acceptedSockets,
      now: () => localNowMs
    });
    acceptedRuntime.start();
    const acceptedSocket = acceptedSockets.sockets[0];
    if (acceptedSocket === undefined) {
      throw new Error("expected accepted socket");
    }
    acceptedSocket.emitOpen();
    const acceptedChallenge = issueAuthenticationChallenge({
      nowMs: localNowMs + 5_000,
      ttlMs: 100,
      randomBytes: (size) => Uint8Array.from({ length: size }, () => 1)
    });
    acceptedSocket.emitMessage(
      encodeFrame(connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(acceptedChallenge.payload)))
    );
    expect(latestFrame(acceptedSocket).type).toBe(FrameType.AUTHENTICATE);

    const rejectedSockets = new FakeSocketFactory();
    const rejectedRuntime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: rejectedSockets,
      now: () => localNowMs
    });
    rejectedRuntime.start();
    const rejectedSocket = rejectedSockets.sockets[0];
    if (rejectedSocket === undefined) {
      throw new Error("expected rejected socket");
    }
    rejectedSocket.emitOpen();
    const rejectedChallenge = issueAuthenticationChallenge({
      nowMs: localNowMs + 5_001,
      ttlMs: 100,
      randomBytes: (size) => Uint8Array.from({ length: size }, () => 1)
    });
    rejectedSocket.emitMessage(
      encodeFrame(connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(rejectedChallenge.payload)))
    );
    expect(rejectedRuntime.getStatus()).toEqual({ state: "offline", reconnectAttempts: 0, lastErrorCode: "AUTH_EXPIRED" });
  });

  it("fails closed when stream cleanup fails and stop cancels all future retries", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const failingResources = { closeAll: vi.fn(() => { throw new Error("cleanup failed"); }) };
    const runtime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: sockets,
      streamResources: failingResources,
      random: () => 1
    });

    runtime.start();
    sockets.sockets[0]?.emitClose();
    expect(runtime.getStatus()).toEqual({
      state: "offline",
      reconnectAttempts: 0,
      lastErrorCode: "AGENT_STREAM_CLEANUP_FAILED"
    });

    const healthyResources = { closeAll: vi.fn() };
    const retryingSockets = new FakeSocketFactory();
    const retryingRuntime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: retryingSockets,
      streamResources: healthyResources,
      random: () => 1
    });
    retryingRuntime.start();
    retryingSockets.sockets[0]?.emitClose();
    retryingRuntime.stop();
    vi.advanceTimersByTime(10_000);

    expect(healthyResources.closeAll).toHaveBeenCalledTimes(2);
    expect(retryingRuntime.getStatus()).toEqual({ state: "stopped", reconnectAttempts: 1 });
    expect(retryingSockets.sockets).toHaveLength(1);
    expect(() => retryingRuntime.start()).toThrow("AGENT_RUNTIME_STOPPED");
  });

  it("treats socket creation and jitter configuration errors as bounded failures", () => {
    vi.useFakeTimers();
    const throwingFactory: AgentSocketFactory = {
      connect: () => {
        throw new Error("connection failed");
      }
    };
    const runtime = new EgressAgentRuntime({
      config: createConfig(1),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: throwingFactory,
      random: () => 1
    });

    runtime.start();
    expect(runtime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });
    vi.advanceTimersByTime(100);
    expect(runtime.getStatus()).toEqual({ state: "offline", reconnectAttempts: 1, lastErrorCode: "RECONNECT_LIMIT_EXCEEDED" });
    expect(() => calculateReconnectDelayMs(1, createConfig().limits, () => -0.1)).toThrow(
      "AGENT_RECONNECT_JITTER_INVALID"
    );
    expect(
      () =>
        new EgressAgentRuntime({
          config: createConfig(),
          ...createIdentity(),
          origin: "http://agent.example.test",
          socketFactory: new FakeSocketFactory()
        })
    ).toThrow("AGENT_ORIGIN_INVALID");
  });

  it("refuses disabled TLS verification before creating a WSS connection", () => {
    const sockets = new FakeSocketFactory();
    const runtime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      socketFactory: sockets
    });
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    expect(() => runtime.start()).toThrow("CONFIG_TLS_VERIFICATION_DISABLED");
    expect(sockets.sockets).toHaveLength(0);
  });

  it("agent 不创建 TCP 入站监听器，也不会记录 capability 或认证材料", () => {
    const runtimeSource = readFileSync(fileURLToPath(new URL("./runtime.ts", import.meta.url)), "utf8");
    const dialerSource = readFileSync(fileURLToPath(new URL("./dialer.ts", import.meta.url)), "utf8");
    expect(`${runtimeSource}\n${dialerSource}`).not.toMatch(
      /\b(?:createServer\s*\(|\.listen\s*\(|console\.(?:log|debug|info|warn|error)|logger\.|process\.(?:stdout|stderr)\.write\s*\()/u
    );

    const sockets = new FakeSocketFactory();
    const connector = new FakeTcpConnector();
    const { identity: capabilityServerIdentity, credentials } = createServerCapabilityCredentials();
    const runtime = new EgressAgentRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://agent.example.test",
      capabilityServerIdentity,
      connector,
      socketFactory: sockets,
      now: () => 1_000,
      randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
    });
    const consoleSpies = [
      vi.spyOn(console, "log"),
      vi.spyOn(console, "debug"),
      vi.spyOn(console, "info"),
      vi.spyOn(console, "warn"),
      vi.spyOn(console, "error")
    ];
    const outputSpies = [vi.spyOn(process.stdout, "write"), vi.spyOn(process.stderr, "write")];

    try {
      const streamId = createStreamId();
      const capability = issueCapability({
        credentials,
        binding: {
          edgeUserId: "edge-user-never-log",
          edgeDeviceId: "edge-device-never-log",
          agentId: createConfig().agentId,
          streamId,
          destination: createConfig().allowedDestination
        },
        allowedDestination: createConfig().allowedDestination,
        nowMs: 1_000,
        ttlMs: 100,
        randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 10)
      });

      runtime.start();
      const socket = sockets.sockets[0];
      if (socket === undefined) {
        throw new Error("expected WSS socket");
      }
      authenticate(socket, 1_000);
      socket.emitMessage(
        encodeFrame(
          streamFrame(
            FrameType.STREAM_OPEN,
            streamId,
            encodeStreamOpenPayload({
              hostname: createConfig().allowedDestination.hostname,
              port: 443,
              capability
            })
          )
        )
      );

      expect(connector.calls).toEqual([{ hostname: createConfig().allowedDestination.hostname, port: 443 }]);
      expect(consoleSpies.every((spy) => spy.mock.calls.length === 0)).toBe(true);
      expect(outputSpies.every((spy) => spy.mock.calls.length === 0)).toBe(true);
    } finally {
      for (const spy of consoleSpies) {
        spy.mockRestore();
      }
      for (const spy of outputSpies) {
        spy.mockRestore();
      }
      runtime.stop();
    }
  });
});
