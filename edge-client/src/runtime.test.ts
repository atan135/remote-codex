import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  CapabilityReplayProtector,
  connectionFrame,
  createEdgeDeviceIdentity,
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningIdentity,
  createStreamId,
  decodeFrame,
  decodeFramePayload,
  decodeStreamOpenPayload,
  encodeChallengePayload,
  encodeFrame,
  encodeHeartbeatPayload,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
  encodeStreamErrorPayload,
  encodeStreamOpenPayload,
  FrameType,
  IdentityKeyRole,
  issueAuthenticationChallenge,
  parseEdgeClientConfig,
  streamFrame,
  verifyCapability,
  type EdgeClientConfig,
  type ServerSigningIdentity,
  type ValidatedDestination
} from "@remote-codex/shared";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  calculateEdgeReconnectDelayMs,
  edgeOriginForServerUrl,
  EdgeClientRuntime,
  EdgeClientRuntimeError,
  loadEdgeClientConfig,
  type EdgeSocket,
  type EdgeSocketFactory
} from "./runtime.js";
import type { EdgeStreamEvent, EdgeStreamEventListener } from "./connect-proxy.js";

const initialTlsVerificationSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

class FakeSocket implements EdgeSocket {
  public readonly sent: Uint8Array[] = [];
  public readonly closeCalls: Array<readonly [number | undefined, string | undefined]> = [];
  public sendBufferedBytes = 0;
  public throwOnSend = false;
  public throwOnClose = false;
  public deferClose = false;
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
    if (this.deferClose) {
      return;
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

class FakeSocketFactory implements EdgeSocketFactory {
  public readonly sockets: FakeSocket[] = [];
  public readonly connections: Array<Readonly<{ serverUrl: string; origin: string }>> = [];

  public connect(serverUrl: URL, origin: string): EdgeSocket {
    const socket = new FakeSocket();
    this.sockets.push(socket);
    this.connections.push({ serverUrl: serverUrl.href, origin });
    return socket;
  }
}

function createConfig(maxReconnectAttempts = 2): EdgeClientConfig {
  return parseEdgeClientConfig({
    component: "edge-client",
    edgeUserId: "edge-user-1",
    edgeDeviceId: "edge-device-1",
    serverUrl: "wss://tunnel.example.test/tunnel",
    listenHost: "127.0.0.1",
    listenPort: 8787,
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
    { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-key-1" },
    keys.privateKey
  );
  const authenticationIdentity = createEdgeDeviceIdentity({
    edgeUserId: "edge-user-1",
    edgeDeviceId: "edge-device-1",
    authenticationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-key-1" },
      keys.publicKey
    )
  });
  return { authenticationIdentity, authenticationKey };
}

function createServerIdentity(): ServerSigningIdentity {
  const keys = generateKeyPairSync("ed25519");
  return createServerSigningIdentity({
    serverId: "server-1",
    capabilityVerificationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: "server-key-1" },
      keys.publicKey
    )
  });
}

function latestFrame(socket: FakeSocket) {
  const bytes = socket.sent.at(-1);
  if (bytes === undefined) {
    throw new Error("expected a sent frame");
  }
  return decodeFrame(bytes);
}

function framesOfType(socket: FakeSocket, type: typeof FrameType[keyof typeof FrameType]) {
  return socket.sent.map((bytes) => decodeFrame(bytes)).filter((frame) => frame.type === type);
}

function authenticate(socket: FakeSocket, nowMs: number): void {
  socket.emitOpen();
  const registration = latestFrame(socket);
  expect(registration.type).toBe(FrameType.REGISTER);
  expect(decodeFramePayload(registration)).toMatchObject({ role: "edge-client", peerId: "edge-device-1" });
  const challenge = issueAuthenticationChallenge({
    nowMs,
    ttlMs: 100,
    randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
  });
  socket.emitMessage(encodeFrame(connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(challenge.payload))));
  expect(latestFrame(socket).type).toBe(FrameType.AUTHENTICATE);
  socket.emitMessage(encodeFrame(connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 0 }))));
}

function openStream(
  runtime: EdgeClientRuntime,
  destination: ValidatedDestination = createConfig().allowedDestination
): { readonly events: EdgeStreamEvent[]; readonly control: ReturnType<EdgeClientRuntime["open"]> } {
  const events: EdgeStreamEvent[] = [];
  const listener: EdgeStreamEventListener = (event) => events.push(event);
  return { events, control: runtime.open(destination, listener) };
}

function latestOpenStreamId(socket: FakeSocket): Uint8Array {
  const frame = framesOfType(socket, FrameType.STREAM_OPEN).at(-1);
  if (frame === undefined) {
    throw new Error("expected STREAM_OPEN");
  }
  return frame.streamId;
}

function emitOpened(socket: FakeSocket, streamId: Uint8Array): void {
  socket.emitMessage(encodeFrame(streamFrame(FrameType.STREAM_OPENED, streamId, new Uint8Array())));
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

describe("edge persistent WSS session", () => {
  it("使用本地配置注册 edge 身份、签名 challenge，并发送有界心跳", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const states: string[] = [];
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000,
      randomBytes: (size) => Uint8Array.from({ length: size }, (_, index) => index + 1)
    });
    runtime.subscribeStatus((status) => states.push(status.state));
    runtime.subscribeStatus(() => {
      throw new Error("observer failure");
    });

    runtime.start();
    expect(sockets.connections).toEqual([{
      serverUrl: "wss://tunnel.example.test/tunnel",
      origin: "https://tunnel.example.test"
    }]);
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected first WSS socket");
    }
    authenticate(socket, 1_000);

    expect(runtime.getStatus()).toEqual({ state: "online", reconnectAttempts: 0 });
    expect(states).toEqual(["offline", "connecting", "authenticating", "online"]);
    expect(runtime.getLocalPolicy()).toEqual({
      edgeUserId: "edge-user-1",
      edgeDeviceId: "edge-device-1",
      maxConcurrentStreams: 2,
      allowedDestination: { hostname: "ai-coding-bj-pub.singularity-ai.com", port: 443 }
    });

    vi.advanceTimersByTime(100);
    expect(latestFrame(socket).type).toBe(FrameType.HEARTBEAT);
    expect(decodeFramePayload(latestFrame(socket))).toEqual({ sequence: 1 });
  });

  it("edge open 只携带固定无授权哨兵，server capability 校验无法通过", () => {
    const sockets = new FakeSocketFactory();
    const config = createConfig();
    const runtime = new EdgeClientRuntime({ config, ...createIdentity(), socketFactory: sockets, now: () => 1_000 });
    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);

    openStream(runtime, config.allowedDestination);
    const open = framesOfType(socket, FrameType.STREAM_OPEN).at(-1);
    if (open === undefined) {
      throw new Error("expected STREAM_OPEN");
    }
    const payload = decodeStreamOpenPayload(open.payload);
    expect(payload.capability).toEqual(Uint8Array.of(0));
    expect(
      verifyCapability({
        capability: payload.capability,
        serverIdentity: createServerIdentity(),
        expectedBinding: {
          edgeUserId: config.edgeUserId,
          edgeDeviceId: config.edgeDeviceId,
          agentId: "agent-1",
          streamId: open.streamId,
          destination: config.allowedDestination
        },
        allowedDestination: config.allowedDestination,
        replayProtector: new CapabilityReplayProtector(),
        nowMs: 1_000
      })
    ).toMatchObject({ ok: false, errorCode: "CAPABILITY_INVALID" });
  });

  it("在 server opened 与 credit 后双向转发 data，并按接收进度归还 credit", () => {
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({ config: createConfig(), ...createIdentity(), socketFactory: sockets, now: () => 1_000 });
    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const stream = openStream(runtime);
    const streamId = latestOpenStreamId(socket);

    emitOpened(socket, streamId);
    expect(stream.events).toEqual([{ type: "opened" }]);
    const initialCredit = framesOfType(socket, FrameType.STREAM_CREDIT).at(-1);
    expect(initialCredit).toBeDefined();
    expect(decodeFramePayload(initialCredit!)).toEqual({ bytes: 1_024 });

    socket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_CREDIT, streamId, encodeStreamCreditPayload({ bytes: 1_024 })))
    );
    expect(stream.control.send(Uint8Array.from(Buffer.from("request-bytes")))).toBe(true);
    const outgoing = framesOfType(socket, FrameType.STREAM_DATA).at(-1);
    expect(Buffer.from(outgoing?.payload ?? new Uint8Array())).toEqual(Buffer.from("request-bytes"));

    socket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_DATA, streamId, Uint8Array.from(Buffer.from("response-bytes"))))
    );
    expect(stream.events).toContainEqual({ type: "data", payload: Uint8Array.from(Buffer.from("response-bytes")) });
    const replenishment = framesOfType(socket, FrameType.STREAM_CREDIT).at(-1);
    expect(decodeFramePayload(replenishment!)).toEqual({ bytes: "response-bytes".length });

    stream.control.close();
    expect(framesOfType(socket, FrameType.STREAM_CLOSE)).toHaveLength(1);
    stream.control.close();
    expect(framesOfType(socket, FrameType.STREAM_CLOSE)).toHaveLength(1);
  });

  it("保持 WSS 与本地接收两侧背压，并在可写后只恢复自己的 stream", () => {
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({ config: createConfig(), ...createIdentity(), socketFactory: sockets, now: () => 1_000 });
    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const stream = openStream(runtime);
    const streamId = latestOpenStreamId(socket);
    emitOpened(socket, streamId);
    socket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_CREDIT, streamId, encodeStreamCreditPayload({ bytes: 512 })))
    );

    socket.sendBufferedBytes = 1_024;
    expect(stream.control.send(Uint8Array.from(Buffer.from("queued")))).toBe(false);
    expect(framesOfType(socket, FrameType.STREAM_DATA)).toHaveLength(0);
    socket.sendBufferedBytes = 0;
    socket.emitSendAvailability();
    expect(Buffer.from(framesOfType(socket, FrameType.STREAM_DATA)[0]?.payload ?? new Uint8Array()).toString()).toBe("queued");
    expect(stream.events).toContainEqual({ type: "writable" });

    stream.control.pauseIncoming();
    socket.emitMessage(encodeFrame(streamFrame(FrameType.STREAM_DATA, streamId, Uint8Array.of(9, 8, 7))));
    const creditCountWhilePaused = framesOfType(socket, FrameType.STREAM_CREDIT).length;
    stream.control.resumeIncoming();
    expect(framesOfType(socket, FrameType.STREAM_CREDIT)).toHaveLength(creditCountWhilePaused + 1);
  });

  it("离线、目标不匹配和并发额度耗尽都以确定性局部失败结束", () => {
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: new FakeSocketFactory(),
      now: () => 1_000
    });
    const offline = openStream(runtime);
    expect(offline.events).toEqual([{ type: "error" }]);
    expect(offline.control.send(Uint8Array.of(1))).toBe(false);

    const sockets = new FakeSocketFactory();
    const online = new EdgeClientRuntime({ config: createConfig(), ...createIdentity(), socketFactory: sockets, now: () => 1_000 });
    online.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const denied = openStream(online, { hostname: "other.example.test", port: 443 });
    expect(denied.events).toEqual([{ type: "rejected" }]);
    openStream(online);
    openStream(online);
    const overflow = openStream(online);
    expect(overflow.events).toEqual([{ type: "rejected" }]);
    expect(online.activeStreamCount).toBe(2);
  });

  it("未知或重复 stream ID 会关闭当前会话并且不向其他 CONNECT listener 写入", () => {
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000,
      random: () => 1
    });
    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const first = openStream(runtime);
    const second = openStream(runtime);
    const firstId = framesOfType(socket, FrameType.STREAM_OPEN)[0]?.streamId;
    if (firstId === undefined) {
      throw new Error("expected first stream ID");
    }
    emitOpened(socket, firstId);
    socket.emitMessage(encodeFrame(streamFrame(FrameType.STREAM_DATA, createStreamId(), Uint8Array.of(1))));

    expect(socket.closeCalls).toHaveLength(1);
    expect(first.events).toContainEqual({ type: "error" });
    expect(second.events).toEqual([{ type: "error" }]);
    expect(runtime.activeStreamCount).toBe(0);
    expect(runtime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "PROTOCOL_VIOLATION" });
  });

  it("旧 WSS 会话的帧不会触碰重连后新 stream，断线会清理 pending 与 opened 映射", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000,
      random: () => 1
    });
    runtime.start();
    const firstSocket = sockets.sockets[0];
    if (firstSocket === undefined) {
      throw new Error("expected first WSS socket");
    }
    authenticate(firstSocket, 1_000);
    const pending = openStream(runtime);
    const opened = openStream(runtime);
    const openedId = framesOfType(firstSocket, FrameType.STREAM_OPEN)[1]?.streamId;
    if (openedId === undefined) {
      throw new Error("expected opened stream ID");
    }
    emitOpened(firstSocket, openedId);
    firstSocket.emitClose(1006, "");
    expect(pending.events).toEqual([{ type: "error" }]);
    expect(opened.events).toContainEqual({ type: "error" });
    expect(runtime.activeStreamCount).toBe(0);

    vi.advanceTimersByTime(100);
    const secondSocket = sockets.sockets[1];
    if (secondSocket === undefined) {
      throw new Error("expected replacement WSS socket");
    }
    authenticate(secondSocket, 1_000);
    const current = openStream(runtime);
    const currentId = latestOpenStreamId(secondSocket);
    firstSocket.emitMessage(encodeFrame(streamFrame(FrameType.STREAM_OPENED, currentId, new Uint8Array())));
    expect(current.events).toEqual([]);
    emitOpened(secondSocket, currentId);
    expect(current.events).toEqual([{ type: "opened" }]);
  });

  it("只接受各 stream 合法阶段的 rejected、error 与 close，并拒绝重复 opened 或 opened 前 data", () => {
    const rejectedSockets = new FakeSocketFactory();
    const rejectedRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: rejectedSockets,
      now: () => 1_000
    });
    rejectedRuntime.start();
    const rejectedSocket = rejectedSockets.sockets[0];
    if (rejectedSocket === undefined) {
      throw new Error("expected rejected socket");
    }
    authenticate(rejectedSocket, 1_000);
    const rejected = openStream(rejectedRuntime);
    const rejectedId = latestOpenStreamId(rejectedSocket);
    rejectedSocket.emitMessage(
      encodeFrame(
        streamFrame(
          FrameType.STREAM_REJECTED,
          rejectedId,
          encodeStreamErrorPayload({ code: "DESTINATION_REJECTED" })
        )
      )
    );
    expect(rejected.events).toEqual([{ type: "rejected" }]);

    const terminalSockets = new FakeSocketFactory();
    const terminalRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: terminalSockets,
      now: () => 1_000
    });
    terminalRuntime.start();
    const terminalSocket = terminalSockets.sockets[0];
    if (terminalSocket === undefined) {
      throw new Error("expected terminal socket");
    }
    authenticate(terminalSocket, 1_000);
    const errored = openStream(terminalRuntime);
    const erroredId = latestOpenStreamId(terminalSocket);
    emitOpened(terminalSocket, erroredId);
    terminalSocket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_ERROR, erroredId, encodeStreamErrorPayload({ code: "CONNECT_FAILED" })))
    );
    expect(errored.events).toContainEqual({ type: "error" });

    const closeSockets = new FakeSocketFactory();
    const closeRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: closeSockets,
      now: () => 1_000
    });
    closeRuntime.start();
    const closeSocket = closeSockets.sockets[0];
    if (closeSocket === undefined) {
      throw new Error("expected close socket");
    }
    authenticate(closeSocket, 1_000);
    const closed = openStream(closeRuntime);
    const closedId = latestOpenStreamId(closeSocket);
    emitOpened(closeSocket, closedId);
    closeSocket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_CLOSE, closedId, encodeStreamClosePayload({ code: "NORMAL" })))
    );
    expect(closed.events).toContainEqual({ type: "close" });

    const invalidSockets = new FakeSocketFactory();
    const invalidRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: invalidSockets,
      now: () => 1_000,
      random: () => 1
    });
    invalidRuntime.start();
    const invalidSocket = invalidSockets.sockets[0];
    if (invalidSocket === undefined) {
      throw new Error("expected invalid socket");
    }
    authenticate(invalidSocket, 1_000);
    const duplicate = openStream(invalidRuntime);
    const duplicateId = latestOpenStreamId(invalidSocket);
    emitOpened(invalidSocket, duplicateId);
    emitOpened(invalidSocket, duplicateId);
    expect(duplicate.events).toContainEqual({ type: "error" });
    expect(invalidRuntime.getStatus().lastErrorCode).toBe("PROTOCOL_VIOLATION");
  });

  it("本地无效 data、超出预算、listener 异常和可选 WSS 通知异常都只影响所属 stream", () => {
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({ config: createConfig(), ...createIdentity(), socketFactory: sockets, now: () => 1_000 });
    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const empty = openStream(runtime);
    const emptyId = latestOpenStreamId(socket);
    emitOpened(socket, emptyId);
    expect(empty.control.send(new Uint8Array())).toBe(false);
    expect(empty.events).toContainEqual({ type: "error" });
    expect(framesOfType(socket, FrameType.STREAM_CLOSE)).toHaveLength(1);

    const oversized = openStream(runtime);
    const oversizedId = latestOpenStreamId(socket);
    emitOpened(socket, oversizedId);
    expect(oversized.control.send(new Uint8Array(1_025))).toBe(false);
    expect(oversized.events).toContainEqual({ type: "error" });

    const throwing = runtime.open(createConfig().allowedDestination, () => {
      throw new Error("local listener failed");
    });
    const throwingId = latestOpenStreamId(socket);
    emitOpened(socket, throwingId);
    expect(runtime.activeStreamCount).toBe(0);
    throwing.close();

    const optionalSockets = new FakeSocketFactory();
    const optionalRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: optionalSockets,
      now: () => 1_000
    });
    optionalRuntime.start();
    const optionalSocket = optionalSockets.sockets[0];
    if (optionalSocket === undefined) {
      throw new Error("expected optional socket");
    }
    optionalSocket.emitOpen();
    const challenge = issueAuthenticationChallenge({ nowMs: 1_000, ttlMs: 100 });
    optionalSocket.emitMessage(encodeFrame(connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(challenge.payload))));
    optionalSocket.throwOnSubscribeSendAvailability = true;
    optionalSocket.emitMessage(encodeFrame(connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 0 }))));
    expect(optionalRuntime.getStatus().state).toBe("online");
  });

  it("认证失败、非二进制帧、认证超时、重连上限和 TLS 禁用均保持失败关闭", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({ config: createConfig(1), ...createIdentity(), socketFactory: sockets, random: () => 1 });
    runtime.start();
    const first = sockets.sockets[0];
    if (first === undefined) {
      throw new Error("expected first WSS socket");
    }
    first.emitOpen();
    first.emitMessage(undefined, false);
    expect(runtime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "PROTOCOL_VIOLATION" });
    vi.advanceTimersByTime(100);
    expect(sockets.sockets).toHaveLength(2);
    sockets.sockets[1]?.emitClose();
    expect(runtime.getStatus()).toEqual({ state: "offline", reconnectAttempts: 1, lastErrorCode: "RECONNECT_LIMIT_EXCEEDED" });

    const authTimeoutSockets = new FakeSocketFactory();
    const authTimeout = new EdgeClientRuntime({ config: createConfig(), ...createIdentity(), socketFactory: authTimeoutSockets, random: () => 1 });
    authTimeout.start();
    vi.advanceTimersByTime(100);
    expect(authTimeout.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "AUTH_TIMEOUT" });

    const tlsSockets = new FakeSocketFactory();
    const tlsRuntime = new EdgeClientRuntime({ config: createConfig(), ...createIdentity(), socketFactory: tlsSockets });
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    expect(() => tlsRuntime.start()).toThrow("CONFIG_TLS_VERIFICATION_DISABLED");
    expect(tlsSockets.sockets).toHaveLength(0);
  });

  it("重新认证成功后重置连续重连计数，后续可恢复断线不会耗尽上限", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(1),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000,
      random: () => 1
    });

    runtime.start();
    sockets.sockets[0]?.emitClose();
    expect(runtime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_DISCONNECTED" });

    vi.advanceTimersByTime(100);
    const recovered = sockets.sockets[1];
    if (recovered === undefined) {
      throw new Error("expected replacement WSS socket");
    }
    authenticate(recovered, 1_000);
    expect(runtime.getStatus()).toEqual({ state: "online", reconnectAttempts: 0 });

    recovered.emitClose();
    expect(runtime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_DISCONNECTED" });
    vi.advanceTimersByTime(100);
    expect(sockets.sockets).toHaveLength(3);
  });

  it("连接工厂、注册发送、challenge、心跳发送与 socket error 都收敛为有界断线", () => {
    vi.useFakeTimers();
    const throwingFactory: EdgeSocketFactory = {
      connect: () => {
        throw new Error("connection failed");
      }
    };
    const factoryRuntime = new EdgeClientRuntime({
      config: createConfig(1),
      ...createIdentity(),
      socketFactory: throwingFactory,
      random: () => 1
    });
    factoryRuntime.start();
    expect(factoryRuntime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });

    const registrationSockets = new FakeSocketFactory();
    const registrationRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: registrationSockets,
      random: () => 1
    });
    registrationRuntime.start();
    const registrationSocket = registrationSockets.sockets[0];
    if (registrationSocket === undefined) {
      throw new Error("expected registration socket");
    }
    registrationSocket.throwOnSend = true;
    registrationSocket.emitOpen();
    expect(registrationRuntime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });

    const expiredSockets = new FakeSocketFactory();
    const expiredRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: expiredSockets,
      now: () => 1_000,
      random: () => 1
    });
    expiredRuntime.start();
    const expiredSocket = expiredSockets.sockets[0];
    if (expiredSocket === undefined) {
      throw new Error("expected expired socket");
    }
    expiredSocket.emitOpen();
    const expired = issueAuthenticationChallenge({ nowMs: 800, ttlMs: 100 });
    expiredSocket.emitMessage(encodeFrame(connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(expired.payload))));
    expect(expiredRuntime.getStatus()).toEqual({ state: "offline", reconnectAttempts: 0, lastErrorCode: "AUTH_EXPIRED" });

    const heartbeatSockets = new FakeSocketFactory();
    const heartbeatRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: heartbeatSockets,
      now: () => 1_000,
      random: () => 1
    });
    heartbeatRuntime.start();
    const heartbeatSocket = heartbeatSockets.sockets[0];
    if (heartbeatSocket === undefined) {
      throw new Error("expected heartbeat socket");
    }
    authenticate(heartbeatSocket, 1_000);
    heartbeatSocket.throwOnSend = true;
    vi.advanceTimersByTime(100);
    expect(heartbeatRuntime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });

    const errorSockets = new FakeSocketFactory();
    const errorRuntime = new EdgeClientRuntime({ config: createConfig(), ...createIdentity(), socketFactory: errorSockets, random: () => 1 });
    errorRuntime.start();
    errorSockets.sockets[0]?.emitError();
    expect(errorRuntime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });
  });

  it("在认证、开流和 credit 等待中的发送失败均关闭当前会话和仅属于它的 stream", () => {
    const challengeSockets = new FakeSocketFactory();
    const challengeRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: challengeSockets,
      now: () => 1_000,
      random: () => 1
    });
    challengeRuntime.start();
    const challengeSocket = challengeSockets.sockets[0];
    if (challengeSocket === undefined) {
      throw new Error("expected challenge socket");
    }
    challengeSocket.emitOpen();
    challengeSocket.throwOnSend = true;
    const challenge = issueAuthenticationChallenge({ nowMs: 1_000, ttlMs: 100 });
    challengeSocket.emitMessage(encodeFrame(connectionFrame(FrameType.CHALLENGE, encodeChallengePayload(challenge.payload))));
    expect(challengeRuntime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });

    const openingSockets = new FakeSocketFactory();
    const openingRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: openingSockets,
      now: () => 1_000,
      random: () => 1
    });
    openingRuntime.start();
    const openingSocket = openingSockets.sockets[0];
    if (openingSocket === undefined) {
      throw new Error("expected opening socket");
    }
    authenticate(openingSocket, 1_000);
    openingSocket.throwOnSend = true;
    const opening = openStream(openingRuntime);
    expect(opening.events).toEqual([{ type: "error" }]);
    expect(openingRuntime.activeStreamCount).toBe(0);

    const creditSockets = new FakeSocketFactory();
    const creditRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: creditSockets,
      now: () => 1_000,
      random: () => 1
    });
    creditRuntime.start();
    const creditSocket = creditSockets.sockets[0];
    if (creditSocket === undefined) {
      throw new Error("expected credit socket");
    }
    authenticate(creditSocket, 1_000);
    const credit = openStream(creditRuntime);
    const creditId = latestOpenStreamId(creditSocket);
    creditSocket.throwOnSend = true;
    emitOpened(creditSocket, creditId);
    expect(credit.events).toContainEqual({ type: "error" });
    expect(creditRuntime.activeStreamCount).toBe(0);
  });

  it("本地 control.close 的 WSS 发送失败会收敛整个当前会话，而非遗留其他 stream", () => {
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000,
      random: () => 1
    });
    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const opened = openStream(runtime);
    const pending = openStream(runtime);
    const openedId = framesOfType(socket, FrameType.STREAM_OPEN)[0]?.streamId;
    if (openedId === undefined) {
      throw new Error("expected opened stream ID");
    }
    emitOpened(socket, openedId);
    socket.throwOnSend = true;

    opened.control.close();

    expect(socket.closeCalls).toHaveLength(1);
    expect(opened.events).toContainEqual({ type: "error" });
    expect(pending.events).toEqual([{ type: "error" }]);
    expect(runtime.activeStreamCount).toBe(0);
    expect(runtime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });
    expect(opened.control.send(Uint8Array.of(1))).toBe(false);
    expect(pending.control.send(Uint8Array.of(2))).toBe(false);
  });

  it("异步 WSS close 回调前立即拒绝新流，且旧会话不能影响重连后的映射", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000,
      random: () => 1
    });
    runtime.start();
    const firstSocket = sockets.sockets[0];
    if (firstSocket === undefined) {
      throw new Error("expected first WSS socket");
    }
    authenticate(firstSocket, 1_000);
    const opened = openStream(runtime);
    const pending = openStream(runtime);
    const openedId = framesOfType(firstSocket, FrameType.STREAM_OPEN)[0]?.streamId;
    if (openedId === undefined) {
      throw new Error("expected opened stream ID");
    }
    emitOpened(firstSocket, openedId);
    const openCountBeforeFailure = framesOfType(firstSocket, FrameType.STREAM_OPEN).length;
    firstSocket.deferClose = true;
    firstSocket.throwOnSend = true;

    opened.control.close();

    expect(runtime.getStatus()).toEqual({ state: "closing", reconnectAttempts: 0, lastErrorCode: "WSS_CONNECTION_FAILED" });
    expect(opened.events).toContainEqual({ type: "error" });
    expect(pending.events).toEqual([{ type: "error" }]);
    expect(runtime.activeStreamCount).toBe(0);
    const duringClosing = openStream(runtime);
    expect(duringClosing.events).toEqual([{ type: "error" }]);
    expect(framesOfType(firstSocket, FrameType.STREAM_OPEN)).toHaveLength(openCountBeforeFailure);
    vi.advanceTimersByTime(1_000);
    expect(framesOfType(firstSocket, FrameType.HEARTBEAT)).toHaveLength(0);
    expect(sockets.sockets).toHaveLength(1);

    firstSocket.emitClose();
    expect(runtime.getStatus()).toEqual({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });
    vi.advanceTimersByTime(100);
    const secondSocket = sockets.sockets[1];
    if (secondSocket === undefined) {
      throw new Error("expected replacement WSS socket");
    }
    authenticate(secondSocket, 1_000);
    const current = openStream(runtime);
    const currentId = latestOpenStreamId(secondSocket);

    firstSocket.emitMessage(encodeFrame(streamFrame(FrameType.STREAM_OPENED, currentId, new Uint8Array())));
    expect(current.events).toEqual([]);
    emitOpened(secondSocket, currentId);
    expect(current.events).toEqual([{ type: "opened" }]);
  });

  it("在不足 credit、WSS 发送水位和失效 session 下保持队列与控制接口的失败关闭", () => {
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000,
      random: () => 1
    });
    const statusEvents: string[] = [];
    const unsubscribe = runtime.subscribeStatus((status) => statusEvents.push(status.state));
    runtime.start();
    runtime.start();
    expect(sockets.sockets).toHaveLength(1);
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const stream = openStream(runtime);
    const streamId = latestOpenStreamId(socket);
    socket.sendBufferedBytes = 1_024;
    emitOpened(socket, streamId);
    expect(framesOfType(socket, FrameType.STREAM_CREDIT)).toHaveLength(0);
    socket.sendBufferedBytes = 0;
    socket.emitSendAvailability();
    expect(framesOfType(socket, FrameType.STREAM_CREDIT)).toHaveLength(1);

    expect(stream.control.send(Uint8Array.of(1, 2))).toBe(false);
    socket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_CREDIT, streamId, encodeStreamCreditPayload({ bytes: 1_024 })))
    );
    expect(framesOfType(socket, FrameType.STREAM_DATA)).toHaveLength(1);
    socket.throwOnGetSendBufferedBytes = true;
    expect(stream.control.send(Uint8Array.of(3))).toBe(true);
    expect(framesOfType(socket, FrameType.STREAM_DATA)).toHaveLength(2);
    stream.control.close();
    expect(stream.control.send(Uint8Array.of(4))).toBe(false);
    socket.emitSendAvailability();
    unsubscribe();
    socket.emitClose();
    expect(statusEvents.at(-1)).toBe("online");
  });

  it("停止活跃会话时即使 socket.close 异常也会释放本地 stream、预算和定时器", () => {
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000
    });
    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const stream = openStream(runtime);
    socket.throwOnClose = true;

    runtime.stop();

    expect(stream.events).toEqual([{ type: "error" }]);
    expect(runtime.activeStreamCount).toBe(0);
    expect(runtime.getStatus()).toEqual({ state: "stopped", reconnectAttempts: 0 });
  });

  it("会话前心跳、opened 前 credit/data 与 server 发起的 STREAM_OPEN 均失败关闭", () => {
    const earlySockets = new FakeSocketFactory();
    const earlyRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: earlySockets,
      now: () => 1_000,
      random: () => 1
    });
    earlyRuntime.start();
    const earlySocket = earlySockets.sockets[0];
    if (earlySocket === undefined) {
      throw new Error("expected early socket");
    }
    earlySocket.emitOpen();
    earlySocket.emitMessage(encodeFrame(connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 0 }))));
    expect(earlyRuntime.getStatus().lastErrorCode).toBe("PROTOCOL_VIOLATION");

    const creditSockets = new FakeSocketFactory();
    const creditRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: creditSockets,
      now: () => 1_000,
      random: () => 1
    });
    creditRuntime.start();
    const creditSocket = creditSockets.sockets[0];
    if (creditSocket === undefined) {
      throw new Error("expected credit socket");
    }
    authenticate(creditSocket, 1_000);
    const credit = openStream(creditRuntime);
    const creditId = latestOpenStreamId(creditSocket);
    creditSocket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_CREDIT, creditId, encodeStreamCreditPayload({ bytes: 1 })))
    );
    expect(credit.events).toEqual([{ type: "error" }]);

    const dataSockets = new FakeSocketFactory();
    const dataRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: dataSockets,
      now: () => 1_000,
      random: () => 1
    });
    dataRuntime.start();
    const dataSocket = dataSockets.sockets[0];
    if (dataSocket === undefined) {
      throw new Error("expected data socket");
    }
    authenticate(dataSocket, 1_000);
    const data = openStream(dataRuntime);
    const dataId = latestOpenStreamId(dataSocket);
    dataSocket.emitMessage(encodeFrame(streamFrame(FrameType.STREAM_DATA, dataId, Uint8Array.of(1))));
    expect(data.events).toEqual([{ type: "error" }]);

    const directionSockets = new FakeSocketFactory();
    const directionRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: directionSockets,
      now: () => 1_000,
      random: () => 1
    });
    directionRuntime.start();
    const directionSocket = directionSockets.sockets[0];
    if (directionSocket === undefined) {
      throw new Error("expected direction socket");
    }
    authenticate(directionSocket, 1_000);
    const direction = openStream(directionRuntime);
    const directionId = latestOpenStreamId(directionSocket);
    directionSocket.emitMessage(
      encodeFrame(
        streamFrame(
          FrameType.STREAM_OPEN,
          directionId,
          encodeStreamOpenPayload({
            hostname: createConfig().allowedDestination.hostname,
            port: 443,
            capability: Uint8Array.of(0)
          })
        )
      )
    );
    expect(direction.events).toEqual([{ type: "error" }]);
    expect(directionRuntime.getStatus().lastErrorCode).toBe("PROTOCOL_VIOLATION");
  });

  it("无效 WSS 水位和重连抖动异常不会放宽流量控制或无限重连", () => {
    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: sockets,
      now: () => 1_000,
      random: () => 1
    });
    runtime.start();
    const socket = sockets.sockets[0];
    if (socket === undefined) {
      throw new Error("expected WSS socket");
    }
    authenticate(socket, 1_000);
    const stream = openStream(runtime);
    const streamId = latestOpenStreamId(socket);
    emitOpened(socket, streamId);
    socket.sendBufferedBytes = -1;
    socket.emitMessage(
      encodeFrame(streamFrame(FrameType.STREAM_CREDIT, streamId, encodeStreamCreditPayload({ bytes: 1_024 })))
    );
    expect(stream.control.send(Uint8Array.of(1))).toBe(true);

    const jitterRuntime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      socketFactory: { connect: () => { throw new Error("WSS unavailable"); } },
      random: () => -1
    });
    jitterRuntime.start();
    expect(jitterRuntime.getStatus()).toEqual({
      state: "offline",
      reconnectAttempts: 1,
      lastErrorCode: "EDGE_RECONNECT_JITTER_INVALID"
    });
  });

  it("严格校验配置、身份和重连抖动，并允许 stop 幂等取消后续重连", () => {
    expect(() => loadEdgeClientConfig('{"component":"edge-client","token":"not-for-logs"}')).toThrow(EdgeClientRuntimeError);
    expect(() => calculateEdgeReconnectDelayMs(0, createConfig().limits)).toThrow("EDGE_RECONNECT_ATTEMPT_INVALID");
    expect(calculateEdgeReconnectDelayMs(1, createConfig().limits, () => 0)).toBe(50);
    expect(calculateEdgeReconnectDelayMs(3, createConfig().limits, () => 1)).toBe(400);
    expect(() => calculateEdgeReconnectDelayMs(1, createConfig().limits, () => -1)).toThrow("EDGE_RECONNECT_JITTER_INVALID");
    expect(edgeOriginForServerUrl(new URL("wss://tunnel.example.test:8443/tunnel"))).toBe(
      "https://tunnel.example.test:8443"
    );
    expect(() => edgeOriginForServerUrl(new URL("https://tunnel.example.test:8443"))).toThrow("EDGE_ORIGIN_INVALID");
    expect(() => new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
      origin: "https://tunnel.example.test/path"
    })).toThrow("EDGE_ORIGIN_INVALID");

    const identity = createIdentity();
    const mismatched = createEdgeDeviceIdentity({
      edgeUserId: "edge-user-1",
      edgeDeviceId: "other-device",
      authenticationKey: identity.authenticationIdentity.authenticationKey
    });
    expect(
      () => new EdgeClientRuntime({ config: createConfig(), authenticationIdentity: mismatched, authenticationKey: identity.authenticationKey })
    ).toThrow("EDGE_DEVICE_IDENTITY_INVALID");

    vi.useFakeTimers();
    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({ config: createConfig(), ...createIdentity(), socketFactory: sockets, random: () => 1 });
    runtime.start();
    sockets.sockets[0]?.emitClose();
    runtime.stop();
    runtime.stop();
    vi.advanceTimersByTime(10_000);
    expect(sockets.sockets).toHaveLength(1);
    expect(runtime.getStatus()).toEqual({ state: "stopped", reconnectAttempts: 1 });
    expect(() => runtime.start()).toThrow("EDGE_RUNTIME_STOPPED");
  });

  it("edge 认证握手不会记录身份、challenge 或认证材料", () => {
    const runtimeSource = readFileSync(fileURLToPath(new URL("./runtime.ts", import.meta.url)), "utf8");
    const proxySource = readFileSync(fileURLToPath(new URL("./connect-proxy.ts", import.meta.url)), "utf8");
    expect(`${runtimeSource}\n${proxySource}`).not.toMatch(
      /\b(?:console\.(?:log|debug|info|warn|error)|logger\.|process\.(?:stdout|stderr)\.write\s*\()/u
    );

    const sockets = new FakeSocketFactory();
    const runtime = new EdgeClientRuntime({
      config: createConfig(),
      ...createIdentity(),
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
      runtime.start();
      const socket = sockets.sockets[0];
      if (socket === undefined) {
        throw new Error("expected WSS socket");
      }

      authenticate(socket, 1_000);
      expect(runtime.getStatus()).toEqual({ state: "online", reconnectAttempts: 0 });
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
