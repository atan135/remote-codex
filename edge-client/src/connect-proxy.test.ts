import { readFileSync } from "node:fs";
import { connect, type Socket } from "node:net";
import { fileURLToPath } from "node:url";

import { DEFAULT_ALLOWED_DESTINATION, type ValidatedDestination } from "@remote-codex/shared";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  LoopbackConnectProxy,
  type EdgeStreamControl,
  type EdgeStreamEvent,
  type EdgeStreamEventListener,
  type EdgeStreamGateway
} from "./connect-proxy.js";

class FakeStream implements EdgeStreamControl {
  public readonly sent: Uint8Array[] = [];
  public closeCalls = 0;
  public pauseIncomingCalls = 0;
  public resumeIncomingCalls = 0;
  public sendResult = true;

  public constructor(private readonly listener: EdgeStreamEventListener) {}

  public send(payload: Uint8Array): boolean {
    this.sent.push(Uint8Array.from(payload));
    return this.sendResult;
  }

  public pauseIncoming(): void {
    this.pauseIncomingCalls += 1;
  }

  public resumeIncoming(): void {
    this.resumeIncomingCalls += 1;
  }

  public close(): void {
    this.closeCalls += 1;
  }

  public emit(event: EdgeStreamEvent): void {
    this.listener(event);
  }
}

class FakeGateway implements EdgeStreamGateway {
  public readonly destinations: ValidatedDestination[] = [];
  public readonly streams: FakeStream[] = [];

  public open(destination: ValidatedDestination, listener: EdgeStreamEventListener): EdgeStreamControl {
    this.destinations.push(destination);
    const stream = new FakeStream(listener);
    this.streams.push(stream);
    return stream;
  }
}

interface SocketCapture {
  readonly chunks: Buffer[];
  readonly socket: Socket;
  error: Error | undefined;
  ended: boolean;
}

const activeProxies: LoopbackConnectProxy[] = [];

afterEach(async () => {
  while (activeProxies.length > 0) {
    await activeProxies.pop()?.stop();
  }
});

function createProxy(gateway: EdgeStreamGateway, openTimeoutMs = 100, maxConcurrentStreams = 2): LoopbackConnectProxy {
  const proxy = new LoopbackConnectProxy({
    allowedDestination: DEFAULT_ALLOWED_DESTINATION,
    limits: { maxConcurrentStreams, openTimeoutMs },
    listenPort: 0,
    streamGateway: gateway
  });
  activeProxies.push(proxy);
  return proxy;
}

function firstStream(gateway: FakeGateway): FakeStream {
  const stream = gateway.streams[0];
  expect(stream).toBeDefined();
  if (stream === undefined) {
    throw new Error("expected one fake stream");
  }

  return stream;
}

async function openSocket(port: number, host = "127.0.0.1"): Promise<Socket> {
  const socket = connect({ host, port });

  await new Promise<void>((resolve, reject) => {
    const onConnect = (): void => {
      socket.off("error", onError);
      resolve();
    };
    const onError = (error: Error): void => {
      socket.off("connect", onConnect);
      reject(error);
    };

    socket.once("connect", onConnect);
    socket.once("error", onError);
  });
  return socket;
}

function captureSocket(socket: Socket): SocketCapture {
  const capture: SocketCapture = { chunks: [], socket, error: undefined, ended: false };
  socket.on("data", (chunk: Buffer) => capture.chunks.push(chunk));
  socket.on("error", (error: Error) => {
    capture.error = error;
  });
  socket.on("end", () => {
    capture.ended = true;
  });
  return capture;
}

function capturedText(capture: SocketCapture): string {
  return Buffer.concat(capture.chunks).toString("latin1");
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  while (!predicate()) {
    if (Date.now() >= deadline) {
      throw new Error("timed out waiting for socket condition");
    }

    await new Promise<void>((resolve) => setTimeout(resolve, 2));
  }
}

async function request(proxy: LoopbackConnectProxy, serializedRequest: string): Promise<SocketCapture> {
  const socket = await openSocket(proxy.address().port);
  const capture = captureSocket(socket);
  socket.write(serializedRequest);
  return capture;
}

async function expectConnectionFailure(host: string, port: number): Promise<void> {
  const socket = connect({ host, port });
  const failure = await new Promise<Error>((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error(`unexpected connection to ${host}`));
    }, 1_000);
    socket.once("connect", () => {
      clearTimeout(timeout);
      socket.destroy();
      reject(new Error(`unexpected connection to ${host}`));
    });
    socket.once("error", (error) => {
      clearTimeout(timeout);
      resolve(error);
    });
  });

  expect(failure).toBeInstanceOf(Error);
}

const CONNECT_REQUEST = `CONNECT ${DEFAULT_ALLOWED_DESTINATION.hostname}:443 HTTP/1.1\r\nHost: ${DEFAULT_ALLOWED_DESTINATION.hostname}:443\r\n\r\n`;

describe("LoopbackConnectProxy", () => {
  it("仅接受有效的本地监听配置，且启停操作幂等", async () => {
    const gateway = new FakeGateway();
    expect(
      () =>
        new LoopbackConnectProxy({
          allowedDestination: DEFAULT_ALLOWED_DESTINATION,
          limits: { maxConcurrentStreams: 0, openTimeoutMs: 100 },
          streamGateway: gateway
        })
    ).toThrow("loopback proxy limits are invalid");
    expect(
      () =>
        new LoopbackConnectProxy({
          allowedDestination: DEFAULT_ALLOWED_DESTINATION,
          limits: { maxConcurrentStreams: 1, openTimeoutMs: 100 },
          listenPort: -1,
          streamGateway: gateway
        })
    ).toThrow("listenPort must be an integer between 0 and 65535");

    const proxy = createProxy(gateway);
    expect(() => proxy.address()).toThrow("loopback proxy is not listening");
    const firstAddress = await proxy.start();
    await expect(proxy.start()).resolves.toEqual(firstAddress);
    await proxy.stop();
    await proxy.stop();
  });

  it("仅在 agent opened 后回 200，并透明转发两个方向的字节", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    await proxy.start();
    const capture = await request(proxy, CONNECT_REQUEST);

    await waitFor(() => gateway.streams.length === 1);
    expect(capturedText(capture)).toBe("");
    expect(gateway.destinations).toEqual([DEFAULT_ALLOWED_DESTINATION]);

    const stream = firstStream(gateway);
    stream.emit({ type: "opened" });
    await waitFor(() => capturedText(capture).includes("HTTP/1.1 200 Connection Established\r\n\r\n"));

    capture.socket.write("edge-bytes");
    await waitFor(() => stream.sent.length === 1);
    expect(Buffer.from(stream.sent[0] ?? new Uint8Array()).toString()).toBe("edge-bytes");

    stream.emit({ type: "data", payload: Uint8Array.from(Buffer.from("gateway-bytes")) });
    await waitFor(() => capturedText(capture).includes("gateway-bytes"));

    capture.socket.end();
    await waitFor(() => stream.closeCalls === 1);
  });

  it("拒绝在 opened 前独立到达的 TCP 字节", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    await proxy.start();
    const capture = await request(proxy, CONNECT_REQUEST);

    await waitFor(() => gateway.streams.length === 1);
    capture.socket.write("must-not-be-forwarded");

    await waitFor(() => capture.ended);
    expect(capturedText(capture)).toContain("HTTP/1.1 400 Bad Request");
    expect(firstStream(gateway).sent).toHaveLength(0);
    expect(firstStream(gateway).closeCalls).toBe(1);
  });

  it("在 gateway 建流异常或 edge 并发限额耗尽时返回固定错误", async () => {
    const throwingGateway: EdgeStreamGateway = {
      open: () => {
        throw new Error("gateway unavailable");
      }
    };
    const throwingProxy = createProxy(throwingGateway);
    await throwingProxy.start();
    const failedCapture = await request(throwingProxy, CONNECT_REQUEST);
    await waitFor(() => failedCapture.ended);
    expect(capturedText(failedCapture)).toContain("HTTP/1.1 502 Bad Gateway");

    const gateway = new FakeGateway();
    const limitedProxy = createProxy(gateway, 100, 1);
    await limitedProxy.start();
    const firstCapture = await request(limitedProxy, CONNECT_REQUEST);
    await waitFor(() => gateway.streams.length === 1);
    const limitedCapture = await request(limitedProxy, CONNECT_REQUEST);
    await waitFor(() => limitedCapture.ended);
    expect(capturedText(limitedCapture)).toContain("HTTP/1.1 502 Bad Gateway");
    expect(gateway.streams).toHaveLength(1);
    firstCapture.socket.destroy();
  });

  it("在 127.0.0.1 之外不接受连接", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    await proxy.start();
    const socket = connect({ host: "127.0.0.2", port: proxy.address().port });

    const failure = await new Promise<Error>((resolve) => socket.once("error", resolve));
    expect((failure as NodeJS.ErrnoException).code).toBe("ECONNREFUSED");
    expect(gateway.streams).toHaveLength(0);
  });

  it("固定 IPv4 loopback 监听，且 CONNECT 机密不会进入运行日志", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    const consoleSpies = [
      vi.spyOn(console, "log"),
      vi.spyOn(console, "debug"),
      vi.spyOn(console, "info"),
      vi.spyOn(console, "warn"),
      vi.spyOn(console, "error")
    ];

    try {
      const address = await proxy.start();
      expect(address.host).toBe("127.0.0.1");
      await expectConnectionFailure("127.0.0.2", address.port);
      await expectConnectionFailure("::1", address.port);

      const capture = await request(
        proxy,
        `CONNECT ${DEFAULT_ALLOWED_DESTINATION.hostname}:443 HTTP/1.1\r\nProxy-Authorization: Basic never-log-this\r\n\r\n`
      );
      await waitFor(() => capture.ended);
      expect(capturedText(capture)).toContain("HTTP/1.1 403 Forbidden");
      expect(gateway.streams).toHaveLength(0);
      expect(consoleSpies.every((spy) => spy.mock.calls.length === 0)).toBe(true);

      const source = readFileSync(fileURLToPath(new URL("./connect-proxy.ts", import.meta.url)), "utf8");
      expect(source).toContain('host: LOOPBACK_LISTEN_HOST');
      expect(source).not.toMatch(/\b(?:console\.(?:log|debug|info|warn|error)|logger\.)/u);
      expect(source).not.toMatch(/0\.0\.0\.0|::1/u);
    } finally {
      for (const spy of consoleSpies) {
        spy.mockRestore();
      }
    }
  });

  it("拒绝普通 HTTP 方法，且不创建 stream", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    await proxy.start();
    const capture = await request(proxy, "GET / HTTP/1.1\r\nHost: proxy.test\r\n\r\n");

    await waitFor(() => capture.ended);
    expect(capturedText(capture)).toContain("HTTP/1.1 405 Method Not Allowed");
    expect(gateway.streams).toHaveLength(0);
  });

  it("在网关前拒绝错误 host、port、绝对 URL、IP literal 和认证头", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    await proxy.start();
    const invalidRequests = [
      "CONNECT other.example:443 HTTP/1.1\r\n\r\n",
      `CONNECT ${DEFAULT_ALLOWED_DESTINATION.hostname}:444 HTTP/1.1\r\n\r\n`,
      "CONNECT https://example.test:443 HTTP/1.1\r\n\r\n",
      "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
      `CONNECT ${DEFAULT_ALLOWED_DESTINATION.hostname}:443 HTTP/1.1\r\nProxy-Authorization: Basic ignored\r\n\r\n`
    ];

    for (const invalidRequest of invalidRequests) {
      const capture = await request(proxy, invalidRequest);
      await waitFor(() => capture.ended);
      expect(capturedText(capture)).toContain("HTTP/1.1 403 Forbidden");
    }

    expect(gateway.streams).toHaveLength(0);
  });

  it("拒绝 body、upgrade 与 CONNECT header 后的额外字节", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    await proxy.start();
    const invalidRequests = [
      `CONNECT ${DEFAULT_ALLOWED_DESTINATION.hostname}:443 HTTP/1.1\r\nContent-Length: 1\r\n\r\nx`,
      `CONNECT ${DEFAULT_ALLOWED_DESTINATION.hostname}:443 HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`,
      `${CONNECT_REQUEST}unexpected`
    ];

    for (const invalidRequest of invalidRequests) {
      const capture = await request(proxy, invalidRequest);
      await waitFor(() => capture.ended);
      expect(capturedText(capture)).toMatch(/HTTP\/1\.1 (400 Bad Request|403 Forbidden)/u);
    }

    expect(gateway.streams).toHaveLength(0);
  });

  it("在 agent 拒绝时返回固定 502 并关闭未 opened stream", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    await proxy.start();
    const capture = await request(proxy, CONNECT_REQUEST);

    await waitFor(() => gateway.streams.length === 1);
    const stream = firstStream(gateway);
    stream.emit({ type: "rejected" });

    await waitFor(() => capture.ended);
    expect(capturedText(capture)).toContain("HTTP/1.1 502 Bad Gateway");
    expect(stream.closeCalls).toBe(1);
  });

  it("在 agent error 或已 opened stream 的 close 时清理对应本地连接", async () => {
    const errorGateway = new FakeGateway();
    const errorProxy = createProxy(errorGateway);
    await errorProxy.start();
    const errorCapture = await request(errorProxy, CONNECT_REQUEST);

    await waitFor(() => errorGateway.streams.length === 1);
    const errorStream = firstStream(errorGateway);
    errorStream.emit({ type: "error" });
    await waitFor(() => errorCapture.ended);
    expect(capturedText(errorCapture)).toContain("HTTP/1.1 502 Bad Gateway");
    expect(errorStream.closeCalls).toBe(1);

    const closeGateway = new FakeGateway();
    const closeProxy = createProxy(closeGateway);
    await closeProxy.start();
    const closeCapture = await request(closeProxy, CONNECT_REQUEST);
    await waitFor(() => closeGateway.streams.length === 1);
    const closeStream = firstStream(closeGateway);
    closeStream.emit({ type: "opened" });
    await waitFor(() => capturedText(closeCapture).includes("200 Connection Established"));
    closeStream.emit({ type: "close" });
    await waitFor(() => closeCapture.ended);
    expect(closeStream.closeCalls).toBe(0);
  });

  it("拒绝 opened 前的 gateway data，并在双向背压恢复时继续转发", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    await proxy.start();
    const rejectedCapture = await request(proxy, CONNECT_REQUEST);
    await waitFor(() => gateway.streams.length === 1);
    const rejectedStream = firstStream(gateway);
    rejectedStream.emit({ type: "data", payload: Uint8Array.of(1) });
    await waitFor(() => rejectedCapture.ended);
    expect(capturedText(rejectedCapture)).toContain("HTTP/1.1 502 Bad Gateway");
    expect(rejectedStream.closeCalls).toBe(1);

    const forwardingGateway = new FakeGateway();
    const forwardingProxy = createProxy(forwardingGateway);
    await forwardingProxy.start();
    const capture = await request(forwardingProxy, CONNECT_REQUEST);
    await waitFor(() => forwardingGateway.streams.length === 1);
    const stream = firstStream(forwardingGateway);
    stream.emit({ type: "opened" });
    await waitFor(() => capturedText(capture).includes("200 Connection Established"));

    stream.sendResult = false;
    capture.socket.write("first");
    await waitFor(() => stream.sent.length === 1);
    stream.sendResult = true;
    stream.emit({ type: "writable" });
    capture.socket.write("second");
    await waitFor(() => stream.sent.length === 2);
    expect(Buffer.from(stream.sent[1] ?? new Uint8Array()).toString()).toBe("second");

    capture.socket.pause();
    for (let index = 0; index < 1_024 && stream.pauseIncomingCalls === 0; index += 1) {
      stream.emit({ type: "data", payload: new Uint8Array(16 * 1024) });
    }
    await waitFor(() => stream.pauseIncomingCalls === 1);
    capture.socket.resume();
    await waitFor(() => stream.resumeIncomingCalls === 1);
  });

  it("在打开超时时返回固定 504 并清理 stream", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway, 20);
    await proxy.start();
    const capture = await request(proxy, CONNECT_REQUEST);

    await waitFor(() => capture.ended);
    expect(capturedText(capture)).toContain("HTTP/1.1 504 Gateway Timeout");
    expect(firstStream(gateway).closeCalls).toBe(1);
  });

  it("停止会撤销 pending CONNECT、关闭监听器，且重复停止不会保留 socket", async () => {
    const gateway = new FakeGateway();
    const proxy = createProxy(gateway);
    const address = await proxy.start();
    const capture = await request(proxy, CONNECT_REQUEST);

    await waitFor(() => gateway.streams.length === 1);
    await proxy.stop();
    await waitFor(() => capture.socket.destroyed);

    expect(firstStream(gateway).closeCalls).toBe(1);
    expect(() => proxy.address()).toThrow("loopback proxy is not listening");
    await proxy.stop();
    await expectConnectionFailure(address.host, address.port);
  });
});
