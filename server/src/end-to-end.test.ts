import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { connect, type Socket } from "node:net";
import { createServer as createTlsServer, connect as connectTls, type Server as TlsServer, type TLSSocket } from "node:tls";

import {
  createEdgeDeviceIdentity,
  createEgressAgentIdentity,
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  decodeFrame,
  FrameType,
  IdentityKeyRole,
  parseEdgeClientConfig,
  parseEgressAgentConfig,
  parseResourceLimits,
  type AllowedDestination,
  type EdgeDeviceIdentity,
  type EgressAgentIdentity,
  type IdentityPrivateKey,
  type IdentityKeyRole as IdentityKeyRoleValue,
  type ValidatedDestination
} from "@remote-codex/shared";
import selfsigned from "selfsigned";
import WebSocket from "ws";
import type { ClientOptions, RawData } from "ws";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { LoopbackConnectProxy } from "../../edge-client/src/connect-proxy.js";
import {
  EdgeClientRuntime,
  type EdgeSocket,
  type EdgeSocketFactory
} from "../../edge-client/src/runtime.js";
import { EgressAgentDialer, type AgentTcpConnector } from "../../egress-agent/src/dialer.js";
import {
  EgressAgentRuntime,
  type AgentSocket,
  type AgentSocketFactory
} from "../../egress-agent/src/runtime.js";
import type { StreamAuditEvent } from "./observability.js";
import { createTunnelServer, type TlsCredentials, type TunnelServer } from "./runtime.js";
import { listenOnApprovedTestPort, startOnApprovedTestPort } from "./test-port-helper.js";

const GATEWAY_HOSTNAME = "gateway.integration.test";
const TUNNEL_TLS_HOSTNAME = "tunnel.integration.test";
const EDGE_A_ORIGIN = "https://edge-a.integration.test";
const EDGE_B_ORIGIN = "https://edge-b.integration.test";
const AGENT_ORIGIN = "https://agent.integration.test";

const allowedDestination: AllowedDestination = Object.freeze({ hostname: GATEWAY_HOSTNAME, port: 443 });
const testLimits = parseResourceLimits({
  maxConcurrentStreams: 2,
  maxBufferedBytesPerStream: 32 * 1024,
  maxAggregateBufferedBytes: 128 * 1024,
  maxFramePayloadBytes: 4 * 1024,
  maxIdleMs: 1_000,
  connectTimeoutMs: 200,
  openTimeoutMs: 800,
  heartbeatIntervalMs: 100,
  heartbeatTimeoutMs: 400,
  reconnectInitialMs: 100,
  reconnectMaxMs: 100,
  maxReconnectAttempts: 8
});

let tunnelTls: TlsCredentials;
let gatewayTls: TlsCredentials;
const initialTlsVerificationSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

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

function makeCertificate(hostname: string): TlsCredentials {
  const certificate = selfsigned.generate([{ name: "commonName", value: hostname }], {
    algorithm: "sha256",
    days: 1,
    keySize: 2048,
    extensions: [
      {
        name: "subjectAltName",
        altNames: [{ type: 2, value: hostname }]
      }
    ]
  });
  return { certificate: Buffer.from(certificate.cert), privateKey: Buffer.from(certificate.private) };
}

function createKeyPair<Role extends IdentityKeyRoleValue>(role: Role, keyId: string) {
  const keys = generateKeyPairSync("ed25519");
  return {
    publicKey: createIdentityPublicKey({ role, keyId }, keys.publicKey),
    privateKey: createIdentityPrivateKey({ role, keyId }, keys.privateKey)
  };
}

function waitFor(predicate: () => boolean, label: string, timeoutMs = 5_000): Promise<void> {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const poll = (): void => {
      if (predicate()) {
        resolve();
        return;
      }

      if (Date.now() >= deadline) {
        reject(new Error(`timed out waiting for ${label}`));
        return;
      }

      setTimeout(poll, 5);
    };
    poll();
  });
}

class RecordingWebSocket implements EdgeSocket, AgentSocket {
  private readonly sendAvailabilityListeners = new Set<() => void>();
  private readonly framePayloads: Uint8Array[] = [];

  public constructor(private readonly socket: WebSocket) {}

  public send(data: Uint8Array): void {
    this.captureTunnelData(data);
    this.socket.send(data, { binary: true }, () => this.notifySendAvailability());
  }

  public close(code?: number, reason?: string): void {
    this.socket.close(code, reason);
  }

  public onOpen(listener: () => void): void {
    this.socket.once("open", listener);
  }

  public onMessage(listener: (data: Uint8Array | undefined, isBinary: boolean) => void): void {
    this.socket.on("message", (data: RawData, isBinary: boolean) => {
      const bytes = rawDataToBytes(data);
      if (bytes !== undefined) {
        this.captureTunnelData(bytes);
      }
      listener(bytes, isBinary);
    });
  }

  public onClose(listener: (code: number, reason: string) => void): void {
    this.socket.once("close", (code: number, reason: Buffer) => listener(code, reason.toString("utf8")));
  }

  public onError(listener: () => void): void {
    this.socket.once("error", listener);
  }

  public getSendBufferedBytes(): number {
    return this.socket.bufferedAmount;
  }

  public onSendAvailability(listener: () => void): () => void {
    this.sendAvailabilityListeners.add(listener);
    return (): void => {
      this.sendAvailabilityListeners.delete(listener);
    };
  }

  public terminateForTest(): void {
    this.socket.terminate();
  }

  public get tunnelDataPayloads(): readonly Uint8Array[] {
    return this.framePayloads.map((payload) => Uint8Array.from(payload));
  }

  private captureTunnelData(serializedFrame: Uint8Array): void {
    try {
      const frame = decodeFrame(serializedFrame);
      if (frame.type === FrameType.STREAM_DATA) {
        this.framePayloads.push(Uint8Array.from(frame.payload));
      }
    } catch {
      // 认证层的输入不属于 stream payload；测试观察点不改变运行时行为。
    }
  }

  private notifySendAvailability(): void {
    for (const listener of this.sendAvailabilityListeners) {
      listener();
    }
  }
}

class RecordingSocketFactory implements EdgeSocketFactory, AgentSocketFactory {
  public readonly sockets: RecordingWebSocket[] = [];

  public constructor(
    private readonly origin: string,
    private readonly certificate: Buffer,
    private readonly servername: string
  ) {}

  public connect(serverUrl: URL, suppliedOrigin?: string): RecordingWebSocket {
    const tlsOptions: ClientOptions & { readonly servername: string } = {
      ca: this.certificate,
      origin: suppliedOrigin ?? this.origin,
      perMessageDeflate: false,
      rejectUnauthorized: true,
      servername: this.servername
    };
    const socket = new RecordingWebSocket(
      new WebSocket(serverUrl, undefined, tlsOptions)
    );
    this.sockets.push(socket);
    return socket;
  }

  public get tunnelDataPayloads(): readonly Uint8Array[] {
    return this.sockets.flatMap((socket) => socket.tunnelDataPayloads);
  }

  public terminateLatest(): void {
    const socket = this.sockets.at(-1);
    if (socket === undefined) {
      throw new Error("expected an authenticated WSS socket");
    }
    socket.terminateForTest();
  }

  public terminateAll(): void {
    for (const socket of this.sockets) {
      socket.terminateForTest();
    }
  }
}

/**
 * 测试专用受控 connector：生产 dialer 仍只看到并验证 hostname:443；本类只把
 * 已通过该精确比较的测试目标桥接到临时 IPv4 loopback TLS 网关。
 */
class LoopbackGatewayConnector implements AgentTcpConnector {
  public readonly destinations: ValidatedDestination[] = [];
  private readonly sockets = new Set<Socket>();

  public constructor(private readonly gatewayPort: number) {}

  public connect(destination: ValidatedDestination): Socket {
    if (destination.hostname !== GATEWAY_HOSTNAME || destination.port !== 443) {
      throw new Error("test connector received an unapproved destination");
    }

    this.destinations.push(destination);
    const socket = connect({ host: "127.0.0.1", port: this.gatewayPort });
    this.sockets.add(socket);
    socket.once("close", () => this.sockets.delete(socket));
    return socket;
  }

  public destroyAll(): void {
    for (const socket of this.sockets) {
      socket.destroy();
    }
  }
}

interface TlsProbe {
  readonly socket: TLSSocket;
  readonly received: Buffer[];
}

async function connectToProxy(proxy: LoopbackConnectProxy): Promise<TlsProbe> {
  const rawSocket = connect({ host: "127.0.0.1", port: proxy.address().port });
  await once(rawSocket, "connect");
  const connectResponse = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    const onData = (chunk: Buffer): void => {
      chunks.push(Buffer.from(chunk));
      const combined = Buffer.concat(chunks);
      const end = combined.indexOf("\r\n\r\n");
      if (end === -1) {
        return;
      }

      rawSocket.off("data", onData);
      rawSocket.off("error", onError);
      if (combined.byteLength !== end + 4) {
        reject(new Error("CONNECT response contained unexpected tunnel bytes"));
        return;
      }
      resolve(combined);
    };
    const onError = (error: Error): void => {
      rawSocket.off("data", onData);
      reject(error);
    };
    rawSocket.on("data", onData);
    rawSocket.once("error", onError);
    rawSocket.write(`CONNECT ${GATEWAY_HOSTNAME}:443 HTTP/1.1\r\nHost: ${GATEWAY_HOSTNAME}:443\r\n\r\n`);
  });
  expect(connectResponse.toString("latin1")).toBe("HTTP/1.1 200 Connection Established\r\n\r\n");

  const socket = connectTls({
    ca: gatewayTls.certificate,
    rejectUnauthorized: true,
    servername: GATEWAY_HOSTNAME,
    socket: rawSocket,
    minVersion: "TLSv1.3"
  });
  const received: Buffer[] = [];
  socket.on("data", (chunk: Buffer) => received.push(Buffer.from(chunk)));
  socket.on("error", () => undefined);
  await once(socket, "secureConnect");
  return { socket, received };
}

async function echo(probe: TlsProbe, payload: Uint8Array): Promise<void> {
  const originalLength = Buffer.concat(probe.received).byteLength;
  probe.socket.write(payload);
  await waitFor(
    () => Buffer.concat(probe.received).subarray(originalLength).equals(Buffer.from(payload)),
    "TLS echo"
  );
}

async function closeTlsProbe(probe: TlsProbe): Promise<void> {
  if (probe.socket.destroyed) {
    return;
  }

  probe.socket.end();
  await Promise.race([once(probe.socket, "close"), new Promise((resolve) => setTimeout(resolve, 500))]);
  if (!probe.socket.destroyed) {
    probe.socket.destroy();
  }
}

class EndToEndFixture {
  public readonly edgeASockets = new RecordingSocketFactory(EDGE_A_ORIGIN, tunnelTls.certificate, TUNNEL_TLS_HOSTNAME);
  public readonly edgeBSockets = new RecordingSocketFactory(EDGE_B_ORIGIN, tunnelTls.certificate, TUNNEL_TLS_HOSTNAME);
  public readonly agentSockets = new RecordingSocketFactory(AGENT_ORIGIN, tunnelTls.certificate, TUNNEL_TLS_HOSTNAME);
  public readonly openProbes = new Set<TlsProbe>();
  public readonly gatewaySockets = new Set<TLSSocket>();
  /** 仅收集 server 已白名单序列化的 stream 元数据，绝不保留原始帧或 TLS 内容。 */
  public readonly auditEvents: StreamAuditEvent[] = [];
  public readonly agentId = "agent-integration-1";
  public readonly edgeAUserId = "edge-user-a";
  public readonly edgeADeviceId = "edge-device-a";
  public readonly edgeBUserId = "edge-user-b";
  public readonly edgeBDeviceId = "edge-device-b";
  public readonly signingCredentials: ReturnType<typeof createServerSigningCredentials>;
  public agent!: EgressAgentRuntime;
  public edgeA!: EdgeClientRuntime;
  public edgeB!: EdgeClientRuntime;
  public agentDialer!: EgressAgentDialer;
  public proxyA!: LoopbackConnectProxy;
  public proxyB!: LoopbackConnectProxy;
  public readonly gateway: TlsServer;
  public connector!: LoopbackGatewayConnector;
  public tunnel!: TunnelServer;
  private tunnelPort = 0;
  private readonly agentIdentity: EgressAgentIdentity;
  private readonly agentAuthenticationKey: IdentityPrivateKey<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
  private readonly edgeAIdentity: EdgeDeviceIdentity;
  private readonly edgeAAuthenticationKey: IdentityPrivateKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
  private readonly edgeBIdentity: EdgeDeviceIdentity;
  private readonly edgeBAuthenticationKey: IdentityPrivateKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>;
  private readonly serverPeerIdentities: NonNullable<Parameters<typeof createTunnelServer>[0]["peerIdentities"]>;

  public constructor() {
    const signingKeys = createKeyPair(IdentityKeyRole.SERVER_CAPABILITY_SIGNING, "server-capability-key");
    const signingIdentity = createServerSigningIdentity({
      serverId: "server-integration-1",
      capabilityVerificationKey: signingKeys.publicKey
    });
    this.signingCredentials = createServerSigningCredentials({
      identity: signingIdentity,
      capabilitySigningKey: signingKeys.privateKey
    });

    const agentKeys = createKeyPair(IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, "agent-auth-key");
    this.agentIdentity = createEgressAgentIdentity({ agentId: this.agentId, authenticationKey: agentKeys.publicKey });
    this.agentAuthenticationKey = agentKeys.privateKey;
    const edgeAKeys = createKeyPair(IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, "edge-a-auth-key");
    this.edgeAIdentity = createEdgeDeviceIdentity({
      edgeUserId: this.edgeAUserId,
      edgeDeviceId: this.edgeADeviceId,
      authenticationKey: edgeAKeys.publicKey
    });
    this.edgeAAuthenticationKey = edgeAKeys.privateKey;
    const edgeBKeys = createKeyPair(IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, "edge-b-auth-key");
    this.edgeBIdentity = createEdgeDeviceIdentity({
      edgeUserId: this.edgeBUserId,
      edgeDeviceId: this.edgeBDeviceId,
      authenticationKey: edgeBKeys.publicKey
    });
    this.edgeBAuthenticationKey = edgeBKeys.privateKey;

    this.gateway = createTlsServer(
      { cert: gatewayTls.certificate, key: gatewayTls.privateKey, minVersion: "TLSv1.3" },
      (socket) => {
        this.gatewaySockets.add(socket);
        socket.on("data", (payload: Buffer) => socket.write(payload));
        socket.once("end", () => socket.end());
        socket.once("close", () => this.gatewaySockets.delete(socket));
      }
    );

    this.serverPeerIdentities = [
      { identity: this.edgeAIdentity },
      { identity: this.edgeBIdentity },
      { identity: this.agentIdentity }
    ];
  }

  public async start(): Promise<void> {
    const gatewayPort = await listenOnApprovedTestPort(this.gateway);
    this.connector = new LoopbackGatewayConnector(gatewayPort);
    await this.startTunnelServer();
    const serverUrl = `wss://127.0.0.1:${this.tunnelPort}/tunnel`;
    const agentConfig = parseEgressAgentConfig({
      component: "egress-agent",
      agentId: this.agentId,
      serverUrl,
      allowedDestination,
      limits: testLimits
    });
    this.agentDialer = new EgressAgentDialer({
      config: agentConfig,
      capabilityServerIdentity: this.signingCredentials.identity,
      connector: this.connector
    });
    this.agent = new EgressAgentRuntime({
      config: agentConfig,
      authenticationIdentity: this.agentIdentity,
      authenticationKey: this.agentAuthenticationKey,
      origin: AGENT_ORIGIN,
      socketFactory: this.agentSockets,
      streamResources: this.agentDialer,
      random: () => 0
    });

    const edgeAStarted = await startOnApprovedTestPort(async (listenPort) => {
      const config = parseEdgeClientConfig({
        component: "edge-client",
        edgeUserId: this.edgeAUserId,
        edgeDeviceId: this.edgeADeviceId,
        serverUrl,
        listenHost: "127.0.0.1",
        listenPort,
        allowedDestination,
        limits: testLimits
      });
      const runtime = new EdgeClientRuntime({
        config,
        authenticationIdentity: this.edgeAIdentity,
        authenticationKey: this.edgeAAuthenticationKey,
        origin: EDGE_A_ORIGIN,
        socketFactory: this.edgeASockets,
        random: () => 0
      });
      const proxy = new LoopbackConnectProxy({
        allowedDestination,
        limits: testLimits,
        listenPort: config.listenPort,
        streamGateway: runtime
      });
      await proxy.start();
      return { config, proxy, runtime };
    });
    this.edgeA = edgeAStarted.value.runtime;
    this.proxyA = edgeAStarted.value.proxy;

    const edgeBStarted = await startOnApprovedTestPort(async (listenPort) => {
      const config = parseEdgeClientConfig({
        component: "edge-client",
        edgeUserId: this.edgeBUserId,
        edgeDeviceId: this.edgeBDeviceId,
        serverUrl,
        listenHost: "127.0.0.1",
        listenPort,
        allowedDestination,
        limits: testLimits
      });
      const runtime = new EdgeClientRuntime({
        config,
        authenticationIdentity: this.edgeBIdentity,
        authenticationKey: this.edgeBAuthenticationKey,
        origin: EDGE_B_ORIGIN,
        socketFactory: this.edgeBSockets,
        random: () => 0
      });
      const proxy = new LoopbackConnectProxy({
        allowedDestination,
        limits: testLimits,
        listenPort: config.listenPort,
        streamGateway: runtime
      });
      await proxy.start();
      return { config, proxy, runtime };
    });
    this.edgeB = edgeBStarted.value.runtime;
    this.proxyB = edgeBStarted.value.proxy;
    this.agent.start();
    this.edgeA.start();
    this.edgeB.start();
    await this.waitForOnline();
  }

  public async restartTunnelServer(): Promise<void> {
    await this.tunnel.close();
    await this.startTunnelServer(this.tunnelPort);
  }

  public async waitForOnline(): Promise<void> {
    await waitFor(
      () =>
        this.agent.getStatus().state === "online" &&
        this.edgeA.getStatus().state === "online" &&
        this.edgeB.getStatus().state === "online",
      "all WSS peers online"
    );
  }

  public async openProbe(proxy: LoopbackConnectProxy): Promise<TlsProbe> {
    const probe = await connectToProxy(proxy);
    this.openProbes.add(probe);
    probe.socket.once("close", () => this.openProbes.delete(probe));
    return probe;
  }

  public destroyGatewayConnections(): void {
    this.connector.destroyAll();
    for (const socket of this.gatewaySockets) {
      socket.destroy();
    }
  }

  public async close(): Promise<void> {
    for (const probe of [...this.openProbes]) {
      await closeTlsProbe(probe);
    }
    await this.proxyA?.stop();
    await this.proxyB?.stop();
    this.edgeA?.stop();
    this.edgeB?.stop();
    this.agent?.stop();
    this.edgeASockets.terminateAll();
    this.edgeBSockets.terminateAll();
    this.agentSockets.terminateAll();
    this.destroyGatewayConnections();
    await this.tunnel?.close();
    await new Promise<void>((resolve) => this.gateway.close(() => resolve()));
  }

  private async startTunnelServer(port?: number): Promise<void> {
    this.tunnel = createTunnelServer({
      tls: tunnelTls,
      allowedOrigins: [EDGE_A_ORIGIN, EDGE_B_ORIGIN, AGENT_ORIGIN],
      peerIdentities: this.serverPeerIdentities,
      authorizationDocument: {
        auditVersion: 1,
        authorizations: [
          {
            edgeUserId: this.edgeAUserId,
            edgeDeviceId: this.edgeADeviceId,
            agentId: this.agentId,
            status: "active",
            quota: { maxConcurrentStreams: 1, maxBufferedBytes: 32 * 1024 },
            createdAtMs: 0,
            auditVersion: 1
          },
          {
            edgeUserId: this.edgeBUserId,
            edgeDeviceId: this.edgeBDeviceId,
            agentId: this.agentId,
            status: "active",
            quota: { maxConcurrentStreams: 1, maxBufferedBytes: 32 * 1024 },
            createdAtMs: 0,
            auditVersion: 1
          }
        ]
      },
      streamAuthorization: {
        signingCredentials: this.signingCredentials,
        allowedDestination,
        resourceLimits: testLimits,
        auditLogger: (serializedEvent): void => {
          this.auditEvents.push(JSON.parse(serializedEvent) as StreamAuditEvent);
        }
      }
    });
    if (port === undefined) {
      this.tunnelPort = await listenOnApprovedTestPort(this.tunnel.httpsServer);
      return;
    }
    this.tunnel.httpsServer.listen(port, "127.0.0.1");
    await once(this.tunnel.httpsServer, "listening");
    this.tunnelPort = port;
  }

}

const fixtures: EndToEndFixture[] = [];

beforeAll(() => {
  delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  tunnelTls = makeCertificate(TUNNEL_TLS_HOSTNAME);
  gatewayTls = makeCertificate(GATEWAY_HOSTNAME);
});

afterAll(() => {
  if (initialTlsVerificationSetting === undefined) {
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    return;
  }
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = initialTlsVerificationSetting;
});

afterEach(async () => {
  while (fixtures.length > 0) {
    await fixtures.pop()?.close();
  }
});

describe("真实三方端到端夹具", () => {
  it("两个 edge 用户经共享 agent 建立经过 hostname 校验的 TLS 隧道，且流与字节互不串扰", async () => {
    const fixture = new EndToEndFixture();
    fixtures.push(fixture);
    await fixture.start();

    const [edgeAProbe, edgeBProbe] = await Promise.all([fixture.openProbe(fixture.proxyA), fixture.openProbe(fixture.proxyB)]);
    const edgeAPayload = Buffer.alloc(97, 0x41);
    const edgeBPayload = Buffer.alloc(211, 0x42);
    await Promise.all([echo(edgeAProbe, edgeAPayload), echo(edgeBProbe, edgeBPayload)]);

    await waitFor(
      () =>
        fixture.tunnel?.streamOpenCoordinator?.getActiveStreams().length === 2 &&
        fixture.agentDialer.activeStreamCount === 2 &&
        fixture.edgeA.activeStreamCount === 1 &&
        fixture.edgeB.activeStreamCount === 1,
      "two isolated streams"
    );
    const activeStreams = fixture.tunnel?.streamOpenCoordinator?.getActiveStreams() ?? [];
    expect(new Set(activeStreams.map((stream) => Buffer.from(stream.streamId).toString("hex"))).size).toBe(2);
    expect(activeStreams.map((stream) => stream.edgeUserId).sort()).toEqual([fixture.edgeAUserId, fixture.edgeBUserId]);
    expect(activeStreams.map((stream) => stream.quota.maxConcurrentStreams)).toEqual([1, 1]);
    expect(fixture.connector.destinations).toEqual([allowedDestination, allowedDestination]);

    const opaquePayloads = [...fixture.edgeASockets.tunnelDataPayloads, ...fixture.edgeBSockets.tunnelDataPayloads, ...fixture.agentSockets.tunnelDataPayloads];
    expect(opaquePayloads.length).toBeGreaterThan(0);
    for (const payload of opaquePayloads) {
      expect(Buffer.from(payload).includes(edgeAPayload)).toBe(false);
      expect(Buffer.from(payload).includes(edgeBPayload)).toBe(false);
    }

    await closeTlsProbe(edgeAProbe);
    await waitFor(() => fixture.edgeA.activeStreamCount === 0 && fixture.edgeB.activeStreamCount === 1, "edge A cleanup only");
    await echo(edgeBProbe, Buffer.alloc(53, 0x43));
    await closeTlsProbe(edgeBProbe);
    await waitFor(
      () => fixture.auditEvents.filter((event) => event.event === "stream.closed").length === 2,
      "metadata-only closed audit events"
    );
    const closedEvents = fixture.auditEvents.filter((event) => event.event === "stream.closed");
    const closedA = closedEvents.find((event) => event.edgeUserId === fixture.edgeAUserId);
    const closedB = closedEvents.find((event) => event.edgeUserId === fixture.edgeBUserId);
    expect(closedA).toMatchObject({
      edgeUserId: fixture.edgeAUserId,
      edgeDeviceId: fixture.edgeADeviceId,
      agentId: fixture.agentId,
      state: "closed"
    });
    expect(closedB).toMatchObject({
      edgeUserId: fixture.edgeBUserId,
      edgeDeviceId: fixture.edgeBDeviceId,
      agentId: fixture.agentId,
      state: "closed"
    });
    expect(closedA?.streamId).not.toBe(closedB?.streamId);
    expect(closedA?.edgeToAgentBytes).toBeGreaterThan(0);
    expect(closedA?.agentToEdgeBytes).toBeGreaterThan(0);
    expect(closedB?.edgeToAgentBytes).toBeGreaterThan(0);
    expect(closedB?.agentToEdgeBytes).toBeGreaterThan(0);
    expect(closedA?.edgeToAgentBytes).not.toBe(closedB?.edgeToAgentBytes);
    expect(closedA?.agentToEdgeBytes).not.toBe(closedB?.agentToEdgeBytes);
  });

  for (const [name, injectFault] of [
    ["server", async (fixture: EndToEndFixture): Promise<void> => fixture.restartTunnelServer()],
    ["edge WSS", async (fixture: EndToEndFixture): Promise<void> => fixture.edgeASockets.terminateLatest()],
    ["agent WSS", async (fixture: EndToEndFixture): Promise<void> => fixture.agentSockets.terminateLatest()],
    ["目标 TCP", async (fixture: EndToEndFixture): Promise<void> => fixture.destroyGatewayConnections()]
  ] as const) {
    it(`中途断开${name}会清理旧流，恢复后只能创建新流`, async () => {
      const fixture = new EndToEndFixture();
      fixtures.push(fixture);
      await fixture.start();
      const originalProbe = await fixture.openProbe(fixture.proxyA);
      await echo(originalProbe, Buffer.from("fault-before"));
      await waitFor(() => fixture.tunnel?.streamOpenCoordinator?.getActiveStreams().length === 1, "initial stream");
      const oldStreamId = Buffer.from(fixture.tunnel?.streamOpenCoordinator?.getActiveStreams()[0]?.streamId ?? []).toString("hex");

      await injectFault(fixture);
      try {
        await waitFor(
          () =>
            fixture.edgeA.activeStreamCount === 0 &&
            fixture.agentDialer.activeStreamCount === 0 &&
            fixture.tunnel?.streamOpenCoordinator?.getActiveStreams().length === 0,
          "fault cleanup"
        );
      } catch {
        throw new Error(
          `fault cleanup incomplete: edge=${fixture.edgeA.activeStreamCount}, agent=${fixture.agentDialer.activeStreamCount}, server=${fixture.tunnel.streamOpenCoordinator?.getActiveStreams().length ?? -1}`
        );
      }
      await fixture.waitForOnline();

      const recoveredProbe = await fixture.openProbe(fixture.proxyA);
      await echo(recoveredProbe, Buffer.from("fault-after"));
      await waitFor(() => fixture.tunnel?.streamOpenCoordinator?.getActiveStreams().length === 1, "recovered stream");
      const newStreamId = Buffer.from(fixture.tunnel?.streamOpenCoordinator?.getActiveStreams()[0]?.streamId ?? []).toString("hex");
      expect(newStreamId).not.toBe(oldStreamId);
      expect(recoveredProbe.socket.destroyed).toBe(false);
    });
  }
});
