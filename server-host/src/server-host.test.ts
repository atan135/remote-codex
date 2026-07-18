import { generateKeyPairSync, type KeyPairKeyObjectResult } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { LoadedProductionBundle, LoadedServerProductionBundle } from "@remote-codex/ops";
import type { StreamMetricsSnapshot, TunnelServer, TunnelServerOptions } from "@remote-codex/server";
import { describe, expect, it, vi } from "vitest";

import { runServerHostCli } from "./cli.js";
import { SafeServerProcessLogger } from "./logging.js";
import { startServerHost } from "./runtime.js";

const SIGNING_KEYS_V1 = generateKeyPairSync("ed25519");
const SIGNING_KEYS_V2 = generateKeyPairSync("ed25519");
const PEER_KEYS_V1 = generateKeyPairSync("ed25519");
const PEER_KEYS_V2 = generateKeyPairSync("ed25519");

function hostConfig(overrides: Record<string, unknown> = {}): LoadedServerProductionBundle["hostConfig"] {
  return {
    schemaVersion: 1,
    listenHost: "0.0.0.0",
    listenPort: 8443,
    publicHostname: "tunnel.example.invalid",
    allowedOrigins: ["https://edge.example.invalid"],
    tlsCertificatePath: "tls/fullchain.pem",
    tlsPrivateKeyPath: "tls/private-key.pem",
    maxConnections: 256,
    listenBacklog: 128,
    shutdownTimeoutMs: 1_000,
    metricsIntervalMs: 10_000,
    transportLimits: {
      maxUpgradeHeaderBytes: 16_384,
      maxUpgradeHeaderCount: 64,
      maxConcurrentHandshakes: 32,
      maxTrackedConnectionAddresses: 4_096,
      maxConnectionsPerWindow: 30,
      connectionRateWindowMs: 60_000,
      handshakeTimeoutMs: 10_000,
      maxMessageBytes: 32_768
    },
    ...overrides
  } as LoadedServerProductionBundle["hostConfig"];
}

interface BundleOptions {
  readonly certificate?: string;
  readonly privateKey?: string;
  readonly hostOverrides?: Record<string, unknown>;
  readonly allowedDestinationHostname?: string;
  readonly authorizationAuditVersion?: number;
  readonly signingKeys?: KeyPairKeyObjectResult;
  readonly peerKeys?: KeyPairKeyObjectResult;
}

function bundle(options: BundleOptions = {}): LoadedServerProductionBundle {
  const signingKeys = options.signingKeys ?? SIGNING_KEYS_V1;
  return {
    component: "server",
    config: {
      component: "server",
      protocolVersion: 2,
      serverId: "server-01",
      allowedDestination: { hostname: options.allowedDestinationHostname ?? "gateway.example.invalid", port: 443 },
      limits: {
        maxConcurrentStreams: 1,
        maxBufferedBytesPerStream: 1_024,
        maxAggregateBufferedBytes: 1_024,
        maxFramePayloadBytes: 1_024,
        maxIdleMs: 1_000,
        connectTimeoutMs: 100,
        openTimeoutMs: 100,
        heartbeatIntervalMs: 100,
        heartbeatTimeoutMs: 200,
        reconnectInitialMs: 100,
        reconnectMaxMs: 100,
        maxReconnectAttempts: 0
      }
    },
    hostConfig: hostConfig(options.hostOverrides),
    tls: {
      certificate: Buffer.from(options.certificate ?? "certificate-v1"),
      privateKey: Buffer.from(options.privateKey ?? "private-key-v1")
    },
    signingCredentials: {
      identity: {
        kind: "server",
        serverId: "server-01",
        capabilityVerificationKey: {
          role: "server-capability-signing",
          keyId: "server-signing-key-01",
          key: signingKeys.publicKey
        }
      },
      capabilitySigningKey: {
        role: "server-capability-signing",
        keyId: "server-signing-key-01",
        key: signingKeys.privateKey
      }
    },
    peerIdentities: [{
      identity: {
        kind: "edge-device",
        edgeUserId: "edge-user-01",
        edgeDeviceId: "edge-device-01",
        authenticationKey: {
          role: "edge-device-authentication",
          keyId: "edge-auth-key-01",
          key: (options.peerKeys ?? PEER_KEYS_V1).publicKey
        }
      }
    }],
    authorizationDocument: { auditVersion: options.authorizationAuditVersion ?? 1, authorizations: [] }
  };
}

function fakeTunnel(): {
  readonly tunnel: TunnelServer;
  readonly setSecureContext: ReturnType<typeof vi.fn>;
  readonly close: ReturnType<typeof vi.fn>;
} {
  const setSecureContext = vi.fn();
  const close = vi.fn(async () => undefined);
  return {
    setSecureContext,
    close,
    tunnel: {
      httpsServer: {
        maxConnections: 0,
        setSecureContext,
        closeAllConnections: vi.fn()
      },
      webSocketServer: {},
      peerSessions: {},
      authorizationRegistry: {},
      close
    } as unknown as TunnelServer
  };
}

describe("server host", () => {
  it("只用严格 bundle 启动一个 8443 listener 并组合 stream 授权", async () => {
    const logs: string[] = [];
    const fake = fakeTunnel();
    let createdOptions: TunnelServerOptions | undefined;
    const listen = vi.fn(async () => undefined);
    const running = await startServerHost("deployment-root", "manifest.json", {
      loadBundle: () => bundle(),
      validateTls: () => undefined,
      createServer: (options) => {
        createdOptions = options;
        return fake.tunnel;
      },
      listen,
      writeLog: (line) => logs.push(line)
    });

    expect(listen).toHaveBeenCalledWith(fake.tunnel, "0.0.0.0", 8443, 128);
    expect(createdOptions).toMatchObject({
      allowedOrigins: ["https://edge.example.invalid"],
      peerIdentities: [expect.objectContaining({ identity: expect.objectContaining({ kind: "edge-device" }) })],
      streamAuthorization: { allowedDestination: { hostname: "gateway.example.invalid", port: 443 } }
    });
    expect(fake.tunnel.httpsServer.maxConnections).toBe(256);
    expect(running.publicWssUrl).toBe("wss://tunnel.example.invalid:8443/tunnel");
    expect(running.healthUrl).toBe("https://tunnel.example.invalid:8443/health");
    expect(logs.join("")).not.toContain("private-key-v1");
    await running.close();
    expect(fake.close).toHaveBeenCalledOnce();
  });

  it("TLS reload 只接受证书内容变化，所有 non-TLS 安全状态变化都要求重启", async () => {
    const logs: string[] = [];
    const fake = fakeTunnel();
    const bundles: LoadedProductionBundle[] = [
      bundle(),
      bundle({ certificate: "certificate-v2", privateKey: "private-key-v2" }),
      bundle({
        certificate: "certificate-v3",
        privateKey: "private-key-v3",
        allowedDestinationHostname: "other.example.invalid"
      }),
      bundle({ certificate: "certificate-v4", privateKey: "private-key-v4", authorizationAuditVersion: 2 }),
      bundle({ certificate: "certificate-v5", privateKey: "private-key-v5", signingKeys: SIGNING_KEYS_V2 }),
      bundle({ certificate: "certificate-v6", privateKey: "private-key-v6", peerKeys: PEER_KEYS_V2 }),
      bundle({ certificate: "certificate-v7", privateKey: "private-key-v7", hostOverrides: { listenPort: 8444 } })
    ];
    const running = await startServerHost("deployment-root", "manifest.json", {
      loadBundle: () => bundles.shift() ?? bundle(),
      validateTls: () => undefined,
      createServer: () => fake.tunnel,
      listen: async () => undefined,
      writeLog: (line) => logs.push(line)
    });

    await expect(running.reloadTls()).resolves.toBe(true);
    expect(fake.setSecureContext).toHaveBeenCalledWith(expect.objectContaining({ minVersion: "TLSv1.3" }));
    await expect(running.reloadTls()).resolves.toBe(false);
    await expect(running.reloadTls()).resolves.toBe(false);
    await expect(running.reloadTls()).resolves.toBe(false);
    await expect(running.reloadTls()).resolves.toBe(false);
    await expect(running.reloadTls()).resolves.toBe(false);
    expect(fake.setSecureContext).toHaveBeenCalledTimes(1);
    expect(logs.join("")).toContain("SERVER_HOST_RELOAD_REQUIRES_RESTART");
    expect(logs.join("")).not.toContain("private-key-v2");
    expect(logs.join("")).not.toContain("private-key-v3");
    expect(logs.join("")).not.toContain("private-key-v4");
    expect(logs.join("")).not.toContain("private-key-v5");
    expect(logs.join("")).not.toContain("private-key-v6");
    await running.close();
  });

  it("启动失败只输出稳定错误码，不回显异常正文或 CLI 输入", async () => {
    const secret = "private-key-secret-path";
    const stderr: string[] = [];
    const result = await runServerHostCli(
      ["--root", secret],
      { stderr: { write: (value) => { stderr.push(String(value)); return true; } } },
      {
        loadBundle: () => { throw new Error(secret); },
        writeLog: () => undefined
      }
    );
    expect(result).toBe(1);
    expect(stderr).toEqual([`${JSON.stringify({ ok: false, code: "SERVER_HOST_START_FAILED" })}\n`]);
    expect(stderr.join("")).not.toContain(secret);
  });
});

describe("进程日志白名单", () => {
  it("过滤审计扩展字段和无效指标键", () => {
    const lines: string[] = [];
    const logger = new SafeServerProcessLogger((line) => lines.push(line), () => 1_000);
    logger.audit(JSON.stringify({
      event: "stream.closed",
      streamId: "stream-01",
      state: "closed",
      durationMs: 10,
      payload: "GET /secret",
      authorization: "Bearer token",
      cookie: "session=secret",
      privateKey: "secret-key"
    }));
    logger.metrics({
      authenticatedEdgePeers: 1,
      authenticatedAgentPeers: 1,
      activeStreamsByAgent: { "agent-01": 1, "unsafe key": 2 },
      rejectedStreamsByEdgeUser: {},
      closedStreamsByReason: { NORMAL: 1 },
      bufferWatermark: { currentBytes: 0, peakBytes: 1, limitBytes: 1_024 }
    } satisfies StreamMetricsSnapshot);

    const serialized = lines.join("");
    expect(serialized).toContain("stream-01");
    expect(serialized).toContain("agent-01");
    expect(serialized).not.toContain("unsafe key");
    expect(serialized).not.toContain("GET /secret");
    expect(serialized).not.toContain("Bearer token");
    expect(serialized).not.toContain("session=secret");
    expect(serialized).not.toContain("secret-key");
  });
});

describe("Linux 部署模板", () => {
  it("只启动一个受限 server 进程并提供证书 reload 与手工边界检查", () => {
    const deploymentRoot = new URL("../../deployment/linux/server/", import.meta.url);
    const service = readFileSync(new URL("remote-codex-server.service", deploymentRoot), "utf8");
    const reloadPath = readFileSync(new URL("remote-codex-server-cert-reload.path", deploymentRoot), "utf8");
    const reloadService = readFileSync(new URL("remote-codex-server-cert-reload.service", deploymentRoot), "utf8");
    const journald = readFileSync(new URL("journald-remote-codex.conf", deploymentRoot), "utf8");
    const verification = readFileSync(new URL("verify-public-server.sh", deploymentRoot), "utf8");

    expect(service.match(/^ExecStart=/gmu)).toHaveLength(1);
    expect(service).toContain("User=remote-codex");
    expect(service).toContain("Restart=on-failure");
    expect(service).toContain("MemoryMax=512M");
    expect(service).toContain("LimitNOFILE=4096");
    expect(service).toContain("After=network-online.target time-sync.target");
    expect(service).not.toContain("--inspect");
    expect(service).not.toContain("remote-client");
    expect(reloadPath).toContain("tls/fullchain.pem");
    expect(reloadPath).toContain("tls/private-key.pem");
    expect(reloadService).toContain("--signal=HUP remote-codex-server.service");
    expect(journald).toContain("SystemMaxUse=1G");
    expect(journald).toContain("MaxRetentionSec=14day");
    expect(verification).toContain("port < 8000 || port > 9000");
    expect(verification).toContain("validate-public-input.mjs");
    expect(verification).toContain('expect_code 404 "${base}/metrics"');
    expect(verification).toContain('expect_code 426 "${base}/tunnel"');
    expect(verification).not.toContain("--insecure");
  });

  it("手工检查参数拒绝 userinfo、IP、通配符、连续点和 URL 扩展部分", () => {
    const validator = fileURLToPath(new URL(
      "../../deployment/linux/server/validate-public-input.mjs",
      import.meta.url
    ));
    const validate = (host: string, origin: string): number | null => spawnSync(process.execPath, [validator], {
      env: {
        ...process.env,
        REMOTE_CODEX_VERIFY_HOST: host,
        REMOTE_CODEX_VERIFY_ORIGIN: origin
      },
      stdio: "ignore"
    }).status;

    expect(validate("tunnel.example.invalid", "https://edge.example.invalid")).toBe(0);
    expect(validate("tunnel..example.invalid", "https://edge.example.invalid")).not.toBe(0);
    expect(validate("127.0.0.1", "https://edge.example.invalid")).not.toBe(0);
    expect(validate("*.example.invalid", "https://edge.example.invalid")).not.toBe(0);
    expect(validate("tunnel.example.invalid", "https://user:pass@edge.example.invalid")).not.toBe(0);
    expect(validate("tunnel.example.invalid", "https://127.0.0.1")).not.toBe(0);
    expect(validate("tunnel.example.invalid", "https://*.example.invalid")).not.toBe(0);
    expect(validate("tunnel.example.invalid", "https://edge..example.invalid")).not.toBe(0);
    expect(validate("tunnel.example.invalid", "https://edge.example.invalid/path")).not.toBe(0);
    expect(validate("tunnel.example.invalid", "https://edge.example.invalid?query=1")).not.toBe(0);
    expect(validate("tunnel.example.invalid", "https://edge.example.invalid#fragment")).not.toBe(0);
  });
});
