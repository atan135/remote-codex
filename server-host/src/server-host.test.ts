import { generateKeyPairSync, type KeyPairKeyObjectResult } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { LoadedProductionBundle, LoadedServerProductionBundle } from "@remote-codex/ops";
import type { StreamMetricsSnapshot, TunnelServer, TunnelServerOptions } from "@remote-codex/server";
import { StreamCloseCode, StreamState, TunnelErrorCode } from "@remote-codex/shared";
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
    schemaVersion: 2,
    listenHost: "127.0.0.1",
    listenPort: 8443,
    publicHostname: "tunnel.example.invalid",
    publicPort: 443,
    allowedOrigins: ["https://edge.example.invalid"],
    tlsCertificatePath: "tls/fullchain.pem",
    tlsPrivateKeyPath: "tls/private-key.pem",
    tlsMinimumVersion: "TLSv1.3",
    clientAddressSource: "loopback-x-forwarded-for",
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
  it("以 loopback 后端启动并公开 Nginx 的 443 URL", async () => {
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

    expect(listen).toHaveBeenCalledWith(fake.tunnel, "127.0.0.1", 8443, 128);
    expect(createdOptions).toMatchObject({
      tlsMinimumVersion: "TLSv1.3",
      clientAddressSource: "loopback-x-forwarded-for",
      allowedOrigins: ["https://edge.example.invalid"],
      peerIdentities: [expect.objectContaining({ identity: expect.objectContaining({ kind: "edge-device" }) })],
      streamAuthorization: { allowedDestination: { hostname: "gateway.example.invalid", port: 443 } }
    });
    expect(fake.tunnel.httpsServer.maxConnections).toBe(256);
    expect(running.publicWssUrl).toBe("wss://tunnel.example.invalid/tunnel");
    expect(running.healthUrl).toBe("https://tunnel.example.invalid/health");
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

    const maliciousCode = "PRIVATE_KEY_TOKEN_SECRET";
    const maliciousStderr: string[] = [];
    const maliciousResult = await runServerHostCli(
      ["--root", "config-root"],
      { stderr: { write: (value) => { maliciousStderr.push(String(value)); return true; } } },
      {
        loadBundle: () => { throw Object.assign(new Error(secret), { code: maliciousCode }); },
        writeLog: () => undefined
      }
    );
    expect(maliciousResult).toBe(1);
    expect(maliciousStderr).toEqual([`${JSON.stringify({ ok: false, code: "SERVER_HOST_START_FAILED" })}\n`]);
    expect(maliciousStderr.join("")).not.toContain(maliciousCode);
  });

  it("started 日志 writer 故障不遗留 listener 且不干扰 reload 或幂等 shutdown", async () => {
    const fake = fakeTunnel();
    const running = await startServerHost("deployment-root", "manifest.json", {
      loadBundle: () => bundle(),
      validateTls: () => undefined,
      createServer: () => fake.tunnel,
      listen: async () => undefined,
      writeLog: () => {
        throw new Error("injected-log-writer-failure");
      }
    });

    await expect(running.reloadTls()).resolves.toBe(true);
    await expect(running.close()).resolves.toBeUndefined();
    await expect(running.close()).resolves.toBeUndefined();
    expect(fake.close).toHaveBeenCalledOnce();
  });
});

describe("进程日志白名单", () => {
  it("过滤审计扩展字段和无效指标键", () => {
    const lines: string[] = [];
    const logger = new SafeServerProcessLogger((line) => lines.push(line), () => 1_000);
    logger.audit(JSON.stringify({
      event: "stream.closed",
      occurredAtMs: 1_000,
      streamId: "stream-01",
      state: "closed",
      durationMs: 10,
      payload: "GET /secret",
      authorization: "Bearer token",
      cookie: "session=secret",
      privateKey: "secret-key"
    }));
    logger.lifecycle("server.started", {
      listenPort: 8_443,
      listenHost: "0.0.0.0",
      publicWssUrl: "wss://secret-host.example.test:8443/tunnel",
      code: "PRIVATE_KEY_TOKEN_SECRET"
    } as unknown as { readonly code?: string; readonly listenPort?: number });
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
    expect(serialized).not.toContain("0.0.0.0");
    expect(serialized).not.toContain("secret-host.example.test");
    expect(serialized).not.toContain("PRIVATE_KEY_TOKEN_SECRET");
  });

  it("保留全部合法 StreamState、隧道错误码与 close code，同时丢弃未知 code", () => {
    const lines: string[] = [];
    const logger = new SafeServerProcessLogger((line) => lines.push(line), () => 1_000);
    let sequence = 0;

    for (const state of Object.values(StreamState)) {
      logger.audit(JSON.stringify({
        event: "stream.state",
        occurredAtMs: 1_000 + sequence,
        streamId: `stream-state-${sequence}`,
        edgePeerId: "edge-peer-1",
        state
      }));
      sequence += 1;
    }
    for (const errorCode of Object.values(TunnelErrorCode)) {
      logger.audit(JSON.stringify({
        event: "stream.rejected",
        occurredAtMs: 1_000 + sequence,
        streamId: `stream-error-${sequence}`,
        edgePeerId: "edge-peer-1",
        state: StreamState.REJECTED,
        errorCode
      }));
      sequence += 1;
    }
    for (const closeCode of Object.values(StreamCloseCode)) {
      logger.audit(JSON.stringify({
        event: "stream.closed",
        occurredAtMs: 1_000 + sequence,
        streamId: `stream-close-${sequence}`,
        edgePeerId: "edge-peer-1",
        state: StreamState.CLOSED,
        closeCode
      }));
      sequence += 1;
    }
    logger.audit(JSON.stringify({
      event: "stream.rejected",
      occurredAtMs: 9_999,
      streamId: "stream-malicious",
      edgePeerId: "edge-peer-1",
      state: StreamState.REJECTED,
      errorCode: "PRIVATE_KEY_TOKEN_SECRET",
      closeCode: "CAPABILITY_SECRET"
    }));

    const records = lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(records.slice(0, Object.values(StreamState).length).map((record) => record.state)).toEqual(
      Object.values(StreamState)
    );
    expect(records.map((record) => record.errorCode).filter((code) => code !== undefined)).toEqual(
      Object.values(TunnelErrorCode)
    );
    expect(records.map((record) => record.closeCode).filter((code) => code !== undefined)).toEqual(
      Object.values(StreamCloseCode)
    );
    expect(lines.join("")).not.toMatch(/PRIVATE_KEY_TOKEN_SECRET|CAPABILITY_SECRET/u);
  });

  it("throwing writer 对 lifecycle、audit 和 metrics 均保持失败隔离", () => {
    const logger = new SafeServerProcessLogger(() => {
      throw new Error("injected-writer-failure");
    }, () => 1_000);
    const metrics: StreamMetricsSnapshot = {
      authenticatedEdgePeers: 1,
      authenticatedAgentPeers: 1,
      activeStreamsByAgent: { "agent-1": 1 },
      rejectedStreamsByEdgeUser: { "user-1": 1 },
      closedStreamsByReason: { NORMAL: 1 },
      bufferWatermark: { currentBytes: 0, peakBytes: 1, limitBytes: 1_024 }
    };

    expect(() => logger.lifecycle("server.started", { listenPort: 8_443 })).not.toThrow();
    expect(() => logger.audit(JSON.stringify({
      event: "stream.closed",
      occurredAtMs: 1_000,
      streamId: "stream-1",
      edgePeerId: "edge-peer-1",
      state: StreamState.CLOSED,
      closeCode: StreamCloseCode.NORMAL
    }))).not.toThrow();
    expect(() => logger.metrics(metrics)).not.toThrow();
  });
});

describe("Linux 部署模板", () => {
  it("以受限 Nginx 公开入口、loopback server 与证书 reload 组成部署模板", () => {
    const deploymentRoot = new URL("../../deployment/linux/server/", import.meta.url);
    const nginxRoot = new URL("../../deployment/linux/nginx/", import.meta.url);
    const service = readFileSync(new URL("remote-codex-server.service", deploymentRoot), "utf8");
    const reloadPath = readFileSync(new URL("remote-codex-server-cert-reload.path", deploymentRoot), "utf8");
    const reloadService = readFileSync(new URL("remote-codex-server-cert-reload.service", deploymentRoot), "utf8");
    const journald = readFileSync(new URL("journald-remote-codex.conf", deploymentRoot), "utf8");
    const verification = readFileSync(new URL("verify-public-server.sh", deploymentRoot), "utf8");
    const nginx = readFileSync(new URL("remote-codex.conf", nginxRoot), "utf8");

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
    expect(nginx).toContain("listen 443 ssl http2");
    expect(nginx).toContain("proxy_pass https://127.0.0.1:8443");
    expect(nginx).toContain("proxy_set_header X-Forwarded-For $remote_addr");
    expect(nginx).toContain("proxy_ssl_verify on");
    expect(nginx).not.toContain("proxy_add_x_forwarded_for");
    expect(verification).toContain("port < 1 || port > 65535");
    expect(verification).toContain("validate-public-input.mjs");
    expect(verification).toContain('expect_code 404 "${base}/metrics"');
    expect(verification).toContain('expect_code 426 "${base}/tunnel"');
    expect(verification).toContain("--tls-max 1.1");
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
  }, 20_000);
});
