import { generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  type EdgeClientRuntimeOptions,
  type EdgeClientStatusListener,
  type EdgeClientStatusSnapshot,
  type EdgeStreamControl,
  type EdgeStreamEventListener,
  type LoopbackConnectProxyOptions
} from "@remote-codex/edge-client";
import {
  createOwnerOnlyDirectoryAtPath,
  hardenOwnerOnly,
  type LoadedEdgeClientProductionBundle,
  type LoadedProductionBundle
} from "@remote-codex/ops";
import type { ValidatedDestination } from "@remote-codex/shared";
import { describe, expect, it, vi } from "vitest";

import { runEdgeClientHostCli } from "./cli.js";
import { SafeEdgeProcessLogger } from "./logging.js";
import {
  createPersistentEdgeStatusLog,
  EdgeLogError,
  type EdgeProcessLogSink
} from "./persistent-log.js";
import {
  acquireProcessLifetimeLease,
  EdgeClientHostError,
  startEdgeClientHost,
  type EdgeClientHostDependencies,
  type EdgeProxyHandle,
  type EdgeRuntimeHandle
} from "./runtime.js";

const EDGE_KEYS = generateKeyPairSync("ed25519");
const SERVER_KEYS = generateKeyPairSync("ed25519");

function bundle(
  serverUrl = "wss://tunnel.example.invalid/tunnel",
  listenPort = 8_787,
  destinationHostname = "gateway.example.invalid"
): LoadedEdgeClientProductionBundle {
  return {
    component: "edge-client",
    config: {
      component: "edge-client",
      protocolVersion: 2,
      edgeUserId: "edge-user-01",
      edgeDeviceId: "edge-device-01",
      serverUrl: new URL(serverUrl),
      listenHost: "127.0.0.1",
      listenPort,
      allowedDestination: { hostname: destinationHostname, port: 443 },
      limits: {
        maxConcurrentStreams: 4,
        maxBufferedBytesPerStream: 16_384,
        maxAggregateBufferedBytes: 65_536,
        maxFramePayloadBytes: 8_192,
        maxIdleMs: 10_000,
        connectTimeoutMs: 1_000,
        openTimeoutMs: 2_000,
        heartbeatIntervalMs: 1_000,
        heartbeatTimeoutMs: 3_000,
        reconnectInitialMs: 100,
        reconnectMaxMs: 1_000,
        maxReconnectAttempts: 3
      }
    },
    identity: {
      kind: "edge-device",
      edgeUserId: "edge-user-01",
      edgeDeviceId: "edge-device-01",
      authenticationKey: {
        role: "edge-device-authentication",
        keyId: "edge-key-secret-id",
        key: EDGE_KEYS.publicKey
      }
    },
    authenticationPrivateKey: {
      role: "edge-device-authentication",
      keyId: "edge-key-secret-id",
      key: EDGE_KEYS.privateKey
    },
    serverIdentity: {
      kind: "server",
      serverId: "public-server-01",
      capabilityVerificationKey: {
        role: "server-capability-signing",
        keyId: "server-key-secret-id",
        key: SERVER_KEYS.publicKey
      }
    }
  };
}

class FakeRuntime implements EdgeRuntimeHandle {
  public readonly start = vi.fn(() => this.emit({ state: "connecting", reconnectAttempts: 0 }));
  public readonly stop = vi.fn(() => this.emit({ state: "stopped", reconnectAttempts: this.status.reconnectAttempts }));
  public readonly open = vi.fn((destination: ValidatedDestination, listener: EdgeStreamEventListener): EdgeStreamControl => {
    void destination;
    void listener;
    return {
      send: () => false,
      pauseIncoming: () => undefined,
      resumeIncoming: () => undefined,
      close: () => undefined
    };
  });
  private readonly listeners = new Set<EdgeClientStatusListener>();
  private status: EdgeClientStatusSnapshot = { state: "offline", reconnectAttempts: 0 };

  public getStatus(): EdgeClientStatusSnapshot {
    return this.status;
  }

  public subscribeStatus(listener: EdgeClientStatusListener): () => void {
    this.listeners.add(listener);
    listener(this.status);
    return (): void => {
      this.listeners.delete(listener);
    };
  }

  public emit(status: EdgeClientStatusSnapshot): void {
    this.status = status;
    for (const listener of this.listeners) {
      listener(status);
    }
  }
}

class FakeProxy implements EdgeProxyHandle {
  public readonly start = vi.fn(async () => ({ host: "127.0.0.1" as const, port: 8_787 }));
  public readonly stop = vi.fn(async () => undefined);
}

function hostHarness(
  runtime: FakeRuntime,
  proxy: FakeProxy,
  logs: string[] = [],
  onTerminalFailure: (code: string) => void = vi.fn()
): {
  readonly dependencies: Partial<EdgeClientHostDependencies>;
  readonly closeLog: ReturnType<typeof vi.fn>;
  readonly releaseLifetime: ReturnType<typeof vi.fn>;
} {
  const closeLog = vi.fn();
  const releaseLifetime = vi.fn();
  const sink: EdgeProcessLogSink = {
    write: (line) => logs.push(line),
    close: closeLog
  };
  return {
    closeLog,
    releaseLifetime,
    dependencies: {
      loadBundle: () => bundle(),
      createRuntime: () => runtime,
      createProxy: () => proxy,
      createLogSink: () => sink,
      acquireLifetimeLease: () => ({ release: releaseLifetime }),
      onTerminalFailure
    }
  };
}

describe("edge production host", () => {
  it("默认进程 lease 使用 referenced timer 并可幂等释放", () => {
    vi.useFakeTimers();
    try {
      const lease = acquireProcessLifetimeLease();
      expect(vi.getTimerCount()).toBe(1);
      lease.release();
      lease.release();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("只把严格 edge bundle 组合成固定 Origin、WSS runtime 和 loopback CONNECT", async () => {
    const runtime = new FakeRuntime();
    const proxy = new FakeProxy();
    const logs: string[] = [];
    const harness = hostHarness(runtime, proxy, logs);
    let runtimeOptions: EdgeClientRuntimeOptions | undefined;
    let proxyOptions: LoopbackConnectProxyOptions | undefined;
    const running = await startEdgeClientHost("config-root", "manifest.json", {
      ...harness.dependencies,
      createRuntime: (options) => {
        runtimeOptions = options;
        return runtime;
      },
      createProxy: (options) => {
        proxyOptions = options;
        return proxy;
      }
    });

    expect(runtimeOptions).toMatchObject({
      origin: "https://tunnel.example.invalid",
      config: {
        edgeUserId: "edge-user-01",
        edgeDeviceId: "edge-device-01",
        serverUrl: new URL("wss://tunnel.example.invalid/tunnel")
      },
      authenticationIdentity: { kind: "edge-device", edgeDeviceId: "edge-device-01" }
    });
    expect(proxyOptions).toMatchObject({
      allowedDestination: { hostname: "gateway.example.invalid", port: 443 },
      listenPort: 8_787,
      streamGateway: runtime
    });
    expect(proxy.start).toHaveBeenCalledOnce();
    expect(runtime.start).toHaveBeenCalledOnce();
    expect(logs.join("")).not.toMatch(/tunnel\.example|gateway\.example|secret-id|127\.0\.0\.1|8787/gu);

    await running.close();
    await running.close();
    expect(runtime.stop).toHaveBeenCalledOnce();
    expect(proxy.stop).toHaveBeenCalledOnce();
    expect(harness.closeLog).toHaveBeenCalledOnce();
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();
  });

  it("接受显式非标准 Public Server 端口", async () => {
    const runtime = new FakeRuntime();
    const proxy = new FakeProxy();
    const harness = hostHarness(runtime, proxy);
    let origin: string | undefined;
    const running = await startEdgeClientHost("config-root", "manifest.json", {
      ...harness.dependencies,
      loadBundle: () => bundle("wss://tunnel.example.invalid:9443/tunnel"),
      createRuntime: (options) => {
        origin = options.origin;
        return runtime;
      }
    });
    expect(origin).toBe("https://tunnel.example.invalid:9443");
    await running.close();
  });

  it.each([
    "wss://tunnel.example.invalid:0/tunnel",
    "wss://127.0.0.1:8443/tunnel",
    "wss://tunnel.example.invalid:8443/other",
    "wss://tunnel.example.invalid:8443/tunnel?debug=true",
    "wss://user@tunnel.example.invalid:8443/tunnel"
  ])("在创建日志、runtime 或 listener 前拒绝越界 server URL: %s", async (serverUrl) => {
    const createLogSink = vi.fn();
    const createRuntime = vi.fn();
    const createProxy = vi.fn();
    await expect(startEdgeClientHost("config-root", "manifest.json", {
      loadBundle: () => bundle(serverUrl),
      createLogSink,
      createRuntime,
      createProxy
    })).rejects.toThrow(EdgeClientHostError);
    expect(createLogSink).not.toHaveBeenCalled();
    expect(createRuntime).not.toHaveBeenCalled();
    expect(createProxy).not.toHaveBeenCalled();
  });

  it("在网络动作前拒绝越界 listener、IP 目标和错误组件", async () => {
    const createProxy = vi.fn();
    await expect(startEdgeClientHost("config-root", "manifest.json", {
      loadBundle: () => bundle(undefined, 7_999),
      createProxy
    })).rejects.toThrow("EDGE_HOST_LISTENER_INVALID");
    await expect(startEdgeClientHost("config-root", "manifest.json", {
      loadBundle: () => bundle(undefined, 8_787, "127.0.0.1"),
      createProxy
    })).rejects.toThrow("EDGE_HOST_NETWORK_POLICY_INVALID");
    await expect(startEdgeClientHost("config-root", "manifest.json", {
      loadBundle: () => ({ component: "egress-agent" }) as LoadedProductionBundle,
      createProxy
    })).rejects.toThrow("EDGE_HOST_COMPONENT_MISMATCH");
    expect(createProxy).not.toHaveBeenCalled();
  });

  it("认证撤销/replay 和重试耗尽会幂等关闭 listener、WSS、stream 与进程 lease", async () => {
    for (const code of ["AUTH_UNAUTHORIZED", "AUTH_REPLAYED", "RECONNECT_LIMIT_EXCEEDED"] as const) {
      const runtime = new FakeRuntime();
      const proxy = new FakeProxy();
      const terminalFailure = vi.fn();
      const harness = hostHarness(runtime, proxy, [], terminalFailure);
      const running = await startEdgeClientHost("config-root", "manifest.json", harness.dependencies);
      runtime.emit({ state: "offline", reconnectAttempts: 3, lastErrorCode: code });
      await running.close();
      expect(runtime.stop).toHaveBeenCalledOnce();
      expect(proxy.stop).toHaveBeenCalledOnce();
      expect(harness.releaseLifetime).toHaveBeenCalledOnce();
      expect(terminalFailure).toHaveBeenCalledOnce();
      expect(terminalFailure).toHaveBeenCalledWith(code);
    }
  });

  it("runtime 订阅时已经 terminal 不会开始创建 listener", async () => {
    const runtime = new FakeRuntime();
    runtime.emit({ state: "offline", reconnectAttempts: 0, lastErrorCode: "AUTH_UNAUTHORIZED" });
    const proxy = new FakeProxy();
    const terminalFailure = vi.fn();
    const harness = hostHarness(runtime, proxy, [], terminalFailure);

    await expect(startEdgeClientHost("config-root", "manifest.json", harness.dependencies)).rejects.toThrow(
      "EDGE_HOST_TERMINATED_DURING_START"
    );
    expect(proxy.start).not.toHaveBeenCalled();
    expect(proxy.stop).toHaveBeenCalledOnce();
    expect(runtime.stop).toHaveBeenCalledOnce();
    expect(terminalFailure).toHaveBeenCalledWith("AUTH_UNAUTHORIZED");
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();
  });

  it("runtime.start 同步 terminal 会拒绝返回 running host并清理已启动 listener", async () => {
    const runtime = new FakeRuntime();
    runtime.start.mockImplementationOnce(() => {
      runtime.emit({ state: "offline", reconnectAttempts: 0, lastErrorCode: "AUTH_UNAUTHORIZED" });
    });
    const proxy = new FakeProxy();
    const logs: string[] = [];
    const terminalFailure = vi.fn();
    const harness = hostHarness(runtime, proxy, logs, terminalFailure);

    await expect(startEdgeClientHost("config-root", "manifest.json", harness.dependencies)).rejects.toThrow(
      "EDGE_HOST_TERMINATED_DURING_START"
    );
    expect(proxy.start).toHaveBeenCalledOnce();
    expect(proxy.stop).toHaveBeenCalledOnce();
    expect(runtime.start).toHaveBeenCalledOnce();
    expect(runtime.stop).toHaveBeenCalledOnce();
    expect(harness.closeLog).toHaveBeenCalledOnce();
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();
    expect(terminalFailure).toHaveBeenCalledOnce();
    expect(terminalFailure).toHaveBeenCalledWith("AUTH_UNAUTHORIZED");
    expect(logs.join("")).toContain("edge.terminal_failure");
    expect(logs.join("")).not.toContain("edge.started");
  });

  it("listener 或 runtime 启动失败会收敛已创建资源并只保留稳定错误码", async () => {
    const runtime = new FakeRuntime();
    const proxy = new FakeProxy();
    proxy.start.mockRejectedValueOnce(Object.assign(new Error("path-secret"), { code: "EADDRINUSE" }));
    const harness = hostHarness(runtime, proxy);
    await expect(startEdgeClientHost("config-root", "manifest.json", harness.dependencies)).rejects.toThrow("EADDRINUSE");
    expect(runtime.stop).toHaveBeenCalledOnce();
    expect(proxy.stop).toHaveBeenCalledOnce();
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();

    const throwingRuntime = new FakeRuntime();
    throwingRuntime.start.mockImplementationOnce(() => {
      throw Object.assign(new Error("private-key-path"), { code: "EDGE_RUNTIME_START_FAILED" });
    });
    const secondProxy = new FakeProxy();
    const secondHarness = hostHarness(throwingRuntime, secondProxy);
    await expect(startEdgeClientHost("config-root", "manifest.json", secondHarness.dependencies)).rejects.toThrow(
      "EDGE_RUNTIME_START_FAILED"
    );
    expect(secondProxy.stop).toHaveBeenCalledOnce();
    expect(throwingRuntime.stop).toHaveBeenCalledOnce();
  });

  it("单项清理抛错仍继续关闭其余资源，重复 close 不会再次执行", async () => {
    const initialExitCode = process.exitCode;
    const runtime = new FakeRuntime();
    const proxy = new FakeProxy();
    const harness = hostHarness(runtime, proxy);
    const running = await startEdgeClientHost("config-root", "manifest.json", harness.dependencies);
    runtime.stop.mockImplementationOnce(() => {
      throw new Error("runtime-stop-failure");
    });
    proxy.stop.mockRejectedValueOnce(new Error("proxy-stop-failure"));
    harness.closeLog.mockImplementationOnce(() => {
      throw new Error("log-close-failure");
    });
    harness.releaseLifetime.mockImplementationOnce(() => {
      throw new Error("lease-release-failure");
    });

    try {
      await expect(running.close()).resolves.toBeUndefined();
      await expect(running.close()).resolves.toBeUndefined();
      expect(runtime.stop).toHaveBeenCalledOnce();
      expect(proxy.stop).toHaveBeenCalledOnce();
      expect(harness.closeLog).toHaveBeenCalledOnce();
      expect(harness.releaseLifetime).toHaveBeenCalledOnce();
    } finally {
      process.exitCode = initialExitCode;
    }
  });

  it("CLI 启动失败不回显异常、路径或配置正文", async () => {
    const secret = "private-key-and-token-secret";
    const stderr: string[] = [];
    const result = await runEdgeClientHostCli(
      ["--root", secret],
      { stderr: { write: (value) => { stderr.push(String(value)); return true; } } },
      { loadBundle: (() => { throw new Error(secret); }) as () => LoadedProductionBundle }
    );
    expect(result).toBe(1);
    expect(stderr).toEqual([`${JSON.stringify({ ok: false, code: "EDGE_HOST_START_FAILED" })}\n`]);
    expect(stderr.join("")).not.toContain(secret);

    const maliciousCode = "PRIVATE_KEY_TOKEN_SECRET";
    const maliciousStderr: string[] = [];
    const maliciousResult = await runEdgeClientHostCli(
      ["--root", "config-root"],
      { stderr: { write: (value) => { maliciousStderr.push(String(value)); return true; } } },
      {
        loadBundle: (() => {
          throw Object.assign(new Error(secret), { code: maliciousCode });
        }) as () => LoadedProductionBundle
      }
    );
    expect(maliciousResult).toBe(1);
    expect(maliciousStderr).toEqual([`${JSON.stringify({ ok: false, code: "EDGE_HOST_START_FAILED" })}\n`]);
    expect(maliciousStderr.join("")).not.toContain(maliciousCode);
  });

  it("CLI 双信号与 runtime terminal 并发仍只执行一次 shutdown", async () => {
    const runtime = new FakeRuntime();
    const proxy = new FakeProxy();
    const terminalFailure = vi.fn();
    const harness = hostHarness(runtime, proxy, [], terminalFailure);
    const listeners = new Map<"SIGTERM" | "SIGINT", () => void>();
    const result = await runEdgeClientHostCli(
      ["--root", "config-root"],
      {
        stderr: { write: () => true },
        signals: {
          once: (signal, listener) => listeners.set(signal, listener)
        }
      },
      harness.dependencies
    );
    expect(result).toBe(0);

    runtime.emit({ state: "offline", reconnectAttempts: 1, lastErrorCode: "AUTH_UNAUTHORIZED" });
    listeners.get("SIGTERM")?.();
    listeners.get("SIGINT")?.();
    await vi.waitFor(() => {
      expect(proxy.stop).toHaveBeenCalledOnce();
      expect(harness.releaseLifetime).toHaveBeenCalledOnce();
    });
    expect(runtime.stop).toHaveBeenCalledOnce();
    expect(harness.closeLog).toHaveBeenCalledOnce();
    expect(terminalFailure).toHaveBeenCalledOnce();
  });
});

describe("owner-only edge 状态日志", () => {
  it("恶意 CONNECT/身份/异常状态只留下白名单字段且不回显网络或凭据", () => {
    const lines: string[] = [];
    const logger = new SafeEdgeProcessLogger((line) => lines.push(line), () => 1_000);
    logger.lifecycle("edge.state_changed", {
      state: "backoff",
      reconnectAttempts: 1,
      lastErrorCode: "PRIVATE_KEY_TOKEN_SECRET",
      connectAuthority: "gateway.example.test:443",
      headers: "Authorization: Bearer secret-token; Cookie: secret-cookie",
      edgeUserId: "secret-user-id",
      edgeDeviceId: "secret-device-id",
      keyId: "secret-key-id",
      payload: "TLS secret bytes"
    } as unknown as EdgeClientStatusSnapshot);

    expect(JSON.parse(lines.join(""))).toEqual({
      event: "edge.state_changed",
      occurredAtMs: 1_000,
      state: "backoff",
      reconnectAttempts: 1
    });
    expect(lines.join("")).not.toMatch(/secret|gateway|Authorization|Cookie|TLS/iu);
  });

  it("按字节上限轮转并只保留固定数量的脱敏 NDJSON", () => {
    const parent = mkdtempSync(join(tmpdir(), "remote-codex-edge-log-"));
    const root = join(parent, "config");
    mkdirSync(root);
    hardenOwnerOnly(root);
    try {
      const sink = createPersistentEdgeStatusLog(root, { maxBytes: 256, maxBackups: 2 });
      const logger = new SafeEdgeProcessLogger((line) => sink.write(line), () => 1_000);
      for (let attempt = 0; attempt < 12; attempt += 1) {
        logger.lifecycle("edge.state_changed", {
          state: "backoff",
          reconnectAttempts: attempt,
          lastErrorCode: "WSS_CONNECTION_FAILED"
        });
      }
      sink.close();
      const files = readdirSync(join(root, "logs")).sort();
      expect(files).toEqual(["edge-status.ndjson", "edge-status.ndjson.1", "edge-status.ndjson.2"]);
      for (const file of files) {
        const contents = readFileSync(join(root, "logs", file), "utf8");
        expect(Buffer.byteLength(contents)).toBeLessThanOrEqual(256);
        expect(contents).toContain("edge.state_changed");
        expect(contents).not.toMatch(/https?:|wss:|gateway|hostname|127\.0\.0\.1|Authorization|cookie|token|privateKey|payload/giu);
      }
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  }, 30_000);

  it("拒绝硬链接日志文件，且 writer 故障不影响状态调用方", () => {
    const parent = mkdtempSync(join(tmpdir(), "remote-codex-edge-log-link-"));
    const root = join(parent, "config");
    mkdirSync(root);
    hardenOwnerOnly(root);
    const logs = join(root, "logs");
    createOwnerOnlyDirectoryAtPath(logs);
    const target = join(root, "outside.ndjson");
    writeFileSync(target, "outside\n");
    hardenOwnerOnly(target);
    linkSync(target, join(logs, "edge-status.ndjson"));
    try {
      expect(() => createPersistentEdgeStatusLog(root)).toThrow(EdgeLogError);
      const logger = new SafeEdgeProcessLogger(() => {
        throw new Error("path-and-secret-must-not-escape");
      });
      expect(() => logger.lifecycle("edge.state_changed", {
        state: "backoff",
        reconnectAttempts: 1,
        lastErrorCode: "WSS_CONNECTION_FAILED"
      })).not.toThrow();
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  }, 30_000);

  it("轮转失败后永久禁写且重复 close 不会误关复用的 fd", () => {
    const parent = mkdtempSync(join(tmpdir(), "remote-codex-edge-log-rotate-fail-"));
    const root = join(parent, "config");
    mkdirSync(root);
    hardenOwnerOnly(root);
    let unrelatedDescriptor: number | undefined;
    try {
      const sink = createPersistentEdgeStatusLog(root, { maxBytes: 256, maxBackups: 1 });
      const logs = join(root, "logs");
      const target = join(root, "outside.ndjson");
      writeFileSync(target, "outside\n");
      hardenOwnerOnly(target);
      linkSync(target, join(logs, "edge-status.ndjson.1"));

      sink.write(`${"a".repeat(200)}\n`);
      expect(() => sink.write(`${"b".repeat(100)}\n`)).toThrow("EDGE_HOST_LOG_FILE_UNSAFE");
      expect(() => sink.write("retry\n")).toThrow("EDGE_HOST_LOG_FILE_UNSAFE");

      const unrelated = join(root, "unrelated.txt");
      writeFileSync(unrelated, "before\n");
      unrelatedDescriptor = openSync(unrelated, "a");
      sink.close();
      sink.close();
      expect(() => writeSync(unrelatedDescriptor as number, "after\n")).not.toThrow();
      closeSync(unrelatedDescriptor);
      unrelatedDescriptor = undefined;
      expect(readFileSync(unrelated, "utf8")).toContain("after");
    } finally {
      if (unrelatedDescriptor !== undefined) {
        try {
          closeSync(unrelatedDescriptor);
        } catch {
          // 断言失败清理不覆盖原始测试错误。
        }
      }
      rmSync(parent, { recursive: true, force: true });
    }
  }, 30_000);
});

describe("Windows edge 部署静态边界", () => {
  const deploymentRoot = new URL("../../deployment/windows/edge-client/", import.meta.url);
  const scripts = [
    "Install-EdgeClientTask.ps1",
    "Uninstall-EdgeClientTask.ps1",
    "Start-EdgeClientTask.ps1",
    "Stop-EdgeClientTask.ps1",
    "Test-EdgeClientStatus.ps1"
  ];

  it("所有脚本通过 PowerShell AST 解析", () => {
    for (const script of scripts) {
      const path = fileURLToPath(new URL(script, deploymentRoot)).replaceAll("'", "''");
      const command = `$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile('${path}',[ref]$tokens,[ref]$errors)>$null;if($errors.Count -ne 0){exit 1}`;
      const parsed = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", command], {
        stdio: "ignore",
        windowsHide: true
      });
      expect(parsed.status, script).toBe(0);
    }
  }, 30_000);

  it("任务固定当前普通用户、最低权限、登录触发、单实例和无限执行时长", () => {
    const install = readFileSync(new URL("Install-EdgeClientTask.ps1", deploymentRoot), "utf8");
    expect(install).toContain("-AtLogOn -User $identity.Name");
    expect(install).toContain("-LogonType Interactive -RunLevel Limited");
    expect(install).toContain("-MultipleInstances IgnoreNew");
    expect(install).toContain("-RestartCount 3");
    expect(install).toContain("-ExecutionTimeLimit ([TimeSpan]::Zero)");
    expect(install).toContain("EDGE_INSTALL_NON_ADMIN_USER_REQUIRED");
    expect(install).toContain("EDGE_TASK_OWNER_MISMATCH");
    expect(install.indexOf("EDGE_TASK_OWNER_MISMATCH")).toBeLessThan(install.indexOf("Register-ScheduledTask"));
    expect(install).not.toMatch(/RunLevel\s+Highest|LogonType\s+(?:ServiceAccount|Password)|-UserId\s+(?:SYSTEM|'SYSTEM'|[" ]SYSTEM[" ])/gu);
  });

  it("脚本不设置系统代理/防火墙、不接收命令，也不创建额外 listener", () => {
    const hostSource = readFileSync(new URL("./runtime.ts", import.meta.url), "utf8");
    const serializedScripts = scripts.map((script) => readFileSync(new URL(script, deploymentRoot), "utf8")).join("\n");
    expect(hostSource).not.toMatch(/\bcreateServer\s*\(|createConnection\s*\(|new\s+Socket\b/gu);
    expect(serializedScripts).not.toMatch(/\b(?:netsh|New-NetFirewallRule|Set-NetFirewallProfile|Set-ItemProperty|New-PSSession|Enter-PSSession|winrm)\b/giu);
    expect(serializedScripts).not.toMatch(/(?:ProxyEnable|ProxyServer|setx|--inspect|named.?pipe|Invoke-Expression|-Command\s+\$)/giu);
    expect(serializedScripts).not.toMatch(/BEGIN PRIVATE KEY|authenticationKey|capability|payload|Authorization|cookie|token/giu);
  });

  it("状态检查只接受一个 loopback listener 和一个 Public Server WSS，输出不含敏感网络字段", () => {
    const status = readFileSync(new URL("Test-EdgeClientStatus.ps1", deploymentRoot), "utf8");
    const okBlock = status.slice(status.indexOf("$ok ="), status.indexOf("[pscustomobject]@{"));
    const outputBlock = status.slice(status.indexOf("[pscustomobject]@{"));
    expect(status).toContain("$connection.LocalAddress -eq '127.0.0.1'");
    expect(status).toContain("$configuration.listenPort -lt 8000");
    expect(status).toContain("$configuration.listenPort -gt 9000");
    expect(status).toContain("$approvedListenerCount -eq 1");
    expect(status).toContain("$unexpectedListenerCount -eq 0");
    expect(status).toContain("$wssConnectionCount -eq 1");
    expect(status).toContain("$serverPendingConnectionCount += 1");
    expect(status).toContain("$localPendingConnectionCount += 1");
    expect(status).toContain("$serverPendingConnectionCount -eq 0");
    expect(status).toContain("serverPendingConnectionCount = $serverPendingConnectionCount");
    expect(status).toContain("localPendingConnectionCount = $localPendingConnectionCount");
    expect(status).not.toContain("pendingConnectionCount = $pendingConnectionCount");
    expect(okBlock).toContain("$serverPendingConnectionCount -eq 0");
    expect(okBlock).not.toContain("$localPendingConnectionCount");
    expect(status).toContain("$unexpectedConnectionCount -eq 0");
    expect(outputBlock).not.toMatch(/RemoteAddress|LocalAddress|CommandLine|serverUrl|hostname|IPAddress|credential|token/giu);
  });

  it("中文手册保留身份、会话级代理、安全收集和真实手工验收边界", () => {
    const guide = readFileSync(new URL("../../docs/operations/windows-edge-client-deployment.md", import.meta.url), "utf8");
    expect(guide).toContain("独立的 `(edgeUserId, edgeDeviceId)`");
    expect(guide).toContain("$env:HTTPS_PROXY");
    expect(guide).toContain("Remove-Item Env:HTTPS_PROXY");
    expect(guide).toContain("不声称调用了 host graceful shutdown");
    expect(guide).toContain("已从 server 撤销的设备");
    expect(guide).toContain("局域网另一台机器");
    expect(guide).toContain("edge-status.ndjson.1");
    expect(guide).toContain("1 MiB");
    expect(guide).toContain("仓库单元测试不声称已经完成这些验收");
  });
});

describe("批准测试端口静态边界", () => {
  it("deferred E2E 的 gateway、tunnel 与两个 edge proxy 共用原子端口分配器", () => {
    const fixture = readFileSync(new URL("../../server/src/end-to-end.test.ts", import.meta.url), "utf8");
    const helper = readFileSync(new URL("../../server/src/test-port-helper.ts", import.meta.url), "utf8");
    expect(fixture).toContain("const gatewayPort = await listenOnApprovedTestPort(this.gateway)");
    expect(fixture.match(/startOnApprovedTestPort\(async \(listenPort\)/gu)).toHaveLength(2);
    expect(fixture).toContain("listenPort: config.listenPort");
    expect(fixture).not.toMatch(/listenPort:\s*(?:0|8787|8788)/gu);
    expect(helper).toContain("const TEST_PORT_MIN = 8_000");
    expect(helper).toContain("const TEST_PORT_MAX = 9_000");
    expect(helper).toContain('code !== "EADDRINUSE" && code !== "EACCES"');
  });
});
