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

import type {
  EgressAgentRuntimeOptions,
  EgressAgentStatusListener,
  EgressAgentStatusSnapshot
} from "@remote-codex/egress-agent";
import {
  createOwnerOnlyDirectoryAtPath,
  hardenOwnerOnly,
  type LoadedEgressAgentProductionBundle,
  type LoadedProductionBundle
} from "@remote-codex/ops";
import { describe, expect, it, vi } from "vitest";

import { runEgressAgentHostCli } from "./cli.js";
import {
  acquireProcessLifetimeLease,
  EgressAgentHostError,
  startEgressAgentHost,
  type EgressAgentHostDependencies,
  type EgressAgentRuntimeHandle
} from "./runtime.js";
import { SafeEgressAgentProcessLogger } from "./logging.js";
import {
  createPersistentAgentStatusLog,
  EgressAgentLogError,
  type AgentProcessLogSink
} from "./persistent-log.js";

const AGENT_KEYS = generateKeyPairSync("ed25519");
const SERVER_KEYS = generateKeyPairSync("ed25519");

function bundle(serverUrl = "wss://tunnel.example.invalid:8443/tunnel"): LoadedEgressAgentProductionBundle {
  return {
    component: "egress-agent",
    config: {
      component: "egress-agent",
      protocolVersion: 2,
      agentId: "company-agent-01",
      serverUrl: new URL(serverUrl),
      allowedDestination: { hostname: "gateway.example.invalid", port: 443 },
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
      kind: "egress-agent",
      agentId: "company-agent-01",
      authenticationKey: {
        role: "egress-agent-authentication",
        keyId: "agent-key-secret-id",
        key: AGENT_KEYS.publicKey
      }
    },
    authenticationPrivateKey: {
      role: "egress-agent-authentication",
      keyId: "agent-key-secret-id",
      key: AGENT_KEYS.privateKey
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

class FakeRuntime implements EgressAgentRuntimeHandle {
  public readonly start = vi.fn(() => this.emit({ state: "connecting", reconnectAttempts: 0 }));
  public readonly stop = vi.fn(() => this.emit({ state: "stopped", reconnectAttempts: this.status.reconnectAttempts }));
  private readonly listeners = new Set<EgressAgentStatusListener>();
  private status: EgressAgentStatusSnapshot = { state: "offline", reconnectAttempts: 0 };

  public getStatus(): EgressAgentStatusSnapshot {
    return this.status;
  }

  public subscribeStatus(listener: EgressAgentStatusListener): () => void {
    this.listeners.add(listener);
    listener(this.status);
    return (): void => {
      this.listeners.delete(listener);
    };
  }

  public emit(status: EgressAgentStatusSnapshot): void {
    this.status = status;
    for (const listener of this.listeners) {
      listener(status);
    }
  }
}

function hostHarness(
  runtime: FakeRuntime,
  logs: string[] = [],
  onTerminalFailure: (code: string) => void = vi.fn()
): {
  readonly dependencies: Partial<EgressAgentHostDependencies>;
  readonly closeLog: ReturnType<typeof vi.fn>;
  readonly releaseLifetime: ReturnType<typeof vi.fn>;
} {
  const closeLog = vi.fn();
  const releaseLifetime = vi.fn();
  const sink: AgentProcessLogSink = {
    write: (line) => logs.push(line),
    close: closeLog
  };
  return {
    closeLog,
    releaseLifetime,
    dependencies: {
      loadBundle: () => bundle(),
      createRuntime: () => runtime,
      createLogSink: () => sink,
      acquireLifetimeLease: () => ({ release: releaseLifetime }),
      onTerminalFailure
    }
  };
}

describe("egress agent production host", () => {
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

  it("只把严格生产 bundle 组合成 WSS runtime 与最终受限 dialer", () => {
    const runtime = new FakeRuntime();
    let options: EgressAgentRuntimeOptions | undefined;
    const logs: string[] = [];
    const harness = hostHarness(runtime, logs);
    const running = startEgressAgentHost("config-root", "manifest.json", {
      ...harness.dependencies,
      createRuntime: (createdOptions) => {
        options = createdOptions;
        return runtime;
      }
    });

    expect(options).toMatchObject({
      origin: "https://tunnel.example.invalid:8443",
      config: {
        agentId: "company-agent-01",
        serverUrl: new URL("wss://tunnel.example.invalid:8443/tunnel"),
        allowedDestination: { hostname: "gateway.example.invalid", port: 443 }
      },
      authenticationIdentity: { kind: "egress-agent", agentId: "company-agent-01" },
      capabilityServerIdentity: { kind: "server", serverId: "public-server-01" }
    });
    expect(options).not.toHaveProperty("connector");
    expect(runtime.start).toHaveBeenCalledOnce();
    const serializedLogs = logs.join("");
    expect(serializedLogs).not.toContain("tunnel.example.invalid");
    expect(serializedLogs).not.toContain("gateway.example.invalid");
    expect(serializedLogs).not.toContain("secret-id");

    running.close();
    running.close();
    expect(runtime.stop).toHaveBeenCalledOnce();
    expect(harness.closeLog).toHaveBeenCalledOnce();
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();
    expect(running.getStatus()).toEqual({ state: "stopped", reconnectAttempts: 0 });
  });

  it.each([
    "wss://tunnel.example.invalid/tunnel",
    "wss://tunnel.example.invalid:7999/tunnel",
    "wss://tunnel.example.invalid:9001/tunnel",
    "wss://127.0.0.1:8443/tunnel",
    "wss://tunnel.example.invalid:8443/other",
    "wss://tunnel.example.invalid:8443/tunnel?debug=true"
  ])("在创建 socket 前拒绝越界 Public Server URL: %s", (serverUrl) => {
    const createRuntime = vi.fn(() => new FakeRuntime());
    expect(() => startEgressAgentHost("config-root", "manifest.json", {
      loadBundle: () => bundle(serverUrl),
      createRuntime,
      onTerminalFailure: vi.fn()
    })).toThrow(EgressAgentHostError);
    expect(createRuntime).not.toHaveBeenCalled();
  });

  it("记录有界重连和撤销状态，终止错误只触发一次失败退出", () => {
    const runtime = new FakeRuntime();
    const logs: string[] = [];
    const terminalFailures: string[] = [];
    const harness = hostHarness(runtime, logs, (code) => terminalFailures.push(code));
    harness.closeLog.mockImplementation(() => {
      throw new Error("injected-log-close-failure");
    });
    const running = startEgressAgentHost("config-root", "manifest.json", harness.dependencies);

    runtime.emit({ state: "backoff", reconnectAttempts: 1, lastErrorCode: "WSS_CONNECTION_FAILED" });
    expect(harness.releaseLifetime).not.toHaveBeenCalled();
    expect(harness.closeLog).not.toHaveBeenCalled();
    runtime.emit({ state: "connecting", reconnectAttempts: 1 });
    runtime.emit({ state: "offline", reconnectAttempts: 1, lastErrorCode: "AUTH_UNAUTHORIZED" });
    runtime.emit({ state: "offline", reconnectAttempts: 1, lastErrorCode: "AUTH_UNAUTHORIZED" });

    expect(terminalFailures).toEqual(["AUTH_UNAUTHORIZED"]);
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();
    expect(harness.closeLog).toHaveBeenCalledOnce();
    const serialized = logs.join("");
    expect(serialized).toContain("WSS_CONNECTION_FAILED");
    expect(serialized).toContain("AUTH_UNAUTHORIZED");
    expect(serialized).toContain('"reconnectAttempts":1');
    expect(serialized).not.toContain("serverUrl");
    expect(serialized).not.toContain("allowedDestination");
    running.close();
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();
    expect(harness.closeLog).toHaveBeenCalledOnce();
  });

  it("证书失败/Server 不可用耗尽后以稳定错误退出，重启停止保持幂等", () => {
    const runtime = new FakeRuntime();
    const terminalFailure = vi.fn();
    const harness = hostHarness(runtime, [], terminalFailure);
    const running = startEgressAgentHost("config-root", "manifest.json", harness.dependencies);
    runtime.emit({ state: "backoff", reconnectAttempts: 3, lastErrorCode: "WSS_CONNECTION_FAILED" });
    expect(harness.releaseLifetime).not.toHaveBeenCalled();
    runtime.emit({ state: "offline", reconnectAttempts: 3, lastErrorCode: "RECONNECT_LIMIT_EXCEEDED" });
    expect(terminalFailure).toHaveBeenCalledWith("RECONNECT_LIMIT_EXCEEDED");
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();
    running.close();
    running.close();
    expect(runtime.stop).toHaveBeenCalledOnce();
    expect(harness.releaseLifetime).toHaveBeenCalledOnce();
  });

  it("启动失败只输出稳定错误码，不回显异常、路径或完整配置", () => {
    const secret = "private-key-and-token-secret";
    const stderr: string[] = [];
    const result = runEgressAgentHostCli(
      ["--root", secret],
      { stderr: { write: (value) => { stderr.push(String(value)); return true; } } },
      {
        loadBundle: (() => { throw new Error(secret); }) as () => LoadedProductionBundle
      }
    );

    expect(result).toBe(1);
    expect(stderr).toEqual([`${JSON.stringify({ ok: false, code: "AGENT_HOST_START_FAILED" })}\n`]);
    expect(stderr.join("")).not.toContain(secret);
  });
});

describe("owner-only 持久状态日志", () => {
  it("按字节上限轮转并只保留固定数量的脱敏 NDJSON 文件", () => {
    const parent = mkdtempSync(join(tmpdir(), "remote-codex-agent-log-"));
    const root = join(parent, "config");
    mkdirSync(root);
    hardenOwnerOnly(root);
    try {
      const sink = createPersistentAgentStatusLog(root, { maxBytes: 256, maxBackups: 2 });
      const logger = new SafeEgressAgentProcessLogger((line) => sink.write(line), () => 1_000);
      for (let attempt = 0; attempt < 12; attempt += 1) {
        logger.lifecycle("agent.state_changed", {
          state: "backoff",
          reconnectAttempts: attempt,
          lastErrorCode: "WSS_CONNECTION_FAILED"
        });
      }
      sink.close();

      const files = readdirSync(join(root, "logs")).sort();
      expect(files).toEqual([
        "agent-status.ndjson",
        "agent-status.ndjson.1",
        "agent-status.ndjson.2"
      ]);
      for (const file of files) {
        const contents = readFileSync(join(root, "logs", file), "utf8");
        expect(Buffer.byteLength(contents)).toBeLessThanOrEqual(256);
        expect(contents).toContain("agent.state_changed");
        expect(contents).not.toMatch(/https?:|wss:|gateway|Authorization|privateKey|payload/giu);
      }
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  }, 30_000);

  it("拒绝硬链接日志文件，且 writer 故障不会影响状态调用方", () => {
    const parent = mkdtempSync(join(tmpdir(), "remote-codex-agent-log-link-"));
    const root = join(parent, "config");
    mkdirSync(root);
    hardenOwnerOnly(root);
    const logs = join(root, "logs");
    createOwnerOnlyDirectoryAtPath(logs);
    const target = join(root, "outside.ndjson");
    writeFileSync(target, "outside\n");
    hardenOwnerOnly(target);
    linkSync(target, join(logs, "agent-status.ndjson"));
    try {
      expect(() => createPersistentAgentStatusLog(root)).toThrow(EgressAgentLogError);
      const logger = new SafeEgressAgentProcessLogger(() => {
        throw new Error("path-and-secret-must-not-escape");
      });
      expect(() => logger.lifecycle("agent.state_changed", {
        state: "backoff",
        reconnectAttempts: 1,
        lastErrorCode: "WSS_CONNECTION_FAILED"
      })).not.toThrow();
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  }, 30_000);

  it("轮转失败后永久禁写且重复 close 不会误关复用的 fd", () => {
    const parent = mkdtempSync(join(tmpdir(), "remote-codex-agent-log-rotate-fail-"));
    const root = join(parent, "config");
    mkdirSync(root);
    hardenOwnerOnly(root);
    let unrelatedDescriptor: number | undefined;
    try {
      const sink = createPersistentAgentStatusLog(root, { maxBytes: 256, maxBackups: 1 });
      const logs = join(root, "logs");
      const target = join(root, "outside.ndjson");
      writeFileSync(target, "outside\n");
      hardenOwnerOnly(target);
      linkSync(target, join(logs, "agent-status.ndjson.1"));

      sink.write(`${"a".repeat(200)}\n`);
      expect(() => sink.write(`${"b".repeat(100)}\n`)).toThrow("AGENT_HOST_LOG_FILE_UNSAFE");
      expect(() => sink.write("retry\n")).toThrow("AGENT_HOST_LOG_FILE_UNSAFE");

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

describe("Windows 部署静态边界", () => {
  const deploymentRoot = new URL("../../deployment/windows/egress-agent/", import.meta.url);
  const scripts = [
    "Install-EgressAgentTask.ps1",
    "Uninstall-EgressAgentTask.ps1",
    "Start-EgressAgentTask.ps1",
    "Stop-EgressAgentTask.ps1",
    "Test-EgressAgentNetwork.ps1"
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

  it("任务计划固定当前普通用户、最低权限、登录触发、单实例和有界失败重启", () => {
    const install = readFileSync(new URL("Install-EgressAgentTask.ps1", deploymentRoot), "utf8");
    expect(install).toContain("-AtLogOn -User $identity.Name");
    expect(install).toContain("-LogonType Interactive -RunLevel Limited");
    expect(install).toContain("-MultipleInstances IgnoreNew");
    expect(install).toContain("-RestartCount 3");
    expect(install).toContain("-ExecutionTimeLimit ([TimeSpan]::Zero)");
    expect(install).not.toContain("New-TimeSpan -Days");
    expect(install).toContain("AGENT_INSTALL_NON_ADMIN_USER_REQUIRED");
    expect(install).toContain("$existingTask = Get-ScheduledTask");
    expect(install).toContain("AGENT_TASK_OWNER_MISMATCH");
    expect(install.indexOf("AGENT_TASK_OWNER_MISMATCH")).toBeLessThan(install.indexOf("Register-ScheduledTask"));
    expect(install).not.toMatch(/RunLevel\s+Highest|LogonType\s+(?:ServiceAccount|Password)|-UserId\s+(?:SYSTEM|'SYSTEM'|["]SYSTEM["])/gu);
    expect(install).not.toMatch(/private\.pem|BEGIN PRIVATE KEY|authenticationKey|capability|token/giu);
  });

  it("脚本不创建 listener、系统代理、防火墙放宽或远程控制面", () => {
    const hostSource = readFileSync(new URL("./runtime.ts", import.meta.url), "utf8");
    const serializedScripts = scripts
      .map((script) => readFileSync(new URL(script, deploymentRoot), "utf8"))
      .join("\n");
    expect(hostSource).not.toMatch(/\bcreateServer\s*\(|\.listen\s*\(|createConnection\s*\(|new\s+Socket\b/gu);
    expect(serializedScripts).not.toMatch(
      /\b(?:netsh|New-NetFirewallRule|Set-NetFirewallProfile|Set-ItemProperty|New-PSSession|Enter-PSSession|winrm|Set-WinSystemLocale)\b/giu
    );
    expect(serializedScripts).not.toMatch(/(?:HTTP_PROXY|HTTPS_PROXY|ProxyEnable|ProxyServer|--inspect|named.?pipe)/giu);
  });

  it("只读网络检查不输出 URL、hostname、IP、命令行或凭据", () => {
    const networkCheck = readFileSync(new URL("Test-EgressAgentNetwork.ps1", deploymentRoot), "utf8");
    const outputBlock = networkCheck.slice(networkCheck.indexOf("[pscustomobject]@{"));
    expect(networkCheck).toContain("Get-NetTCPConnection");
    expect(networkCheck).toContain("$connection.State -eq 'Listen'");
    expect(networkCheck).toContain("$serverUri.Port -lt 8000");
    expect(networkCheck).toContain("$serverUri.Port -gt 9000");
    expect(networkCheck).toContain("$connection.RemotePort -eq 443");
    expect(networkCheck).toContain("$connection.State -eq 'Established'");
    expect(networkCheck).toContain("$connection.RemotePort -eq 0");
    expect(networkCheck).toContain("if (-not $approvedServer -and -not $approvedGateway)");
    expect(networkCheck.indexOf("if (-not $approvedServer -and -not $approvedGateway)")).toBeLessThan(
      networkCheck.indexOf("if ($approvedServer)")
    );
    expect(networkCheck).toContain("$staleConnectionCount += 1");
    expect(networkCheck).toContain("$taskOwned -and");
    expect(networkCheck).toContain("$taskRunning -and");
    expect(networkCheck).toContain("$processes.Count -eq 1");
    expect(networkCheck).toContain("$wssConnectionCount -eq 1");
    expect(networkCheck).toContain("$staleConnectionCount -eq 0");
    expect(outputBlock).not.toMatch(/RemoteAddress|CommandLine|serverUrl|hostname|IPAddress|credential|token/giu);
  });

  it("停止脚本等待强制终止完成且不声称发送 Node 信号", () => {
    const stop = readFileSync(new URL("Stop-EgressAgentTask.ps1", deploymentRoot), "utf8");
    expect(stop).toContain("Stop-ScheduledTask");
    expect(stop).toContain("AddSeconds(15)");
    expect(stop).toContain("AGENT_TASK_STOP_TIMEOUT");
    expect(stop).toContain("agent_task_force_stop_confirmed");
    expect(stop).not.toMatch(/SIGTERM|SIGINT|graceful/giu);
  });

  it("中文手册保留真实公司 egress 与 SNI 的手工验收边界", () => {
    const guide = readFileSync(
      new URL("../../docs/operations/windows-egress-agent-deployment.md", import.meta.url),
      "utf8"
    );
    expect(guide).toContain("Server 暂时不可用");
    expect(guide).toContain("证书错误");
    expect(guide).toContain("Agent 凭据撤销");
    expect(guide).toContain("进程重启");
    expect(guide).toContain("agent-status.ndjson.1");
    expect(guide).toContain("1 MiB");
    expect(guide).toContain("不声称执行了 host graceful shutdown");
    expect(guide).toContain("公司网络");
    expect(guide).toContain("不能由本地");
    expect(guide).not.toContain("NODE_TLS_REJECT_UNAUTHORIZED=0` 以");
  });
});
