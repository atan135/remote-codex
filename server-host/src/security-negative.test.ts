import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../", import.meta.url));

function read(relativePath: string): string {
  return readFileSync(join(REPOSITORY_ROOT, relativePath), "utf8");
}

function filesWithExtensions(relativeDirectory: string, extensions: ReadonlySet<string>): readonly string[] {
  const root = join(REPOSITORY_ROOT, relativeDirectory);
  const files: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(path);
      } else if ([...extensions].some((extension) => entry.name.endsWith(extension))) {
        files.push(path);
      }
    }
  };
  visit(root);
  return Object.freeze(files.sort());
}

describe("阶段 6 生产暴露面静态审计", () => {
  it("只有 server 提供公开 TLS/WSS，edge 固定 loopback CONNECT，agent 仅受限出站拨号", () => {
    const serverRuntime = read("server/src/runtime.ts");
    const serverHostRuntime = read("server-host/src/runtime.ts");
    const edgeProxy = read("edge-client/src/connect-proxy.ts");
    const edgeHostRuntime = read("edge-client-host/src/runtime.ts");
    const agentRuntime = read("egress-agent/src/runtime.ts");
    const agentDialer = read("egress-agent/src/dialer.ts");
    const agentHostRuntime = read("egress-agent-host/src/runtime.ts");

    expect(serverRuntime).toContain('import { createServer, type Server as HttpsServer } from "node:https"');
    expect(serverRuntime).toContain('import { isIP } from "node:net"');
    expect(serverRuntime).toContain("request.url === HEALTH_CHECK_PATH");
    expect(serverRuntime).toContain("request.url === TUNNEL_WEBSOCKET_PATH");
    expect(serverRuntime).not.toMatch(/(?:\.connect|createConnection)\s*\(/u);
    expect(serverHostRuntime).toContain("server.httpsServer.listen({ host, port, backlog, exclusive: true })");

    expect(edgeProxy).toContain('export const LOOPBACK_LISTEN_HOST = "127.0.0.1"');
    expect(edgeProxy).toContain("this.server.listen({ host: LOOPBACK_LISTEN_HOST, port: this.listenPort");
    expect(edgeHostRuntime).toContain("bundle.config.listenHost !== LOOPBACK_LISTEN_HOST");
    expect(edgeProxy).not.toMatch(/0\.0\.0\.0|\[?::\]?/u);

    const agentSurface = `${agentRuntime}\n${agentDialer}\n${agentHostRuntime}`;
    expect(agentSurface).not.toMatch(/\bcreateServer\s*\(|\.listen\s*\(|node:http|node:https|node:http2/u);
    expect(agentDialer).toContain("socket.connect({ host: destination.hostname, port: destination.port })");
    expect(agentDialer).toContain("validateDestination(payload.hostname, payload.port, this.config.allowedDestination)");
  });

  it("生产 runtime 不包含 SOCKS、任意命令、文件接口、调试或额外代理入口", () => {
    const productionFiles = [
      ...filesWithExtensions("server/src", new Set([".ts"])),
      ...filesWithExtensions("server-host/src", new Set([".ts"])),
      ...filesWithExtensions("egress-agent/src", new Set([".ts"])),
      ...filesWithExtensions("egress-agent-host/src", new Set([".ts"])),
      ...filesWithExtensions("edge-client/src", new Set([".ts"])),
      ...filesWithExtensions("edge-client-host/src", new Set([".ts"]))
    ].filter((path) => !path.endsWith(".test.ts") && !path.endsWith("test-port-helper.ts"));
    const source = productionFiles.map((path) => readFileSync(path, "utf8")).join("\n");

    expect(source).not.toMatch(/node:child_process|node:vm|\beval\s*\(|\bnew\s+Function\b|--inspect|node:inspector/iu);
    expect(source).not.toMatch(/\bSOCKS5?\b|\/debug\b|\/inspect\b|\/exec\b|\/shell\b|\/files?\b|\/proxy\b/iu);
    expect(source).not.toContain("remote-client");
  });

  it("部署模板不放宽防火墙/系统代理，也不启动调试器或任意 shell", () => {
    const deploymentFiles = filesWithExtensions(
      "deployment",
      new Set([".ps1", ".service", ".path", ".sh", ".mjs"])
    );
    const deployment = deploymentFiles.map((path) => readFileSync(path, "utf8")).join("\n");
    const serverService = read("deployment/linux/server/remote-codex-server.service");

    expect(serverService.match(/^ExecStart=/gmu)).toHaveLength(1);
    expect(serverService).toContain("NoNewPrivileges=true");
    expect(serverService).toContain("CapabilityBoundingSet=");
    expect(deployment).not.toMatch(
      /node:child_process|node:vm|\beval\s*\(|\bnew\s+Function\b|Invoke-Expression|Start-Process|\bcmd(?:\.exe)?\b|powershell\.exe|--inspect|node:inspector/iu
    );
    expect(deployment).not.toMatch(/New-NetFirewallRule|Set-NetFirewallProfile|netsh|ProxyEnable|ProxyServer|Internet Settings/iu);
    expect(deployment).not.toMatch(/\bSOCKS5?\b|remote-client/iu);
  });
});
