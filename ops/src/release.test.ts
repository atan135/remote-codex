import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { OpsError } from "./errors.js";
import {
  createReleaseInventory,
  parseReleasePolicyJson,
  stageReleaseCandidate,
  validateReleaseInventory,
  type ReleasePolicy
} from "./release.js";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const POLICY_PATH = join(REPOSITORY_ROOT, "deployment", "release-policy.json");
const POLICY_JSON = readFileSync(POLICY_PATH, "utf8");
const POLICY = parseReleasePolicyJson(POLICY_JSON);
const TEMPORARY_ROOTS: string[] = [];

function temporaryDirectory(): string {
  const root = mkdtempSync(join(tmpdir(), "remote-codex-release-"));
  TEMPORARY_ROOTS.push(root);
  return root;
}

function write(root: string, path: string, contents: string): void {
  const absolutePath = join(root, ...path.split("/"));
  mkdirSync(dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, contents, "utf8");
}

function source(path: string): string {
  return readFileSync(join(REPOSITORY_ROOT, ...path.split("/")), "utf8");
}

function addPolicyFields(root: string, fields: Readonly<Record<string, unknown>>): void {
  const path = join(root, "deployment", "release-policy.json");
  const policy = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  writeFileSync(path, `${JSON.stringify({ ...policy, ...fields }, null, 2)}\n`, "utf8");
}

function createCandidate(policy: ReleasePolicy = POLICY): { readonly parent: string; readonly root: string; readonly inventory: string } {
  const parent = temporaryDirectory();
  const root = join(parent, "candidate");
  mkdirSync(root);
  for (const path of policy.staticFiles) {
    write(root, path, source(path));
  }
  for (const workspace of policy.workspaces) {
    write(root, `${workspace.directory}/package.json`, source(`${workspace.directory}/package.json`));
    for (const moduleName of workspace.modules) {
      write(root, `${workspace.directory}/dist/${moduleName}.js`,
        workspace.directory === "shared" && moduleName === "config"
          ? "export const PROTOCOL_VERSION = 2;\n"
          : workspace.directory === "ops" && moduleName === "schema"
            ? "export const PRODUCTION_MANIFEST_SCHEMA_VERSION = 2;\n"
            : workspace.directory === "ops" && moduleName === "server-host"
              ? "export const SERVER_HOST_CONFIG_SCHEMA_VERSION = 2;\n"
          : "export {};\n");
    }
  }
  return { parent, root, inventory: join(parent, "inventory.json") };
}

function expectReleaseError(action: () => unknown, code: string): void {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(OpsError);
  expect(caught).toMatchObject({ code });
}

afterEach(() => {
  while (TEMPORARY_ROOTS.length > 0) {
    rmSync(TEMPORARY_ROOTS.pop() as string, { recursive: true, force: true });
  }
});

describe("release 策略与清单", () => {
  it("策略只包含预期 workspace，且声明的仓库输入存在", () => {
    expect(POLICY.workspaces.filter(({ role }) => role === "production").map(({ directory }) => directory).sort()).toEqual([
      "edge-client-host", "egress-agent-host", "ops", "server-host"
    ]);
    for (const path of POLICY.staticFiles) {
      expect(() => readFileSync(join(REPOSITORY_ROOT, ...path.split("/")))).not.toThrow();
    }
    for (const workspace of POLICY.workspaces) {
      for (const moduleName of workspace.modules) {
        expect(() => readFileSync(join(REPOSITORY_ROOT, workspace.directory, "src", `${moduleName}.ts`))).not.toThrow();
      }
    }
  });

  it("为有效 allowlist 候选生成确定性 SHA-256 清单并重新验证", () => {
    const fixture = createCandidate();
    const created = createReleaseInventory(fixture.root, POLICY_PATH, fixture.inventory);
    const verified = validateReleaseInventory(fixture.root, POLICY_PATH, fixture.inventory);
    expect(created).toEqual(verified);
    expect(created).toMatchObject({ ok: true, releaseVersion: "0.1.0", protocolVersion: 2 });
    expect(created.fileCount).toBeGreaterThan(70);
    expect(created.aggregateSha256).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("从构建树只暂存 policy 中的生产运行文件", () => {
    const sourceFixture = createCandidate();
    write(sourceFixture.root, "server/dist/end-to-end.test.js", "fixture token and header\n");
    write(sourceFixture.root, "server/dist/runtime.js.map", "{}\n");
    const staged = join(sourceFixture.parent, "staged");
    const inventory = join(sourceFixture.parent, "staged-inventory.json");
    const result = stageReleaseCandidate(sourceFixture.root, POLICY_PATH, staged);
    expect(result).toMatchObject({ ok: true, releaseVersion: "0.1.0", protocolVersion: 2 });
    expect(() => readFileSync(join(staged, "server", "dist", "end-to-end.test.js"))).toThrow();
    expect(() => readFileSync(join(staged, "server", "dist", "runtime.js.map"))).toThrow();
    createReleaseInventory(staged, POLICY_PATH, inventory);
    expect(validateReleaseInventory(staged, POLICY_PATH, inventory)).toEqual(result);
  });

  it("stage 中途失败只清理本次创建的 output，且不删除预先存在目录", () => {
    const incomplete = createCandidate();
    rmSync(join(incomplete.root, "shared", "dist", "stream.js"));
    const partialOutput = join(incomplete.parent, "partial-output");
    expectReleaseError(
      () => stageReleaseCandidate(incomplete.root, POLICY_PATH, partialOutput),
      "OPS_RELEASE_STAGE_COPY_FAILED"
    );
    expect(existsSync(partialOutput)).toBe(false);

    const existing = createCandidate();
    const existingOutput = join(existing.parent, "existing-output");
    mkdirSync(existingOutput);
    writeFileSync(join(existingOutput, "owner-marker.txt"), "owner\n", "utf8");
    expectReleaseError(
      () => stageReleaseCandidate(existing.root, POLICY_PATH, existingOutput),
      "OPS_RELEASE_STAGE_OUTPUT_EXISTS"
    );
    expect(readFileSync(join(existingOutput, "owner-marker.txt"), "utf8")).toBe("owner\n");
  });

  it("拒绝缺失 dist 和未知文件", () => {
    const missing = createCandidate();
    rmSync(join(missing.root, "server-host", "dist", "cli-main.js"));
    expectReleaseError(() => createReleaseInventory(missing.root, POLICY_PATH, missing.inventory), "OPS_RELEASE_FILE_SET_MISMATCH");

    const unknown = createCandidate();
    write(unknown.root, "unexpected.txt", "unexpected\n");
    expectReleaseError(() => createReleaseInventory(unknown.root, POLICY_PATH, unknown.inventory), "OPS_RELEASE_FILE_SET_MISMATCH");
  });

  it("拒绝 test、测试辅助、source map、类型声明与构建缓存进入生产 dist", () => {
    for (const path of [
      "server/dist/end-to-end.test.js",
      "server/dist/test-port-helper.js",
      "server-host/dist/security-negative.test.js",
      "edge-client-host/dist/edge-client-host.test.js",
      "shared/dist/config.js.map",
      "shared/dist/config.d.ts",
      "shared/dist/.tsbuildinfo",
      "ops/coverage/coverage-final.json"
    ]) {
      const fixture = createCandidate();
      write(fixture.root, path, "{}\n");
      expectReleaseError(() => createReleaseInventory(fixture.root, POLICY_PATH, fixture.inventory), "OPS_RELEASE_FILE_SET_MISMATCH");
    }
  });

  it("拒绝私钥、证书、.env 和秘密正文", () => {
    for (const path of ["keys/private.pem", "tls/server.crt", ".env.production"]) {
      const fixture = createCandidate();
      write(fixture.root, path, "secret\n");
      expectReleaseError(() => createReleaseInventory(fixture.root, POLICY_PATH, fixture.inventory), "OPS_RELEASE_SECRET_FILE_REJECTED");
    }
    const content = createCandidate();
    write(content.root, "README.md", "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n");
    expectReleaseError(() => createReleaseInventory(content.root, POLICY_PATH, content.inventory), "OPS_RELEASE_SECRET_CONTENT_REJECTED");
  });

  it("拒绝凭据 header、常见凭据赋值和 token 正文", () => {
    for (const contents of [
      "Authorization: Bearer actual-release-credential\n",
      "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\n",
      "Cookie: session=actual-release-cookie\n",
      "const password = \"actual-release-password\";\n",
      "sk-1234567890abcdefghijklmnop\n"
    ]) {
      const fixture = createCandidate();
      write(fixture.root, "README.md", contents);
      expectReleaseError(
        () => createReleaseInventory(fixture.root, POLICY_PATH, fixture.inventory),
        "OPS_RELEASE_CREDENTIAL_CONTENT_REJECTED"
      );
    }
  });

  it("拒绝范围外 listener、remote-client 依赖和协议/schema 版本漂移", () => {
    const port = createCandidate();
    addPolicyFields(port.root, { listenPort: 0 });
    expectReleaseError(() => createReleaseInventory(port.root, POLICY_PATH, port.inventory), "OPS_RELEASE_LISTEN_PORT_REJECTED");

    const publicListener = createCandidate();
    addPolicyFields(publicListener.root, { listenHost: "::1" });
    expectReleaseError(() => createReleaseInventory(publicListener.root, POLICY_PATH, publicListener.inventory), "OPS_RELEASE_LISTEN_HOST_REJECTED");

    for (const allowedDestination of [
      { hostname: "127.0.0.1", port: 443 },
      { hostname: "*.example.invalid", port: 443 },
      { hostname: "Gateway.Example.Invalid", port: 443 },
      { hostname: "gateway.example.invalid", port: 443, fallbackPort: 8443 }
    ]) {
      const destination = createCandidate();
      addPolicyFields(destination.root, { allowedDestination });
      expectReleaseError(
        () => createReleaseInventory(destination.root, POLICY_PATH, destination.inventory),
        "OPS_RELEASE_DESTINATION_REJECTED"
      );
    }

    for (const serverUrl of [
      "wss://127.0.0.1/tunnel",
      "wss://*.example.invalid/tunnel",
      "wss://Tunnel.Example.Invalid/tunnel"
    ]) {
      const server = createCandidate();
      addPolicyFields(server.root, { serverUrl });
      expectReleaseError(
        () => createReleaseInventory(server.root, POLICY_PATH, server.inventory),
        "OPS_RELEASE_SERVER_URL_REJECTED"
      );
    }

    const dependency = createCandidate();
    const packagePath = join(dependency.root, "edge-client-host", "package.json");
    const packageDocument = JSON.parse(readFileSync(packagePath, "utf8")) as Record<string, unknown>;
    const dependencies = packageDocument.dependencies as Record<string, string>;
    writeFileSync(packagePath, `${JSON.stringify({
      ...packageDocument,
      dependencies: { ...dependencies, "remote-client": "1.0.0" }
    }, null, 2)}\n`, "utf8");
    expectReleaseError(() => createReleaseInventory(dependency.root, POLICY_PATH, dependency.inventory), "OPS_RELEASE_REMOTE_CLIENT_DEPENDENCY_REJECTED");

    const protocol = createCandidate();
    write(protocol.root, "shared/dist/config.js", "export const PROTOCOL_VERSION = 1;\n");
    expectReleaseError(() => createReleaseInventory(protocol.root, POLICY_PATH, protocol.inventory), "OPS_RELEASE_PROTOCOL_VERSION_MISMATCH");

    const schema = createCandidate();
    write(schema.root, "ops/dist/schema.js", "export const PRODUCTION_MANIFEST_SCHEMA_VERSION = 3;\n");
    expectReleaseError(() => createReleaseInventory(schema.root, POLICY_PATH, schema.inventory), "OPS_RELEASE_CONFIG_SCHEMA_MISMATCH");
  });

  it("拒绝符号链接以及清单生成后的文件篡改", () => {
    const linked = createCandidate();
    const target = join(linked.parent, "outside-directory");
    mkdirSync(target);
    symlinkSync(target, join(linked.root, "unexpected-link"), process.platform === "win32" ? "junction" : "dir");
    expectReleaseError(() => createReleaseInventory(linked.root, POLICY_PATH, linked.inventory), "OPS_RELEASE_SYMLINK_REJECTED");

    const tampered = createCandidate();
    createReleaseInventory(tampered.root, POLICY_PATH, tampered.inventory);
    write(tampered.root, "README.md", `${source("README.md")}\n`);
    expectReleaseError(() => validateReleaseInventory(tampered.root, POLICY_PATH, tampered.inventory), "OPS_RELEASE_INVENTORY_MISMATCH");
  });
});
