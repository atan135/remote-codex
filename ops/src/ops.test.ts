import { generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  DEFAULT_ALLOWED_DESTINATION,
  IdentityKeyRole
} from "@remote-codex/shared";
import { describe, expect, it } from "vitest";

import {
  changeAuthorizationFileWithSecurity,
  verifyAuthorizationAuditTrail,
  verifyAuthorizationAuditTrailWithSecurity
} from "./authorization-files.js";
import { runCli, type CliDependencies } from "./cli.js";
import { runCliMain } from "./cli-main.js";
import { OpsError } from "./errors.js";
import { generateIdentityFiles } from "./identity-files.js";
import {
  loadPeerIdentityRegistryWithSecurity,
  loadProductionBundleWithSecurity
} from "./production-loader.js";
import {
  createOwnerOnlyDirectory,
  createOwnerOnlyDirectoryAtPath,
  evaluatePosixDirectoryMode,
  evaluatePosixMode,
  hardenOwnerOnly,
  windowsAclTrusteesAreOwnerOnly,
  writeNewFile
} from "./secure-files.js";
import type { FileSecurityAdapter } from "./secure-files.js";
import { parsePeerIdentityRegistryJson, parseProductionManifestJson } from "./schema.js";
import { parseServerHostConfigJson } from "./server-host.js";

const FAST_TEST_SECURITY: FileSecurityAdapter = Object.freeze({
  assertSecureFile: () => undefined,
  hardenOwnerOnly: () => undefined
});

function temporaryRoot(realSecurity = false): string {
  const root = mkdtempSync(join(tmpdir(), "remote-codex-ops-"));
  if (realSecurity) {
    hardenOwnerOnly(root);
  }
  return root;
}

function makePathBroad(filePath: string): void {
  if (process.platform === "win32") {
    execFileSync("icacls.exe", [filePath, "/grant", "*S-1-1-0:(R)"], { stdio: "ignore", windowsHide: true });
    return;
  }
  chmodSync(filePath, 0o755);
}

function expectOpsError(action: () => unknown, code: string): OpsError {
  let caught: unknown;
  try {
    action();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(OpsError);
  expect(caught).toMatchObject({ code });
  return caught as OpsError;
}

function writeOwnerFile(root: string, relativePath: string, value: unknown): void {
  writeNewFile(
    join(root, relativePath),
    `${JSON.stringify(value, null, 2)}\n`,
    "owner-only",
    FAST_TEST_SECURITY
  );
}

function runtimeLimits(): undefined {
  return undefined;
}

function cliDependencies(): CliDependencies {
  return {
    loadProductionBundle: (() => ({ component: "edge-client" }) as never) as CliDependencies["loadProductionBundle"],
    generateIdentityFiles: ((input) => Object.freeze({
      role: input.role,
      keyId: input.keyId,
      publicKeyPath: `${input.outputDirectory}/public.pem`,
      privateKeyPath: `${input.outputDirectory}/private.pem`,
      descriptorPath: `${input.outputDirectory}/identity.json`
    })) as CliDependencies["generateIdentityFiles"],
    verifyAuthorizationAuditTrail: (() => Object.freeze({
      auditVersion: 4,
      archivedVersions: Object.freeze([1, 2, 3, 4])
    })) as CliDependencies["verifyAuthorizationAuditTrail"],
    changeAuthorizationFile: (() => ({ auditVersion: 5, authorizations: [] }) as never) as CliDependencies["changeAuthorizationFile"],
    createReleaseInventory: (() => Object.freeze({
      ok: true,
      releaseVersion: "0.1.0",
      protocolVersion: 2,
      fileCount: 120,
      byteCount: 1024,
      aggregateSha256: "a".repeat(64)
    })) as CliDependencies["createReleaseInventory"],
    stageReleaseCandidate: (() => Object.freeze({
      ok: true,
      releaseVersion: "0.1.0",
      protocolVersion: 2,
      fileCount: 120,
      byteCount: 1024,
      aggregateSha256: "a".repeat(64)
    })) as CliDependencies["stageReleaseCandidate"],
    validateReleaseInventory: (() => Object.freeze({
      ok: true,
      releaseVersion: "0.1.0",
      protocolVersion: 2,
      fileCount: 120,
      byteCount: 1024,
      aggregateSha256: "a".repeat(64)
    })) as CliDependencies["validateReleaseInventory"]
  };
}

describe("离线 CLI", () => {
  it("分发合法 deployment、identity 和 authorization 命令且只返回脱敏元数据", () => {
    const dependencies = cliDependencies();
    expect(runCli([
      "deployment", "validate", "--root", "deployment-root", "--manifest", "manifest.json"
    ], dependencies)).toEqual({ ok: true, component: "edge-client" });

    expect(runCli([
      "release", "validate", "--root", "release-root", "--policy", "policy.json", "--inventory", "inventory.json"
    ], dependencies)).toMatchObject({ ok: true, releaseVersion: "0.1.0", protocolVersion: 2, fileCount: 120 });

    const identity = runCli([
      "identity", "generate",
      "--root", "deployment-root",
      "--output-directory", "keys/edge-01",
      "--role", IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION,
      "--key-id", "edge-key-01"
    ], dependencies);
    expect(identity).toMatchObject({ role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-key-01" });
    expect(JSON.stringify(identity)).not.toContain("BEGIN PRIVATE KEY");

    expect(runCli([
      "authorization", "grant",
      "--root", "deployment-root",
      "--authorizations", "authorizations.json",
      "--peers", "peers.json",
      "--history", "history",
      "--edge-user-id", "user-01",
      "--edge-device-id", "device-01",
      "--agent-id", "agent-01",
      "--max-concurrent-streams", "2",
      "--max-buffered-bytes", "32768",
      "--now-ms", "1000"
    ], dependencies)).toEqual({ ok: true, auditVersion: 5 });
  });

  it("拒绝未知或缺失参数，main 输出稳定错误 JSON 且不回显输入", () => {
    const secret = "super-secret-token";
    const unknown = expectOpsError(
      () => runCli([
        "deployment", "validate",
        "--root", "deployment-root",
        "--manifest", "manifest.json",
        "--token", secret
      ], cliDependencies()),
      "OPS_CLI_UNKNOWN_ARGUMENT"
    );
    expect(unknown.message).not.toContain(secret);
    expectOpsError(
      () => runCli(["deployment", "validate", "--root", "deployment-root"], cliDependencies()),
      "OPS_CLI_ARGUMENT_REQUIRED"
    );

    const stdout: string[] = [];
    const stderr: string[] = [];
    const privateKeyText = "BEGIN PRIVATE KEY secret material";
    const exitCode = runCliMain(
      ["deployment", "validate", "--root", privateKeyText],
      {
        stdout: { write: (value) => stdout.push(value) },
        stderr: { write: (value) => stderr.push(value) }
      },
      cliDependencies()
    );
    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual([`${JSON.stringify({ ok: false, code: "OPS_CLI_ARGUMENT_REQUIRED" })}\n`]);
    expect(stderr.join("")).not.toContain(privateKeyText);
  });
});

describe("生产 manifest 与最小权限", () => {
  it("支持 loopback Nginx 反代并严格限制代理信任边界与传输资源", () => {
    const valid = {
      schemaVersion: 2,
      listenHost: "127.0.0.1",
      listenPort: 8443,
      publicHostname: "tunnel.example.invalid",
      publicPort: 443,
      allowedOrigins: ["https://tunnel.example.invalid"],
      tlsCertificatePath: "tls/fullchain.pem",
      tlsPrivateKeyPath: "tls/private-key.pem",
      tlsMinimumVersion: "TLSv1.3",
      clientAddressSource: "loopback-x-forwarded-for",
      maxConnections: 256,
      listenBacklog: 128,
      shutdownTimeoutMs: 15_000,
      metricsIntervalMs: 60_000,
      transportLimits: {
        maxUpgradeHeaderBytes: 16_384,
        maxUpgradeHeaderCount: 64,
        maxConcurrentHandshakes: 32,
        maxTrackedConnectionAddresses: 4_096,
        maxConnectionsPerWindow: 30,
        connectionRateWindowMs: 60_000,
        handshakeTimeoutMs: 10_000,
        maxMessageBytes: 32_768
      }
    };
    expect(parseServerHostConfigJson(JSON.stringify(valid))).toMatchObject({
      listenHost: "127.0.0.1",
      listenPort: 8443,
      publicHostname: "tunnel.example.invalid",
      publicPort: 443
    });
    expect(parseServerHostConfigJson(JSON.stringify({ ...valid, listenPort: 443 })).listenPort).toBe(443);
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({ ...valid, publicHostname: "127.0.0.1" })),
      "OPS_SERVER_PUBLIC_HOSTNAME_INVALID"
    );
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({ ...valid, publicHostname: "*.example.invalid" })),
      "OPS_SERVER_PUBLIC_HOSTNAME_INVALID"
    );
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({ ...valid, allowedOrigins: ["http://edge.example.invalid"] })),
      "OPS_SERVER_ORIGIN_INVALID"
    );
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({ ...valid, allowedOrigins: ["https://127.0.0.1"] })),
      "OPS_SERVER_ORIGIN_INVALID"
    );
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({ ...valid, listenHost: "0.0.0.0", publicPort: 8443 })),
      "OPS_SERVER_PROXY_SOURCE_REQUIRES_LOOPBACK"
    );
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({ ...valid, clientAddressSource: "socket", listenHost: "0.0.0.0" })),
      "OPS_SERVER_PUBLIC_PORT_MISMATCH"
    );
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({ ...valid, tlsMinimumVersion: "TLSv1.1" })),
      "OPS_SERVER_TLS_MINIMUM_VERSION_INVALID"
    );
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({
        ...valid,
        transportLimits: { ...valid.transportLimits, maxConcurrentHandshakes: 33 }
      })),
      "OPS_SERVER_HOST_INTEGER_INVALID"
    );
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({
        ...valid,
        transportLimits: { ...valid.transportLimits, connectionRateWindowMs: 1 }
      })),
      "OPS_SERVER_HOST_INTEGER_INVALID"
    );
    expect(parseServerHostConfigJson(JSON.stringify({
      ...valid,
      transportLimits: { ...valid.transportLimits, connectionRateWindowMs: 120_000 }
    })).transportLimits.connectionRateWindowMs).toBe(120_000);
    expectOpsError(
      () => parseServerHostConfigJson(JSON.stringify({ ...valid, token: "must-not-be-accepted" })),
      "OPS_UNKNOWN_FIELD"
    );
  });

  it("严格拒绝未知字段、角色错配和宽松路径", () => {
    const base = {
      schemaVersion: 2,
      component: "egress-agent",
      serverId: "public-server-01",
      configPath: "config.json",
      authenticationKey: {
        role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION,
        keyId: "agent-key-01",
        publicKeyPath: "keys/agent/public.pem",
        privateKeyPath: "keys/agent/private.pem"
      },
      serverCapabilityVerificationKey: {
        role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING,
        keyId: "server-key-01",
        publicKeyPath: "keys/server/public.pem"
      }
    };
    expectOpsError(
      () => parseProductionManifestJson(JSON.stringify({ ...base, schemaVersion: 1 })),
      "OPS_MANIFEST_VERSION_MISMATCH"
    );
    expectOpsError(() => parseProductionManifestJson(JSON.stringify({ ...base, token: "must-not-echo" })), "OPS_UNKNOWN_FIELD");
    expectOpsError(
      () => parseProductionManifestJson(JSON.stringify({ ...base, authenticationKey: { ...base.authenticationKey, role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION } })),
      "OPS_IDENTITY_ROLE_MISMATCH"
    );
    expectOpsError(
      () => parseProductionManifestJson(JSON.stringify({
        ...base,
        authenticationKey: { ...base.authenticationKey, privateKeyPath: base.authenticationKey.publicKeyPath }
      })),
      "OPS_IDENTITY_KEY_PATH_CONFLICT"
    );
    expectOpsError(
      () => parseProductionManifestJson(JSON.stringify({ ...base, configPath: "../other/config.json" })),
      "OPS_PATH_NOT_STRICTLY_RELATIVE"
    );
    expectOpsError(
      () => parseProductionManifestJson(JSON.stringify({ ...base, configPath: "config.json:alternate" })),
      "OPS_PATH_NOT_STRICTLY_RELATIVE"
    );
  });

  it("按 owner-only 和只读公钥策略判定 POSIX mode", () => {
    expect(evaluatePosixMode(0o600, "owner-only")).toBe(true);
    expect(evaluatePosixMode(0o640, "owner-only")).toBe(false);
    expect(evaluatePosixMode(0o644, "public-readonly")).toBe(true);
    expect(evaluatePosixMode(0o666, "public-readonly")).toBe(false);
    expect(evaluatePosixDirectoryMode(0o700)).toBe(true);
    expect(evaluatePosixDirectoryMode(0o600)).toBe(false);
    expect(evaluatePosixDirectoryMode(0o750)).toBe(false);
    const currentSid = "S-1-5-21-1000";
    expect(windowsAclTrusteesAreOwnerOnly([], currentSid)).toBe(false);
    expect(windowsAclTrusteesAreOwnerOnly([currentSid, "SY"], currentSid)).toBe(true);
    expect(windowsAclTrusteesAreOwnerOnly([currentSid, "S-1-1-0"], currentSid)).toBe(false);
    expect(windowsAclTrusteesAreOwnerOnly([currentSid], "not-a-sid")).toBe(false);
  });

  it("拒绝宽松父目录，并在 harden 失败时清理新文件和空目录", () => {
    const root = temporaryRoot(true);
    try {
      const broadDirectory = createOwnerOnlyDirectory(root, "broad-parent");
      makePathBroad(broadDirectory);
      expectOpsError(() => createOwnerOnlyDirectory(root, "broad-parent/child"), "OPS_FILE_PERMISSIONS_TOO_BROAD");

      const failedFile = join(root, "failed-private.pem");
      expectOpsError(
        () => writeNewFile(failedFile, "private material", "owner-only", {
          ...FAST_TEST_SECURITY,
          hardenOwnerOnly: () => { throw new OpsError("OPS_TEST_HARDEN_FAILED"); }
        }),
        "OPS_TEST_HARDEN_FAILED"
      );
      expect(existsSync(failedFile)).toBe(false);

      if (process.platform === "win32") {
        const failedFinalValidationFile = join(root, "failed-final-validation.pem");
        expectOpsError(
          () => writeNewFile(
            failedFinalValidationFile,
            "private material",
            "owner-only",
            {
              ...FAST_TEST_SECURITY,
              hardenOwnerOnly: (filePath) => hardenOwnerOnly(
                filePath,
                () => { throw new OpsError("OPS_TEST_EMPTY_ACL"); }
              )
            }
          ),
          "OPS_WINDOWS_ACL_HARDEN_FAILED"
        );
        expect(existsSync(failedFinalValidationFile)).toBe(false);
      }

      const failedDirectory = join(root, "failed-directory");
      expectOpsError(
        () => createOwnerOnlyDirectoryAtPath(failedDirectory, {
          ...FAST_TEST_SECURITY,
          hardenOwnerOnly: () => { throw new OpsError("OPS_TEST_HARDEN_FAILED"); }
        }),
        "OPS_TEST_HARDEN_FAILED"
      );
      expect(existsSync(failedDirectory)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
  }, 60_000);

describe("独立身份材料", () => {
  it("生成不可覆盖且不在返回值中暴露 PEM 的 Ed25519 文件", () => {
    const root = temporaryRoot(true);
    try {
      const generated = generateIdentityFiles({
        rootDirectory: root,
        outputDirectory: "edge-key-01",
        role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION,
        keyId: "edge-key-01"
      });
      expect(generated).toEqual({
        role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION,
        keyId: "edge-key-01",
        publicKeyPath: "edge-key-01/public.pem",
        privateKeyPath: "edge-key-01/private.pem",
        descriptorPath: "edge-key-01/identity.json"
      });
      expect(JSON.stringify(generated)).not.toContain("PRIVATE KEY");
      expect(readFileSync(join(root, generated.privateKeyPath), "utf8")).toContain("PRIVATE KEY");
      expectOpsError(
        () => generateIdentityFiles({ rootDirectory: root, outputDirectory: "edge-key-01", role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-key-01" }),
        "OPS_FILE_ALREADY_EXISTS"
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);

  it("agent 私钥不能构造 server capability 签名凭据", () => {
    const agentKeys = generateKeyPairSync("ed25519");
    const serverKeys = generateKeyPairSync("ed25519");
    const serverIdentity = createServerSigningIdentity({
      serverId: "server-01",
      capabilityVerificationKey: createIdentityPublicKey(
        { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: "server-key" },
        serverKeys.publicKey
      )
    });
    const agentPrivate = createIdentityPrivateKey(
      { role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: "agent-key" },
      agentKeys.privateKey
    );
    expect(() => createServerSigningCredentials({ identity: serverIdentity, capabilitySigningKey: agentPrivate as never })).toThrow(
      "IDENTITY_KEY_ROLE_MISMATCH"
    );
  });
});

describe("离线生产 bundle 校验", () => {
  it("组合 server host、TLS、签名身份和授权材料", () => {
    const root = temporaryRoot(true);
    try {
      const server = generateIdentityFiles({
        rootDirectory: root,
        outputDirectory: "server",
        role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING,
        keyId: "server-key"
      });
      createOwnerOnlyDirectory(root, "tls");
      writeNewFile(join(root, "tls/fullchain.pem"), "certificate", "public-readonly", FAST_TEST_SECURITY);
      writeNewFile(join(root, "tls/private-key.pem"), "private-key", "owner-only", FAST_TEST_SECURITY);
      writeOwnerFile(root, "manifest.json", {
        schemaVersion: 2,
        component: "server",
        configPath: "config.json",
        hostConfigPath: "host.json",
        peerIdentityRegistryPath: "peer-identities.json",
        authorizationRegistryPath: "authorizations.json",
        capabilitySigningKey: {
          role: server.role,
          keyId: server.keyId,
          publicKeyPath: server.publicKeyPath,
          privateKeyPath: server.privateKeyPath
        }
      });
      writeOwnerFile(root, "config.json", {
        component: "server",
        serverId: "server-01",
        allowedDestination: DEFAULT_ALLOWED_DESTINATION
      });
      writeOwnerFile(root, "host.json", {
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
        shutdownTimeoutMs: 15_000,
        metricsIntervalMs: 60_000,
        transportLimits: {
          maxUpgradeHeaderBytes: 16_384,
          maxUpgradeHeaderCount: 64,
          maxConcurrentHandshakes: 32,
          maxTrackedConnectionAddresses: 4_096,
          maxConnectionsPerWindow: 30,
          connectionRateWindowMs: 60_000,
          handshakeTimeoutMs: 10_000,
          maxMessageBytes: 32_768
        }
      });
      writeOwnerFile(root, "peer-identities.json", { schemaVersion: 1, identities: [] });
      writeOwnerFile(root, "authorizations.json", { auditVersion: 1, authorizations: [] });

      const loaded = loadProductionBundleWithSecurity(root, "manifest.json", {}, FAST_TEST_SECURITY);
      expect(loaded).toMatchObject({
        component: "server",
        config: { serverId: "server-01" },
        hostConfig: { listenHost: "127.0.0.1", listenPort: 8443, publicPort: 443 },
        tls: { certificate: Buffer.from("certificate"), privateKey: Buffer.from("private-key") }
      });
      expect(JSON.stringify(loaded)).not.toContain("BEGIN PRIVATE KEY");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 120_000);

  it("只加载 edge 所需材料，并拒绝批准范围外监听端口", () => {
    const root = temporaryRoot(true);
    try {
      const edge = generateIdentityFiles({ rootDirectory: root, outputDirectory: "edge", role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-key" });
      const server = generateIdentityFiles({ rootDirectory: root, outputDirectory: "server", role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: "server-key" });
      const manifest = {
        schemaVersion: 2,
        component: "edge-client",
        serverId: "server-01",
        configPath: "config.json",
        authenticationKey: { role: edge.role, keyId: edge.keyId, publicKeyPath: edge.publicKeyPath, privateKeyPath: edge.privateKeyPath },
        serverCapabilityVerificationKey: { role: server.role, keyId: server.keyId, publicKeyPath: server.publicKeyPath }
      };
      writeOwnerFile(root, "manifest.json", manifest);
      writeOwnerFile(root, "config.json", {
        component: "edge-client",
        edgeUserId: "user-01",
        edgeDeviceId: "device-01",
        serverUrl: "wss://server.example.invalid/tunnel",
        listenHost: "127.0.0.1",
        listenPort: 8787,
        allowedDestination: DEFAULT_ALLOWED_DESTINATION,
        limits: runtimeLimits()
      });
      const loaded = loadProductionBundleWithSecurity(root, "manifest.json", {}, FAST_TEST_SECURITY);
      expect(loaded).toMatchObject({ component: "edge-client", config: { listenPort: 8787 }, identity: { kind: "edge-device" } });

      rmSync(join(root, "config.json"));
      writeOwnerFile(root, "config.json", {
        component: "edge-client",
        edgeUserId: "user-01",
        edgeDeviceId: "device-01",
        serverUrl: "wss://server.example.invalid/tunnel",
        listenPort: 7999,
        allowedDestination: DEFAULT_ALLOWED_DESTINATION
      });
      expectOpsError(
        () => loadProductionBundleWithSecurity(root, "manifest.json", {}, FAST_TEST_SECURITY),
        "OPS_LISTEN_PORT_OUTSIDE_APPROVED_RANGE"
      );

      rmSync(join(root, "config.json"));
      writeOwnerFile(root, "config.json", {
        component: "edge-client",
        edgeUserId: "user-01",
        edgeDeviceId: "device-01",
        serverUrl: "wss://server.example.invalid/tunnel",
        listenPort: 8787,
        allowedDestination: { hostname: "127.0.0.1", port: 443 }
      });
      expectOpsError(
        () => loadProductionBundleWithSecurity(root, "manifest.json", {}, FAST_TEST_SECURITY),
        "OPS_DESTINATION_INVALID"
      );

      rmSync(join(root, "config.json"));
      writeOwnerFile(root, "config.json", {
        component: "edge-client",
        edgeUserId: "user-01",
        edgeDeviceId: "device-01",
        serverUrl: "wss://server.example.invalid/tunnel",
        listenPort: 8787,
        allowedDestination: DEFAULT_ALLOWED_DESTINATION
      });
      rmSync(join(root, "manifest.json"));
      writeOwnerFile(root, "manifest.json", {
        ...manifest,
        serverCapabilityVerificationKey: {
          ...manifest.serverCapabilityVerificationKey,
          publicKeyPath: server.privateKeyPath
        }
      });
      const disguisedPrivateError = expectOpsError(
        () => loadProductionBundleWithSecurity(root, "manifest.json", {}, FAST_TEST_SECURITY),
        "OPS_PUBLIC_KEY_INVALID"
      );
      expect(disguisedPrivateError.message).not.toContain("PRIVATE KEY");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 120_000);
});

describe("授权文件原子变更与审计", () => {
  it("支持 grant、只收紧配额、撤销并保留连续审计版本", () => {
    const root = temporaryRoot(true);
    try {
      createOwnerOnlyDirectory(root, "keys");
      const edge = generateIdentityFiles({ rootDirectory: root, outputDirectory: "keys/edge", role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-key" });
      const agent = generateIdentityFiles({ rootDirectory: root, outputDirectory: "keys/agent", role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: "agent-key" });
      writeOwnerFile(root, "peers.json", {
        schemaVersion: 1,
        identities: [
          {
            kind: "edge-device",
            edgeUserId: "user-01",
            edgeDeviceId: "device-01",
            authenticationKey: { role: edge.role, keyId: edge.keyId, publicKeyPath: edge.publicKeyPath }
          },
          {
            kind: "egress-agent",
            agentId: "agent-01",
            authenticationKey: { role: agent.role, keyId: agent.keyId, publicKeyPath: agent.publicKeyPath }
          }
        ]
      });
      writeOwnerFile(root, "private-as-peer.json", {
        schemaVersion: 1,
        identities: [{
          kind: "edge-device",
          edgeUserId: "user-01",
          edgeDeviceId: "device-01",
          authenticationKey: { role: edge.role, keyId: edge.keyId, publicKeyPath: edge.privateKeyPath }
        }]
      });
      const peerPrivateError = expectOpsError(
        () => loadPeerIdentityRegistryWithSecurity(root, "private-as-peer.json", FAST_TEST_SECURITY),
        "OPS_PUBLIC_KEY_INVALID"
      );
      expect(peerPrivateError.message).not.toContain("PRIVATE KEY");
      writeOwnerFile(root, "authorizations.json", { auditVersion: 1, authorizations: [] });
      const options = {
        rootDirectory: root,
        authorizationPath: "authorizations.json",
        peerIdentityRegistryPath: "peers.json",
        historyDirectory: "authorization-history"
      };
      expect(changeAuthorizationFileWithSecurity(options, {
        operation: "grant",
        edgeUserId: "user-01",
        edgeDeviceId: "device-01",
        agentId: "agent-01",
        quota: { maxConcurrentStreams: 4, maxBufferedBytes: 65_536 },
        nowMs: 1_000
      }, FAST_TEST_SECURITY).auditVersion).toBe(2);
      expect(changeAuthorizationFileWithSecurity(options, {
        operation: "tighten-quota",
        edgeUserId: "user-01",
        edgeDeviceId: "device-01",
        agentId: "agent-01",
        quota: { maxConcurrentStreams: 2, maxBufferedBytes: 32_768 }
      }, FAST_TEST_SECURITY).auditVersion).toBe(3);
      expectOpsError(() => changeAuthorizationFileWithSecurity(options, {
        operation: "tighten-quota",
        edgeUserId: "user-01",
        edgeDeviceId: "device-01",
        agentId: "agent-01",
        quota: { maxConcurrentStreams: 3, maxBufferedBytes: 32_768 }
      }, FAST_TEST_SECURITY), "OPS_AUTHORIZATION_QUOTA_INCREASE_FORBIDDEN");
      expect(changeAuthorizationFileWithSecurity(options, {
        operation: "revoke",
        selector: "edge-device",
        id: "device-01",
        nowMs: 2_000
      }, FAST_TEST_SECURITY).auditVersion).toBe(4);
      expect(verifyAuthorizationAuditTrailWithSecurity(options, FAST_TEST_SECURITY)).toEqual({
        auditVersion: 4,
        archivedVersions: [1, 2, 3, 4]
      });

      const firstAudit = join(root, "authorization-history", "authorization-v000000000001.json");
      makePathBroad(firstAudit);
      expectOpsError(() => verifyAuthorizationAuditTrail(options), "OPS_FILE_PERMISSIONS_TOO_BROAD");
      hardenOwnerOnly(firstAudit);
      expect(verifyAuthorizationAuditTrailWithSecurity(options, FAST_TEST_SECURITY).auditVersion).toBe(4);

      rmSync(firstAudit);
      let symlinkCreated = false;
      try {
        symlinkSync(join(root, "authorizations.json"), firstAudit, "file");
        symlinkCreated = true;
      } catch (error: unknown) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "EPERM" && code !== "EACCES" && code !== "ENOTSUP") {
          throw error;
        }
      }
      if (symlinkCreated) {
        expectOpsError(() => verifyAuthorizationAuditTrail(options), "OPS_SYMBOLIC_LINK_FORBIDDEN");
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 180_000);

  it("peer registry 严格拒绝把 edge key 标成 agent 角色", () => {
    expectOpsError(() => parsePeerIdentityRegistryJson(JSON.stringify({
      schemaVersion: 1,
      identities: [{
        kind: "egress-agent",
        agentId: "agent-01",
        authenticationKey: { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-key", publicKeyPath: "keys/edge/public.pem" }
      }]
    })), "OPS_IDENTITY_ROLE_MISMATCH");
  });
});
