import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { spawn } from "node:child_process";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const localStartConfigPath = resolve(repositoryRoot, "config", "local.start.json");

const hostEntrypoints = Object.freeze({
  server: "server-host/dist/cli-main.js",
  agent: "egress-agent-host/dist/cli-main.js",
  edge: "edge-client-host/dist/cli-main.js"
});

function isSupportedRole(role) {
  return typeof role === "string" && Object.hasOwn(hostEntrypoints, role);
}

function fail(code) {
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
}

function isWithinRepository(path) {
  const difference = relative(repositoryRoot, path);
  return difference === "" || (!difference.startsWith("..") && !isAbsolute(difference));
}

function loadLocalStartConfig() {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(localStartConfigPath, "utf8"));
  } catch (error) {
    if (error !== null && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      fail("REMOTE_CODEX_START_CONFIG_NOT_FOUND");
    } else {
      fail("REMOTE_CODEX_START_CONFIG_INVALID");
    }
    return undefined;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail("REMOTE_CODEX_START_CONFIG_INVALID");
    return undefined;
  }

  const keys = Object.keys(parsed);
  if (keys.length !== 3 || !keys.every((key) => key === "role" || key === "configRoot" || key === "manifest")) {
    fail("REMOTE_CODEX_START_CONFIG_INVALID");
    return undefined;
  }

  const { role, configRoot, manifest } = parsed;
  if (!isSupportedRole(role)) {
    fail("REMOTE_CODEX_START_ROLE_INVALID");
    return undefined;
  }
  if (typeof configRoot !== "string" || configRoot.length === 0 || configRoot.trim() !== configRoot || !isAbsolute(configRoot)) {
    fail("REMOTE_CODEX_START_CONFIG_ROOT_INVALID");
    return undefined;
  }
  if (typeof manifest !== "string" || manifest.length === 0 || manifest.trim() !== manifest ||
      manifest.includes("/") || manifest.includes("\\")) {
    fail("REMOTE_CODEX_START_MANIFEST_INVALID");
    return undefined;
  }

  const configRootPath = resolve(configRoot);
  if (isWithinRepository(configRootPath)) {
    fail("REMOTE_CODEX_START_CONFIG_ROOT_INVALID");
    return undefined;
  }

  return Object.freeze({ role, configRoot: configRootPath, manifest });
}

const requestedRole = process.argv[2];
if (process.argv.length > 3 || (requestedRole !== undefined && !isSupportedRole(requestedRole))) {
  fail("REMOTE_CODEX_START_ROLE_INVALID");
} else {
  const startConfig = loadLocalStartConfig();
  if (startConfig !== undefined) {
    if (requestedRole !== undefined && requestedRole !== startConfig.role) {
      fail("REMOTE_CODEX_START_ROLE_MISMATCH");
    } else {
      const entrypointPath = resolve(repositoryRoot, hostEntrypoints[startConfig.role]);

      if (!existsSync(entrypointPath)) {
        fail("REMOTE_CODEX_START_BUILD_REQUIRED");
      } else {
        const child = spawn(process.execPath, [entrypointPath, "--root", startConfig.configRoot, "--manifest", startConfig.manifest], {
          cwd: repositoryRoot,
          stdio: "inherit"
        });
        let exited = false;

        const forwardSignal = (signal) => {
          if (!exited) {
            child.kill(signal);
          }
        };

        process.once("SIGINT", () => forwardSignal("SIGINT"));
        process.once("SIGTERM", () => forwardSignal("SIGTERM"));
        child.once("error", () => fail("REMOTE_CODEX_START_EXECUTION_FAILED"));
        child.once("exit", (code) => {
          exited = true;
          process.exitCode = code === 0 ? 0 : 1;
        });
      }
    }
  }
}
