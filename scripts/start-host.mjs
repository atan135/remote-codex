import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { spawn } from "node:child_process";

const CONFIG_ROOT_ENVIRONMENT_VARIABLE = "REMOTE_CODEX_CONFIG_ROOT";
const MANIFEST_ENVIRONMENT_VARIABLE = "REMOTE_CODEX_MANIFEST";
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const hostEntrypoints = Object.freeze({
  server: "server-host/dist/cli-main.js",
  agent: "egress-agent-host/dist/cli-main.js",
  edge: "edge-client-host/dist/cli-main.js"
});

function fail(code) {
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
}

const role = process.argv[2];
const entrypoint = hostEntrypoints[role];
if (entrypoint === undefined || process.argv.length !== 3) {
  fail("REMOTE_CODEX_START_ROLE_INVALID");
} else {
  const configRoot = process.env[CONFIG_ROOT_ENVIRONMENT_VARIABLE];
  const manifest = process.env[MANIFEST_ENVIRONMENT_VARIABLE] ?? "manifest.json";
  const entrypointPath = resolve(repositoryRoot, entrypoint);

  if (configRoot === undefined || configRoot.length === 0) {
    fail("REMOTE_CODEX_START_CONFIG_ROOT_REQUIRED");
  } else if (manifest.length === 0) {
    fail("REMOTE_CODEX_START_MANIFEST_INVALID");
  } else if (!existsSync(entrypointPath)) {
    fail("REMOTE_CODEX_START_BUILD_REQUIRED");
  } else {
    const child = spawn(process.execPath, [entrypointPath, "--root", configRoot, "--manifest", manifest], {
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
