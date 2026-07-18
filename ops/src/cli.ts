import { IdentityKeyRole, type IdentityKeyRole as IdentityKeyRoleType } from "@remote-codex/shared";

import { changeAuthorizationFile, verifyAuthorizationAuditTrail, type AuthorizationChange } from "./authorization-files.js";
import { fail } from "./errors.js";
import { generateIdentityFiles } from "./identity-files.js";
import { loadProductionBundle } from "./production-loader.js";

type Arguments = ReadonlyMap<string, string>;

export interface CliDependencies {
  readonly loadProductionBundle: typeof loadProductionBundle;
  readonly generateIdentityFiles: typeof generateIdentityFiles;
  readonly verifyAuthorizationAuditTrail: typeof verifyAuthorizationAuditTrail;
  readonly changeAuthorizationFile: typeof changeAuthorizationFile;
}

const DEFAULT_DEPENDENCIES: CliDependencies = Object.freeze({
  loadProductionBundle,
  generateIdentityFiles,
  verifyAuthorizationAuditTrail,
  changeAuthorizationFile
});

function parseArguments(values: readonly string[]): Arguments {
  const parsed = new Map<string, string>();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (name === undefined || value === undefined || !name.startsWith("--") || value.startsWith("--") || parsed.has(name)) {
      return fail("OPS_CLI_ARGUMENTS_INVALID");
    }
    parsed.set(name, value);
  }
  return parsed;
}

function exactArguments(arguments_: Arguments, allowed: readonly string[]): void {
  const expected = new Set(allowed);
  for (const key of arguments_.keys()) {
    if (!expected.has(key)) {
      fail("OPS_CLI_UNKNOWN_ARGUMENT");
    }
  }
  for (const key of allowed) {
    if (!arguments_.has(key)) {
      fail("OPS_CLI_ARGUMENT_REQUIRED");
    }
  }
}

function value(arguments_: Arguments, name: string): string {
  return arguments_.get(name) ?? fail("OPS_CLI_ARGUMENT_REQUIRED");
}

function integer(arguments_: Arguments, name: string): number {
  const raw = value(arguments_, name);
  if (!/^(0|[1-9][0-9]*)$/u.test(raw)) {
    return fail("OPS_CLI_INTEGER_INVALID");
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) {
    return fail("OPS_CLI_INTEGER_INVALID");
  }
  return parsed;
}

function commonAuthorizationOptions(arguments_: Arguments): {
  readonly rootDirectory: string;
  readonly authorizationPath: string;
  readonly peerIdentityRegistryPath: string;
  readonly historyDirectory: string;
} {
  return {
    rootDirectory: value(arguments_, "--root"),
    authorizationPath: value(arguments_, "--authorizations"),
    peerIdentityRegistryPath: value(arguments_, "--peers"),
    historyDirectory: value(arguments_, "--history")
  };
}

function authorizationChange(command: string, arguments_: Arguments): AuthorizationChange {
  if (command === "grant" || command === "tighten-quota") {
    return {
      operation: command,
      edgeUserId: value(arguments_, "--edge-user-id"),
      edgeDeviceId: value(arguments_, "--edge-device-id"),
      agentId: value(arguments_, "--agent-id"),
      quota: {
        maxConcurrentStreams: integer(arguments_, "--max-concurrent-streams"),
        maxBufferedBytes: integer(arguments_, "--max-buffered-bytes")
      },
      ...(command === "grant" ? { nowMs: integer(arguments_, "--now-ms") } : {})
    } as AuthorizationChange;
  }
  const selector = value(arguments_, "--selector");
  if (selector !== "edge-user" && selector !== "edge-device" && selector !== "agent") {
    return fail("OPS_CLI_SELECTOR_INVALID");
  }
  return { operation: "revoke", selector, id: value(arguments_, "--id"), nowMs: integer(arguments_, "--now-ms") };
}

export function runCli(
  argv: readonly string[],
  dependencies: CliDependencies = DEFAULT_DEPENDENCIES
): unknown {
  const [group, command, ...rawArguments] = argv;
  const arguments_ = parseArguments(rawArguments);
  if (group === "deployment" && command === "validate") {
    exactArguments(arguments_, ["--root", "--manifest"]);
    const bundle = dependencies.loadProductionBundle(value(arguments_, "--root"), value(arguments_, "--manifest"));
    return Object.freeze({ ok: true, component: bundle.component });
  }
  if (group === "identity" && command === "generate") {
    exactArguments(arguments_, ["--root", "--output-directory", "--role", "--key-id"]);
    const role = value(arguments_, "--role") as IdentityKeyRoleType;
    if (!Object.values(IdentityKeyRole).includes(role)) {
      return fail("OPS_IDENTITY_ROLE_INVALID");
    }
    return dependencies.generateIdentityFiles({
      rootDirectory: value(arguments_, "--root"),
      outputDirectory: value(arguments_, "--output-directory"),
      role,
      keyId: value(arguments_, "--key-id")
    });
  }
  if (group === "authorization" && command === "validate") {
    exactArguments(arguments_, ["--root", "--authorizations", "--peers", "--history"]);
    return Object.freeze({
      ok: true,
      ...dependencies.verifyAuthorizationAuditTrail(commonAuthorizationOptions(arguments_))
    });
  }
  if (group === "authorization" && (command === "grant" || command === "tighten-quota" || command === "revoke")) {
    const operationArguments = command === "revoke"
      ? ["--root", "--authorizations", "--peers", "--history", "--selector", "--id", "--now-ms"]
      : [
          "--root", "--authorizations", "--peers", "--history", "--edge-user-id", "--edge-device-id", "--agent-id",
          "--max-concurrent-streams", "--max-buffered-bytes", ...(command === "grant" ? ["--now-ms"] : [])
        ];
    exactArguments(arguments_, operationArguments);
    const document = dependencies.changeAuthorizationFile(
      commonAuthorizationOptions(arguments_),
      authorizationChange(command, arguments_)
    );
    return Object.freeze({ ok: true, auditVersion: document.auditVersion });
  }
  fail("OPS_CLI_COMMAND_INVALID");
}
