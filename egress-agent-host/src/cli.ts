import {
  startEgressAgentHost,
  type EgressAgentHostDependencies,
  type RunningEgressAgentHost
} from "./runtime.js";

export interface EgressAgentHostCliIo {
  readonly stderr: Pick<NodeJS.WritableStream, "write">;
}

const SAFE_CLI_CODES = new Set([
  "AGENT_HOST_CLI_ARGUMENT_INVALID",
  "AGENT_HOST_CLI_ARGUMENT_REQUIRED",
  "AGENT_HOST_COMPONENT_MISMATCH",
  "AGENT_HOST_LIFETIME_INIT_FAILED",
  "AGENT_HOST_SERVER_URL_INVALID",
  "AGENT_HOST_START_FAILED"
]);

function safeCode(error: unknown): string {
  if (error !== null && typeof error === "object" && "code" in error &&
      typeof error.code === "string" && SAFE_CLI_CODES.has(error.code)) {
    return error.code;
  }
  return "AGENT_HOST_FAILED";
}

function parseArguments(argv: readonly string[]): { readonly rootDirectory: string; readonly manifestPath: string } {
  let rootDirectory: string | undefined;
  let manifestPath = "manifest.json";
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value.length === 0 || value.trim() !== value) {
      throw Object.assign(new Error("AGENT_HOST_CLI_ARGUMENT_REQUIRED"), { code: "AGENT_HOST_CLI_ARGUMENT_REQUIRED" });
    }
    if (name === "--root" && rootDirectory === undefined) {
      rootDirectory = value;
      continue;
    }
    if (name === "--manifest" && manifestPath === "manifest.json") {
      manifestPath = value;
      continue;
    }
    throw Object.assign(new Error("AGENT_HOST_CLI_ARGUMENT_INVALID"), { code: "AGENT_HOST_CLI_ARGUMENT_INVALID" });
  }
  if (rootDirectory === undefined) {
    throw Object.assign(new Error("AGENT_HOST_CLI_ARGUMENT_REQUIRED"), { code: "AGENT_HOST_CLI_ARGUMENT_REQUIRED" });
  }
  return { rootDirectory, manifestPath };
}

export function runEgressAgentHostCli(
  argv: readonly string[],
  io: EgressAgentHostCliIo = { stderr: process.stderr },
  dependencies: Partial<EgressAgentHostDependencies> = {}
): number {
  let running: RunningEgressAgentHost | undefined;
  try {
    const arguments_ = parseArguments(argv);
    running = startEgressAgentHost(arguments_.rootDirectory, arguments_.manifestPath, dependencies);
  } catch (error: unknown) {
    io.stderr.write(`${JSON.stringify({ ok: false, code: safeCode(error) })}\n`);
    return 1;
  }

  let stopping = false;
  const stop = (): void => {
    if (stopping) {
      return;
    }
    stopping = true;
    try {
      running?.close();
    } catch {
      process.exitCode = 1;
    }
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  return 0;
}
