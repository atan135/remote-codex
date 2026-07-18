import { startServerHost, type RunningServerHost, type ServerHostDependencies } from "./runtime.js";

export interface ServerHostCliIo {
  readonly stderr: Pick<NodeJS.WritableStream, "write">;
}

const SAFE_CLI_CODES = new Set([
  "SERVER_HOST_CLI_ARGUMENT_INVALID",
  "SERVER_HOST_CLI_ARGUMENT_REQUIRED",
  "SERVER_HOST_COMPONENT_MISMATCH",
  "SERVER_HOST_LISTEN_FAILED",
  "SERVER_HOST_RELOAD_REQUIRES_RESTART",
  "SERVER_HOST_START_FAILED",
  "SERVER_HOST_TLS_CREDENTIALS_INVALID",
  "SERVER_HOST_TLS_RELOAD_FAILED"
]);

function safeCode(error: unknown): string {
  if (error !== null && typeof error === "object" && "code" in error &&
      typeof error.code === "string" && SAFE_CLI_CODES.has(error.code)) {
    return error.code;
  }
  return "SERVER_HOST_FAILED";
}

function parseArguments(argv: readonly string[]): { readonly rootDirectory: string; readonly manifestPath: string } {
  let rootDirectory: string | undefined;
  let manifestPath = "manifest.json";
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value.length === 0 || value.trim() !== value) {
      throw Object.assign(new Error("SERVER_HOST_CLI_ARGUMENT_REQUIRED"), { code: "SERVER_HOST_CLI_ARGUMENT_REQUIRED" });
    }
    if (name === "--root" && rootDirectory === undefined) {
      rootDirectory = value;
      continue;
    }
    if (name === "--manifest" && manifestPath === "manifest.json") {
      manifestPath = value;
      continue;
    }
    throw Object.assign(new Error("SERVER_HOST_CLI_ARGUMENT_INVALID"), { code: "SERVER_HOST_CLI_ARGUMENT_INVALID" });
  }
  if (rootDirectory === undefined) {
    throw Object.assign(new Error("SERVER_HOST_CLI_ARGUMENT_REQUIRED"), { code: "SERVER_HOST_CLI_ARGUMENT_REQUIRED" });
  }
  return { rootDirectory, manifestPath };
}

export async function runServerHostCli(
  argv: readonly string[],
  io: ServerHostCliIo = { stderr: process.stderr },
  dependencies: Partial<ServerHostDependencies> = {}
): Promise<number> {
  let running: RunningServerHost | undefined;
  try {
    const args = parseArguments(argv);
    running = await startServerHost(args.rootDirectory, args.manifestPath, dependencies);
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
    void running?.close().then(
      () => process.exitCode = 0,
      () => process.exitCode = 1
    );
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  process.on("SIGHUP", () => {
    void running?.reloadTls();
  });
  return 0;
}
