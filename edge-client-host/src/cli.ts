import {
  startEdgeClientHost,
  type EdgeClientHostDependencies,
  type RunningEdgeClientHost
} from "./runtime.js";

export interface EdgeClientHostCliIo {
  readonly stderr: Pick<NodeJS.WritableStream, "write">;
  readonly signals?: EdgeClientHostSignalSource;
}

export interface EdgeClientHostSignalSource {
  once(signal: "SIGTERM" | "SIGINT", listener: () => void): unknown;
}

function safeCode(error: unknown): string {
  if (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string" &&
    /^[A-Z][A-Z0-9_]{0,127}$/u.test(error.code)
  ) {
    return error.code;
  }
  return "EDGE_HOST_FAILED";
}

function parseArguments(argv: readonly string[]): { readonly rootDirectory: string; readonly manifestPath: string } {
  let rootDirectory: string | undefined;
  let manifestPath = "manifest.json";
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value.length === 0 || value.trim() !== value) {
      throw Object.assign(new Error("EDGE_HOST_CLI_ARGUMENT_REQUIRED"), { code: "EDGE_HOST_CLI_ARGUMENT_REQUIRED" });
    }
    if (name === "--root" && rootDirectory === undefined) {
      rootDirectory = value;
      continue;
    }
    if (name === "--manifest" && manifestPath === "manifest.json") {
      manifestPath = value;
      continue;
    }
    throw Object.assign(new Error("EDGE_HOST_CLI_ARGUMENT_INVALID"), { code: "EDGE_HOST_CLI_ARGUMENT_INVALID" });
  }
  if (rootDirectory === undefined) {
    throw Object.assign(new Error("EDGE_HOST_CLI_ARGUMENT_REQUIRED"), { code: "EDGE_HOST_CLI_ARGUMENT_REQUIRED" });
  }
  return { rootDirectory, manifestPath };
}

export async function runEdgeClientHostCli(
  argv: readonly string[],
  io: EdgeClientHostCliIo = { stderr: process.stderr },
  dependencies: Partial<EdgeClientHostDependencies> = {}
): Promise<number> {
  let running: RunningEdgeClientHost | undefined;
  try {
    const arguments_ = parseArguments(argv);
    running = await startEdgeClientHost(arguments_.rootDirectory, arguments_.manifestPath, dependencies);
  } catch (error: unknown) {
    io.stderr.write(`${JSON.stringify({ ok: false, code: safeCode(error) })}\n`);
    return 1;
  }

  let stopping: Promise<void> | undefined;
  const stop = (): void => {
    stopping ??= running?.close().catch(() => {
      process.exitCode = 1;
    }) ?? Promise.resolve();
  };
  const signals = io.signals ?? process;
  signals.once("SIGTERM", stop);
  signals.once("SIGINT", stop);
  return 0;
}
