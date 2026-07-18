#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

import { runCli, type CliDependencies } from "./cli.js";
import { OpsError } from "./errors.js";

export interface CliOutput {
  readonly stdout: { write(value: string): unknown };
  readonly stderr: { write(value: string): unknown };
}

export function runCliMain(
  argv: readonly string[],
  output: CliOutput = process,
  dependencies?: CliDependencies
): number {
  try {
    const result = dependencies === undefined ? runCli(argv) : runCli(argv, dependencies);
    output.stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error: unknown) {
    const code = error instanceof OpsError ? error.code : "OPS_INTERNAL_ERROR";
    output.stderr.write(`${JSON.stringify({ ok: false, code })}\n`);
    return 1;
  }
}

const executablePath = process.argv[1];
if (executablePath !== undefined && import.meta.url === pathToFileURL(resolve(executablePath)).href) {
  process.exitCode = runCliMain(process.argv.slice(2));
}
