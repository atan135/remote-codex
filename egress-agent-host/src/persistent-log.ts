import {
  closeSync,
  constants,
  existsSync,
  fdatasyncSync,
  fstatSync,
  lstatSync,
  openSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
  type Stats
} from "node:fs";
import { dirname, join } from "node:path";

import {
  assertSecureFile,
  createOwnerOnlyDirectoryAtPath,
  hardenOwnerOnly
} from "@remote-codex/ops";

export const AGENT_STATUS_LOG_RELATIVE_PATH = "logs/agent-status.ndjson";
export const DEFAULT_AGENT_STATUS_LOG_MAX_BYTES = 1_048_576;
export const DEFAULT_AGENT_STATUS_LOG_BACKUPS = 3;

export interface AgentProcessLogSink {
  write(serializedRecord: string): void;
  close(): void;
}

export interface AgentStatusLogOptions {
  readonly maxBytes?: number;
  readonly maxBackups?: number;
}

export class EgressAgentLogError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "EgressAgentLogError";
  }
}

function fail(code: string): never {
  throw new EgressAgentLogError(code);
}

function validateLimit(value: number, minimum: number, maximum: number, code: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    return fail(code);
  }
  return value;
}

function validateDirectory(path: string, expectedParent?: string): string {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    return fail("AGENT_HOST_LOG_DIRECTORY_UNSAFE");
  }
  assertSecureFile(path, "owner-only", "directory");
  const actual = realpathSync(path);
  if (expectedParent !== undefined && dirname(actual) !== expectedParent) {
    return fail("AGENT_HOST_LOG_DIRECTORY_UNSAFE");
  }
  return actual;
}

function validateFile(path: string, expectedParent: string): Stats {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
    return fail("AGENT_HOST_LOG_FILE_UNSAFE");
  }
  assertSecureFile(path, "owner-only");
  const actual = realpathSync(path);
  if (dirname(actual) !== expectedParent) {
    return fail("AGENT_HOST_LOG_FILE_UNSAFE");
  }
  return metadata;
}

class RotatingAgentStatusLog implements AgentProcessLogSink {
  private descriptor: number | undefined;
  private currentBytes: number;
  private state: "open" | "failed" | "closed" = "open";
  private failureCode: string | undefined;

  public constructor(
    private readonly logDirectory: string,
    private readonly maxBytes: number,
    private readonly maxBackups: number
  ) {
    const opened = this.openCurrent();
    this.descriptor = opened.descriptor;
    this.currentBytes = opened.bytes;
    if (this.currentBytes >= this.maxBytes) {
      this.rotate();
    }
  }

  public write(serializedRecord: string): void {
    if (this.state !== "open" || this.descriptor === undefined) {
      return fail(this.failureCode ?? "AGENT_HOST_LOG_CLOSED");
    }
    const record = Buffer.from(serializedRecord, "utf8");
    if (record.byteLength === 0 || record.byteLength > this.maxBytes || record[record.byteLength - 1] !== 0x0a) {
      return fail("AGENT_HOST_LOG_RECORD_INVALID");
    }
    if (this.currentBytes > 0 && this.currentBytes + record.byteLength > this.maxBytes) {
      this.rotate();
    }
    const descriptor = this.descriptor;
    if (this.state !== "open" || descriptor === undefined) {
      return fail(this.failureCode ?? "AGENT_HOST_LOG_CLOSED");
    }
    try {
      let written = 0;
      while (written < record.byteLength) {
        const count = writeSync(descriptor, record, written, record.byteLength - written);
        if (!Number.isSafeInteger(count) || count <= 0) {
          throw new EgressAgentLogError("AGENT_HOST_LOG_WRITE_FAILED");
        }
        written += count;
        this.currentBytes += count;
      }
      fdatasyncSync(descriptor);
    } catch {
      return this.transitionToFailed("AGENT_HOST_LOG_WRITE_FAILED");
    }
  }

  public close(): void {
    if (this.state === "closed") {
      return;
    }
    this.state = "closed";
    const descriptor = this.takeDescriptor();
    if (descriptor === undefined) {
      return;
    }
    try {
      closeSync(descriptor);
    } catch {
      // 日志 fd 关闭失败不能阻止 runtime/TCP/WSS 清理。
    }
  }

  private path(index = 0): string {
    return join(this.logDirectory, index === 0 ? "agent-status.ndjson" : `agent-status.ndjson.${index}`);
  }

  private openCurrent(): { readonly descriptor: number; readonly bytes: number } {
    const path = this.path();
    if (!existsSync(path)) {
      const created = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      closeSync(created);
      hardenOwnerOnly(path);
    }
    const expected = validateFile(path, this.logDirectory);
    let descriptor: number | undefined;
    try {
      descriptor = openSync(path, constants.O_APPEND | constants.O_WRONLY);
      const opened = fstatSync(descriptor);
      if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== expected.dev || opened.ino !== expected.ino) {
        return fail("AGENT_HOST_LOG_FILE_UNSAFE");
      }
      const result = { descriptor, bytes: opened.size };
      descriptor = undefined;
      return result;
    } finally {
      if (descriptor !== undefined) {
        try {
          closeSync(descriptor);
        } catch {
          // 初始化失败后不复用未知状态的 fd 数字。
        }
      }
    }
  }

  private rotate(): void {
    const descriptor = this.takeDescriptor();
    if (descriptor === undefined) {
      return this.transitionToFailed("AGENT_HOST_LOG_ROTATION_FAILED");
    }
    try {
      closeSync(descriptor);
      for (let index = this.maxBackups; index >= 1; index -= 1) {
        const destination = this.path(index);
        if (existsSync(destination)) {
          validateFile(destination, this.logDirectory);
          unlinkSync(destination);
        }
        const source = this.path(index - 1);
        if (existsSync(source)) {
          validateFile(source, this.logDirectory);
          renameSync(source, destination);
        }
      }
      const opened = this.openCurrent();
      this.descriptor = opened.descriptor;
      this.currentBytes = opened.bytes;
    } catch (error: unknown) {
      const code = error instanceof EgressAgentLogError ? error.code : "AGENT_HOST_LOG_ROTATION_FAILED";
      return this.transitionToFailed(code);
    }
  }

  private takeDescriptor(): number | undefined {
    const descriptor = this.descriptor;
    this.descriptor = undefined;
    return descriptor;
  }

  private transitionToFailed(code: string): never {
    this.state = "failed";
    this.failureCode ??= code;
    const descriptor = this.takeDescriptor();
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // fd 已从对象移除；失败后绝不再次 close 该数字。
      }
    }
    return fail(this.failureCode ?? code);
  }
}

export function createPersistentAgentStatusLog(
  rootDirectory: string,
  options: AgentStatusLogOptions = {}
): AgentProcessLogSink {
  const maxBytes = validateLimit(
    options.maxBytes ?? DEFAULT_AGENT_STATUS_LOG_MAX_BYTES,
    128,
    64 * 1024 * 1024,
    "AGENT_HOST_LOG_MAX_BYTES_INVALID"
  );
  const maxBackups = validateLimit(
    options.maxBackups ?? DEFAULT_AGENT_STATUS_LOG_BACKUPS,
    1,
    16,
    "AGENT_HOST_LOG_BACKUPS_INVALID"
  );
  try {
    const root = validateDirectory(rootDirectory);
    const logDirectoryPath = join(root, "logs");
    if (!existsSync(logDirectoryPath)) {
      createOwnerOnlyDirectoryAtPath(logDirectoryPath);
    }
    const logDirectory = validateDirectory(logDirectoryPath, root);
    for (let index = 0; index <= maxBackups; index += 1) {
      const candidate = join(logDirectory, index === 0 ? "agent-status.ndjson" : `agent-status.ndjson.${index}`);
      if (existsSync(candidate)) {
        const metadata = validateFile(candidate, logDirectory);
        if (metadata.size > maxBytes) {
          unlinkSync(candidate);
        }
      }
    }
    return new RotatingAgentStatusLog(logDirectory, maxBytes, maxBackups);
  } catch (error: unknown) {
    if (error instanceof EgressAgentLogError) {
      throw error;
    }
    return fail("AGENT_HOST_LOG_INIT_FAILED");
  }
}
