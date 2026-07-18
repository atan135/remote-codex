import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  writeFileSync
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";

import { fail } from "./errors.js";

export type FileSensitivity = "owner-only" | "public-readonly";
export interface FileSecurityAdapter {
  readonly assertSecureFile: (
    path: string,
    sensitivity: FileSensitivity,
    expectedType?: "file" | "directory"
  ) => void;
  readonly hardenOwnerOnly: (path: string) => void;
}
let cachedWindowsSid: string | undefined;

function assertWithAdapter(
  adapter: FileSecurityAdapter | undefined,
  filePath: string,
  sensitivity: FileSensitivity,
  expectedType: "file" | "directory" = "file"
): void {
  (adapter?.assertSecureFile ?? assertSecureFile)(filePath, sensitivity, expectedType);
}

function hardenWithAdapter(adapter: FileSecurityAdapter | undefined, filePath: string): void {
  (adapter?.hardenOwnerOnly ?? hardenOwnerOnly)(filePath);
}

function isInside(root: string, target: string): boolean {
  const relation = relative(root, target);
  return relation === "" || (!relation.startsWith(`..${sep}`) && relation !== ".." && !isAbsolute(relation));
}

function assertRelativePath(relativePath: string): void {
  if (
    typeof relativePath !== "string" ||
    relativePath.length === 0 ||
    relativePath.includes("\\") ||
    relativePath.includes(":") ||
    relativePath.includes("\0") ||
    relativePath.startsWith("/") ||
    win32.isAbsolute(relativePath) ||
    relativePath.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")
  ) {
    fail("OPS_PATH_NOT_STRICTLY_RELATIVE", "path");
  }
}

function strictDeploymentRoot(rootDirectory: string, adapter?: FileSecurityAdapter): string {
  if (lstatSync(rootDirectory).isSymbolicLink()) {
    return fail("OPS_SYMBOLIC_LINK_FORBIDDEN", "root");
  }
  const root = realpathSync(rootDirectory);
  if (!statSync(root).isDirectory()) {
    return fail("OPS_DIRECTORY_INVALID", "root");
  }
  assertSecureDirectory(root, adapter);
  return root;
}

function assertSecureDirectory(directoryPath: string, adapter?: FileSecurityAdapter): void {
  assertWithAdapter(adapter, directoryPath, "owner-only", "directory");
}

export function resolveDeploymentFile(
  rootDirectory: string,
  relativePath: string
): string {
  return resolveDeploymentFileWithSecurity(rootDirectory, relativePath);
}

export function resolveDeploymentFileWithSecurity(
  rootDirectory: string,
  relativePath: string,
  adapter?: FileSecurityAdapter
): string {
  assertRelativePath(relativePath);
  const root = strictDeploymentRoot(rootDirectory, adapter);
  const segments = relativePath.split("/");
  let cursor = root;
  for (const segment of segments) {
    cursor = join(cursor, segment);
    let metadata;
    try {
      metadata = lstatSync(cursor);
    } catch {
      return fail("OPS_FILE_NOT_FOUND", relativePath);
    }
    if (metadata.isSymbolicLink()) {
      return fail("OPS_SYMBOLIC_LINK_FORBIDDEN", relativePath);
    }
    if (cursor !== join(root, ...segments) && !metadata.isDirectory()) {
      return fail("OPS_DIRECTORY_INVALID", relativePath);
    }
    if (metadata.isDirectory()) {
      assertSecureDirectory(cursor, adapter);
    }
  }
  const actual = realpathSync(cursor);
  if (!isInside(root, actual) || !statSync(actual).isFile()) {
    return fail("OPS_PATH_OUTSIDE_DEPLOYMENT_ROOT", relativePath);
  }
  return actual;
}

export function evaluatePosixMode(mode: number, sensitivity: FileSensitivity): boolean {
  const permissions = mode & 0o777;
  if (sensitivity === "owner-only") {
    return (permissions & 0o077) === 0;
  }
  return (permissions & 0o022) === 0;
}

export function evaluatePosixDirectoryMode(mode: number): boolean {
  return (mode & 0o777) === 0o700;
}

function assertWindowsAcl(filePath: string, sensitivity: FileSensitivity): void {
  void sensitivity;
  const currentSid = currentWindowsSid();
  const trustees = windowsAclTrustees(filePath);
  if (!windowsAclTrusteesAreOwnerOnly(trustees, currentSid)) {
    fail("OPS_FILE_PERMISSIONS_TOO_BROAD");
  }
}

export function windowsAclTrusteesAreOwnerOnly(trustees: readonly string[], currentSid: string): boolean {
  if (!/^S-[0-9-]+$/u.test(currentSid) || trustees.length === 0) {
    return false;
  }
  const allowedTrustees = new Set([currentSid, "SY", "S-1-5-18"]);
  return trustees.every((trustee) => allowedTrustees.has(trustee));
}

function windowsAclTrustees(filePath: string): readonly string[] {
  const aclFile = join(tmpdir(), `remote-codex-acl-${randomUUID()}.txt`);
  let serializedAcl: string;
  try {
    execFileSync("icacls.exe", [filePath, "/save", aclFile, "/c"], { stdio: "ignore", windowsHide: true });
    serializedAcl = readFileSync(aclFile, "utf16le");
  } catch {
    return fail("OPS_WINDOWS_ACL_CHECK_FAILED");
  } finally {
    rmSync(aclFile, { force: true });
  }
  return Object.freeze(
    [...serializedAcl.matchAll(/;;;([^)]+)\)/gu)]
      .map((match) => match[1])
      .filter((trustee): trustee is string => trustee !== undefined)
  );
}

export function assertSecureFile(
  filePath: string,
  sensitivity: FileSensitivity,
  expectedType: "file" | "directory" = "file"
): void {
  const metadata = statSync(filePath);
  if ((expectedType === "file" && !metadata.isFile()) || (expectedType === "directory" && !metadata.isDirectory())) {
    fail(expectedType === "file" ? "OPS_FILE_INVALID" : "OPS_DIRECTORY_INVALID");
  }
  if (process.platform === "win32") {
    assertWindowsAcl(filePath, sensitivity);
    return;
  }
  const permissionsAreSafe = expectedType === "directory"
    ? evaluatePosixDirectoryMode(metadata.mode)
    : evaluatePosixMode(metadata.mode, sensitivity);
  if (!permissionsAreSafe) {
    fail("OPS_FILE_PERMISSIONS_TOO_BROAD");
  }
}

export function readDeploymentFile(
  rootDirectory: string,
  relativePath: string,
  sensitivity: FileSensitivity
): string {
  return readDeploymentFileWithSecurity(rootDirectory, relativePath, sensitivity);
}

export function readDeploymentFileWithSecurity(
  rootDirectory: string,
  relativePath: string,
  sensitivity: FileSensitivity,
  adapter?: FileSecurityAdapter
): string {
  const filePath = resolveDeploymentFileWithSecurity(rootDirectory, relativePath, adapter);
  assertWithAdapter(adapter, filePath, sensitivity);
  return readFileSync(filePath, "utf8");
}

function currentWindowsSid(): string {
  if (cachedWindowsSid !== undefined) {
    return cachedWindowsSid;
  }
  try {
    const output = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true }).trim();
    const match = output.match(/,"(S-[0-9-]+)"$/u);
    cachedWindowsSid = match?.[1] ?? fail("OPS_WINDOWS_ACL_HARDEN_FAILED");
    return cachedWindowsSid;
  } catch {
    return fail("OPS_WINDOWS_ACL_HARDEN_FAILED");
  }
}

export function hardenOwnerOnly(
  filePath: string,
  finalWindowsValidator: (path: string, sensitivity: FileSensitivity) => void = assertWindowsAcl
): void {
  if (process.platform !== "win32") {
    chmodSync(filePath, statSync(filePath).isDirectory() ? 0o700 : 0o600);
    return;
  }
  const sid = currentWindowsSid();
  try {
    execFileSync(
      "icacls.exe",
      [filePath, "/inheritance:r", "/grant:r", `*${sid}:(F)`, "*S-1-5-18:(F)"],
      { stdio: "ignore", windowsHide: true }
    );
    const trusteeAliases: Readonly<Record<string, string>> = {
      AU: "S-1-5-11",
      BA: "S-1-5-32-544",
      BG: "S-1-5-32-546",
      BU: "S-1-5-32-545",
      IU: "S-1-5-4",
      OW: "S-1-3-4",
      WD: "S-1-1-0"
    };
    const trusteesToRemove: string[] = [];
    for (const trustee of windowsAclTrustees(filePath)) {
      if (trustee === sid || trustee === "SY" || trustee === "S-1-5-18") {
        continue;
      }
      const trusteeSid = trusteeAliases[trustee] ?? trustee;
      if (!/^S-[0-9-]+$/u.test(trusteeSid)) {
        fail("OPS_WINDOWS_ACL_HARDEN_FAILED");
      }
      trusteesToRemove.push(`*${trusteeSid}`);
    }
    if (trusteesToRemove.length > 0) {
      execFileSync("icacls.exe", [filePath, "/remove", ...trusteesToRemove], { stdio: "ignore", windowsHide: true });
    }
    finalWindowsValidator(filePath, "owner-only");
  } catch {
    fail("OPS_WINDOWS_ACL_HARDEN_FAILED");
  }
}

function ensureContainedDirectory(
  rootDirectory: string,
  relativeDirectory: string,
  adapter?: FileSecurityAdapter
): string {
  assertRelativePath(relativeDirectory);
  const root = strictDeploymentRoot(rootDirectory, adapter);
  const directory = resolve(root, ...relativeDirectory.split("/"));
  if (!isInside(root, directory)) {
    return fail("OPS_PATH_OUTSIDE_DEPLOYMENT_ROOT", relativeDirectory);
  }
  let cursor = root;
  for (const segment of relativeDirectory.split("/")) {
    cursor = join(cursor, segment);
    if (existsSync(cursor)) {
      if (lstatSync(cursor).isSymbolicLink() || !statSync(cursor).isDirectory()) {
        return fail("OPS_DIRECTORY_INVALID", relativeDirectory);
      }
      assertSecureDirectory(cursor, adapter);
      continue;
    }
    createOwnerOnlyDirectoryAtPath(cursor, adapter);
  }
  return realpathSync(directory);
}

export function createOwnerOnlyDirectoryAtPath(
  directoryPath: string,
  adapter?: FileSecurityAdapter
): void {
  mkdirSync(directoryPath, { mode: 0o700 });
  try {
    hardenWithAdapter(adapter, directoryPath);
    if (adapter !== undefined || process.platform !== "win32") {
      assertSecureDirectory(directoryPath, adapter);
    }
  } catch (error: unknown) {
    try {
      rmdirSync(directoryPath);
    } catch {
      fail("OPS_DIRECTORY_HARDEN_CLEANUP_FAILED");
    }
    throw error;
  }
}

export function createOwnerOnlyDirectory(
  rootDirectory: string,
  relativeDirectory: string,
  adapter?: FileSecurityAdapter
): string {
  return ensureContainedDirectory(rootDirectory, relativeDirectory, adapter);
}

export function writeNewFile(
  filePath: string,
  contents: string | Uint8Array,
  sensitivity: FileSensitivity,
  adapter?: FileSecurityAdapter
): void {
  let descriptor: number | undefined;
  let created = false;
  try {
    descriptor = openSync(filePath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, sensitivity === "owner-only" ? 0o600 : 0o644);
    created = true;
    writeFileSync(descriptor, contents);
    fsyncSync(descriptor);
  } catch (error: unknown) {
    if (descriptor !== undefined) {
      closeSync(descriptor);
      descriptor = undefined;
    }
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      fail("OPS_FILE_ALREADY_EXISTS");
    }
    if (created) {
      rmSync(filePath, { force: true });
    }
    throw error;
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
  }
  if (sensitivity === "owner-only" || process.platform === "win32") {
    try {
      hardenWithAdapter(adapter, filePath);
      if (adapter !== undefined || process.platform !== "win32") {
        assertWithAdapter(adapter, filePath, sensitivity);
      }
    } catch (error: unknown) {
      rmSync(filePath, { force: true });
      throw error;
    }
  }
}

export function atomicReplaceOwnerOnly(
  filePath: string,
  contents: string,
  adapter?: FileSecurityAdapter
): void {
  const temporaryPath = join(dirname(filePath), `.${randomUUID()}.tmp`);
  try {
    writeNewFile(temporaryPath, contents, "owner-only", adapter);
    renameSync(temporaryPath, filePath);
  } finally {
    rmSync(temporaryPath, { force: true });
  }
}

export function acquireFileLock(filePath: string, adapter?: FileSecurityAdapter): () => void {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(filePath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      return fail("OPS_AUTHORIZATION_LOCKED");
    }
    throw error;
  }
  try {
    hardenWithAdapter(adapter, filePath);
  } catch (error: unknown) {
    closeSync(descriptor);
    rmSync(filePath, { force: true });
    throw error;
  }
  return (): void => {
    if (descriptor !== undefined) {
      closeSync(descriptor);
      descriptor = undefined;
    }
    rmSync(filePath, { force: true });
  };
}

export function deploymentRoot(rootDirectory: string, adapter?: FileSecurityAdapter): string {
  return strictDeploymentRoot(rootDirectory, adapter);
}
