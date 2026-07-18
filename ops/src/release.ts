import { createHash } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { normalizeHostname, PROTOCOL_VERSION } from "@remote-codex/shared";

import { fail, OpsError } from "./errors.js";
import { PRODUCTION_MANIFEST_SCHEMA_VERSION } from "./schema.js";
import { SERVER_HOST_CONFIG_SCHEMA_VERSION } from "./server-host.js";

export const RELEASE_POLICY_SCHEMA_VERSION = 1 as const;
export const RELEASE_INVENTORY_SCHEMA_VERSION = 1 as const;

type WorkspaceRole = "runtime" | "production";

interface ReleaseWorkspacePolicy {
  readonly directory: string;
  readonly packageName: string;
  readonly role: WorkspaceRole;
  readonly dependencies: readonly string[];
  readonly modules: readonly string[];
}

export interface ReleasePolicy {
  readonly schemaVersion: typeof RELEASE_POLICY_SCHEMA_VERSION;
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly productionManifestSchemaVersion: typeof PRODUCTION_MANIFEST_SCHEMA_VERSION;
  readonly serverHostConfigSchemaVersion: typeof SERVER_HOST_CONFIG_SCHEMA_VERSION;
  readonly staticFiles: readonly string[];
  readonly workspaces: readonly ReleaseWorkspacePolicy[];
}

interface ReleaseInventoryFile {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

interface ReleaseInventory {
  readonly schemaVersion: typeof RELEASE_INVENTORY_SCHEMA_VERSION;
  readonly releaseVersion: string;
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly policySha256: string;
  readonly aggregateSha256: string;
  readonly files: readonly ReleaseInventoryFile[];
}

export interface ReleaseVerificationResult {
  readonly ok: true;
  readonly releaseVersion: string;
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly fileCount: number;
  readonly byteCount: number;
  readonly aggregateSha256: string;
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const VERSION_PATTERN = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/u;
const STRICT_SEGMENT_PATTERN = /^[a-z0-9][a-z0-9-]*$/u;
const STRICT_MODULE_PATTERN = /^[a-z0-9][a-z0-9-]*$/u;
const DIST_SUFFIXES = Object.freeze([".js"]);
const DEPENDENCY_FIELDS = Object.freeze(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]);

const EXPECTED_WORKSPACES = Object.freeze({
  "shared": Object.freeze({ packageName: "@remote-codex/shared", role: "runtime", dependencies: [] }),
  "server": Object.freeze({ packageName: "@remote-codex/server", role: "runtime", dependencies: ["@remote-codex/shared", "ws"] }),
  "egress-agent": Object.freeze({ packageName: "@remote-codex/egress-agent", role: "runtime", dependencies: ["@remote-codex/shared", "ws"] }),
  "edge-client": Object.freeze({ packageName: "@remote-codex/edge-client", role: "runtime", dependencies: ["@remote-codex/shared", "ws"] }),
  "ops": Object.freeze({ packageName: "@remote-codex/ops", role: "production", dependencies: ["@remote-codex/server", "@remote-codex/shared"] }),
  "server-host": Object.freeze({ packageName: "@remote-codex/server-host", role: "production", dependencies: ["@remote-codex/ops", "@remote-codex/server", "@remote-codex/shared"] }),
  "egress-agent-host": Object.freeze({ packageName: "@remote-codex/egress-agent-host", role: "production", dependencies: ["@remote-codex/egress-agent", "@remote-codex/ops", "@remote-codex/shared"] }),
  "edge-client-host": Object.freeze({ packageName: "@remote-codex/edge-client-host", role: "production", dependencies: ["@remote-codex/edge-client", "@remote-codex/ops", "@remote-codex/shared"] })
} satisfies Readonly<Record<string, { readonly packageName: string; readonly role: WorkspaceRole; readonly dependencies: readonly string[] }>>);

function record(value: unknown, code: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return fail(code);
  }
  return value as Record<string, unknown>;
}

function exactFields(value: Record<string, unknown>, fields: readonly string[], code: string): void {
  const expected = new Set(fields);
  if (Object.keys(value).length !== expected.size || Object.keys(value).some((field) => !expected.has(field))) {
    fail(code);
  }
}

function strictString(value: unknown, pattern: RegExp, code: string): string {
  if (typeof value !== "string" || !pattern.test(value)) {
    return fail(code);
  }
  return value;
}

function stringArray(value: unknown, pattern: RegExp, code: string): readonly string[] {
  if (!Array.isArray(value)) {
    return fail(code);
  }
  const parsed = value.map((entry) => strictString(entry, pattern, code));
  if (new Set(parsed).size !== parsed.length || parsed.some((entry, index) => index > 0 && entry <= (parsed[index - 1] ?? ""))) {
    fail(code);
  }
  return Object.freeze(parsed);
}

function strictRelativePath(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0 || isAbsolute(value) || value.includes("\\") || value.includes("\u0000")) {
    return fail(code);
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    return fail(code);
  }
  return value;
}

function parseJson(bytes: Buffer, code: string): unknown {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    return fail(code);
  }
}

export function parseReleasePolicyJson(json: string): ReleasePolicy {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return fail("OPS_RELEASE_POLICY_JSON_INVALID");
  }
  const root = record(raw, "OPS_RELEASE_POLICY_INVALID");
  exactFields(root, [
    "schemaVersion", "protocolVersion", "productionManifestSchemaVersion", "serverHostConfigSchemaVersion",
    "staticFiles", "workspaces"
  ], "OPS_RELEASE_POLICY_INVALID");
  if (root.schemaVersion !== RELEASE_POLICY_SCHEMA_VERSION) {
    fail("OPS_RELEASE_POLICY_VERSION_MISMATCH");
  }
  if (root.protocolVersion !== PROTOCOL_VERSION) {
    fail("OPS_RELEASE_PROTOCOL_VERSION_MISMATCH");
  }
  if (root.productionManifestSchemaVersion !== PRODUCTION_MANIFEST_SCHEMA_VERSION ||
      root.serverHostConfigSchemaVersion !== SERVER_HOST_CONFIG_SCHEMA_VERSION) {
    fail("OPS_RELEASE_CONFIG_SCHEMA_MISMATCH");
  }
  const staticFiles = stringArray(root.staticFiles, /^(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9_./-]+$/u, "OPS_RELEASE_POLICY_INVALID")
    .map((entry) => strictRelativePath(entry, "OPS_RELEASE_POLICY_INVALID"));
  if (!Array.isArray(root.workspaces)) {
    return fail("OPS_RELEASE_POLICY_INVALID");
  }
  const workspaces = root.workspaces.map((entry): ReleaseWorkspacePolicy => {
    const workspace = record(entry, "OPS_RELEASE_POLICY_INVALID");
    exactFields(workspace, ["directory", "packageName", "role", "dependencies", "modules"], "OPS_RELEASE_POLICY_INVALID");
    const directory = strictString(workspace.directory, STRICT_SEGMENT_PATTERN, "OPS_RELEASE_POLICY_INVALID");
    const expected = EXPECTED_WORKSPACES[directory as keyof typeof EXPECTED_WORKSPACES];
    if (expected === undefined || workspace.packageName !== expected.packageName || workspace.role !== expected.role) {
      return fail("OPS_RELEASE_WORKSPACE_MISMATCH");
    }
    const dependencies = stringArray(workspace.dependencies, /^(@[a-z0-9-]+\/[a-z0-9-]+|[a-z0-9][a-z0-9-]*)$/u, "OPS_RELEASE_POLICY_INVALID");
    if (dependencies.length !== expected.dependencies.length || dependencies.some((name, index) => name !== expected.dependencies[index])) {
      fail("OPS_RELEASE_DEPENDENCY_BOUNDARY_INVALID");
    }
    const modules = stringArray(workspace.modules, STRICT_MODULE_PATTERN, "OPS_RELEASE_POLICY_INVALID");
    if (modules.length === 0 || !modules.includes("index")) {
      fail("OPS_RELEASE_DIST_POLICY_INVALID");
    }
    return Object.freeze({ directory, packageName: expected.packageName, role: expected.role, dependencies, modules });
  });
  const directories = workspaces.map(({ directory }) => directory);
  if (directories.length !== Object.keys(EXPECTED_WORKSPACES).length ||
      new Set(directories).size !== directories.length ||
      Object.keys(EXPECTED_WORKSPACES).some((directory) => !directories.includes(directory))) {
    fail("OPS_RELEASE_WORKSPACE_MISMATCH");
  }
  return Object.freeze({
    schemaVersion: RELEASE_POLICY_SCHEMA_VERSION,
    protocolVersion: PROTOCOL_VERSION,
    productionManifestSchemaVersion: PRODUCTION_MANIFEST_SCHEMA_VERSION,
    serverHostConfigSchemaVersion: SERVER_HOST_CONFIG_SCHEMA_VERSION,
    staticFiles: Object.freeze(staticFiles),
    workspaces: Object.freeze(workspaces)
  });
}

function expectedFiles(policy: ReleasePolicy): readonly string[] {
  const files = [...policy.staticFiles];
  for (const workspace of policy.workspaces) {
    files.push(`${workspace.directory}/package.json`);
    for (const moduleName of workspace.modules) {
      for (const suffix of DIST_SUFFIXES) {
        files.push(`${workspace.directory}/dist/${moduleName}${suffix}`);
      }
    }
  }
  files.sort();
  if (new Set(files).size !== files.length) {
    fail("OPS_RELEASE_POLICY_INVALID");
  }
  return Object.freeze(files);
}

function forbiddenPath(path: string): boolean {
  return path.split("/").some((segment) => {
    const lower = segment.toLowerCase();
    return lower === ".env" || lower.startsWith(".env.") || lower === "id_rsa" ||
      lower.includes("private-key") || lower.includes("private_key") ||
      [".pem", ".key", ".p12", ".pfx", ".crt", ".cer"].some((suffix) => lower.endsWith(suffix));
  });
}

function scanFiles(rootDirectory: string): readonly string[] {
  const absoluteRoot = resolve(rootDirectory);
  let rootStatus;
  try {
    rootStatus = lstatSync(absoluteRoot);
  } catch {
    return fail("OPS_RELEASE_ROOT_INVALID");
  }
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) {
    fail("OPS_RELEASE_ROOT_INVALID");
  }
  const files: string[] = [];
  const visit = (directory: string): void => {
    const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      const absolutePath = join(directory, entry.name);
      const status = lstatSync(absolutePath);
      if (status.isSymbolicLink()) {
        fail("OPS_RELEASE_SYMLINK_REJECTED");
      }
      if (status.isDirectory()) {
        visit(absolutePath);
        continue;
      }
      if (!status.isFile()) {
        fail("OPS_RELEASE_FILE_TYPE_REJECTED");
      }
      const path = relative(absoluteRoot, absolutePath).split(sep).join("/");
      if (forbiddenPath(path)) {
        fail("OPS_RELEASE_SECRET_FILE_REJECTED");
      }
      files.push(path);
    }
  };
  visit(absoluteRoot);
  files.sort();
  return Object.freeze(files);
}

function assertNoSecretContent(bytes: Buffer): void {
  const text = bytes.toString("utf8");
  const privateKeyBoundary = new RegExp([
    "-----BEGIN ", "(?:ENCRYPTED )?", "(?:RSA |EC |OPENSSH )?", "PRIVATE KEY-----"
  ].join(""), "u");
  const certificateBoundary = ["-----BEGIN ", "CERTIFICATE-----"].join("");
  if (privateKeyBoundary.test(text) || text.includes(certificateBoundary)) {
    fail("OPS_RELEASE_SECRET_CONTENT_REJECTED");
  }
  const credentialNames = ["Authorization", "Proxy-Authorization", "Cookie"].join("|");
  const headerPattern = new RegExp(`(?:^|\\r?\\n)(?:${credentialNames})\\s*:\\s*(?!<|\\[|\\{|\\$|REDACTED\\b)[^\\r\\n]{4,}`, "iu");
  const assignmentNames = ["token", "secret", "password", "api[_-]?key", "cookie", "authorization", "proxy[_-]?authorization"].join("|");
  const assignmentPattern = new RegExp(`(?:["']?(?:${assignmentNames})["']?)\\s*[:=]\\s*["'][^"'\\r\\n]{8,}["']`, "iu");
  const knownTokenPattern = new RegExp([
    "(?:sk-", "[A-Za-z0-9_-]{12,}", "|ghp_", "[A-Za-z0-9]{20,}", "|xox[baprs]-", "[A-Za-z0-9-]{12,}", ")"
  ].join(""), "u");
  if (headerPattern.test(text) || assignmentPattern.test(text) || knownTokenPattern.test(text)) {
    fail("OPS_RELEASE_CREDENTIAL_CONTENT_REJECTED");
  }
}

function canonicalHostname(value: unknown, code: string): string {
  if (typeof value !== "string") {
    return fail(code);
  }
  let normalized: string;
  try {
    normalized = normalizeHostname(value);
  } catch {
    return fail(code);
  }
  if (value !== normalized) {
    fail(code);
  }
  return normalized;
}

function assertPortBoundaries(value: unknown): void {
  if (Array.isArray(value)) {
    for (const entry of value) {
      assertPortBoundaries(entry);
    }
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  const object = value as Record<string, unknown>;
  for (const [key, entry] of Object.entries(object)) {
    if (key === "listenPort" && (!Number.isInteger(entry) || (entry as number) < 8000 || (entry as number) > 9000)) {
      fail("OPS_RELEASE_LISTEN_PORT_REJECTED");
    }
    if (key === "listenHost" && entry !== "127.0.0.1") {
      fail("OPS_RELEASE_LISTEN_HOST_REJECTED");
    }
    if (key === "serverUrl") {
      if (typeof entry !== "string") {
        fail("OPS_RELEASE_SERVER_URL_REJECTED");
      }
      let serverUrl: URL;
      try {
        serverUrl = new URL(entry);
      } catch {
        return fail("OPS_RELEASE_SERVER_URL_REJECTED");
      }
      const port = Number(serverUrl.port);
      if (serverUrl.protocol !== "wss:" || serverUrl.port === "" || port < 8000 || port > 9000 ||
          serverUrl.pathname !== "/tunnel" || serverUrl.username !== "" || serverUrl.password !== "" ||
          serverUrl.search !== "" || serverUrl.hash !== "") {
        fail("OPS_RELEASE_SERVER_URL_REJECTED");
      }
      try {
        canonicalHostname(serverUrl.hostname, "OPS_RELEASE_SERVER_URL_REJECTED");
      } catch {
        return fail("OPS_RELEASE_SERVER_URL_REJECTED");
      }
      if (entry !== serverUrl.href) {
        fail("OPS_RELEASE_SERVER_URL_REJECTED");
      }
    }
    if (key === "allowedDestination") {
      const destination = record(entry, "OPS_RELEASE_DESTINATION_REJECTED");
      exactFields(destination, ["hostname", "port"], "OPS_RELEASE_DESTINATION_REJECTED");
      if (destination.port !== 443) {
        fail("OPS_RELEASE_DESTINATION_REJECTED");
      }
      canonicalHostname(destination.hostname, "OPS_RELEASE_DESTINATION_REJECTED");
    }
    assertPortBoundaries(entry);
  }
}

function packageJson(rootDirectory: string, path: string): Record<string, unknown> {
  return record(parseJson(readFileSync(join(rootDirectory, ...path.split("/"))), "OPS_RELEASE_PACKAGE_JSON_INVALID"), "OPS_RELEASE_PACKAGE_JSON_INVALID");
}

function dependencyNames(packageDocument: Record<string, unknown>): readonly string[] {
  const productionDependencies = packageDocument.dependencies;
  if (productionDependencies === undefined) {
    return Object.freeze([]);
  }
  const dependencies = record(productionDependencies, "OPS_RELEASE_DEPENDENCY_BOUNDARY_INVALID");
  return Object.freeze(Object.keys(dependencies).sort());
}

function assertNoRemoteClientDependency(packageDocument: Record<string, unknown>): void {
  for (const field of DEPENDENCY_FIELDS) {
    const value = packageDocument[field];
    if (value === undefined) {
      continue;
    }
    const dependencies = record(value, "OPS_RELEASE_DEPENDENCY_BOUNDARY_INVALID");
    if (Object.keys(dependencies).some((name) => name === "remote-client" || name.startsWith("@remote-codex/remote-client"))) {
      fail("OPS_RELEASE_REMOTE_CLIENT_DEPENDENCY_REJECTED");
    }
  }
}

function assertPackageBoundaries(rootDirectory: string, policy: ReleasePolicy): string {
  const rootPackage = packageJson(rootDirectory, "package.json");
  exactFields(rootPackage, ["name", "version", "private", "type", "packageManager", "engines", "scripts", "devDependencies"], "OPS_RELEASE_ROOT_PACKAGE_INVALID");
  const releaseVersion = strictString(rootPackage.version, VERSION_PATTERN, "OPS_RELEASE_VERSION_INVALID");
  if (rootPackage.name !== "remote-codex" || rootPackage.private !== true || rootPackage.type !== "module") {
    fail("OPS_RELEASE_ROOT_PACKAGE_INVALID");
  }
  assertNoRemoteClientDependency(rootPackage);
  for (const workspace of policy.workspaces) {
    const document = packageJson(rootDirectory, `${workspace.directory}/package.json`);
    if (document.name !== workspace.packageName || document.version !== releaseVersion || document.private !== true || document.type !== "module") {
      fail("OPS_RELEASE_WORKSPACE_PACKAGE_INVALID");
    }
    assertNoRemoteClientDependency(document);
    const actualDependencies = dependencyNames(document);
    if (actualDependencies.length !== workspace.dependencies.length || actualDependencies.some((name, index) => name !== workspace.dependencies[index])) {
      fail("OPS_RELEASE_DEPENDENCY_BOUNDARY_INVALID");
    }
    const dependencies = record(document.dependencies ?? {}, "OPS_RELEASE_DEPENDENCY_BOUNDARY_INVALID");
    for (const dependency of workspace.dependencies.filter((name) => name.startsWith("@remote-codex/"))) {
      if (dependencies[dependency] !== "workspace:*") {
        fail("OPS_RELEASE_DEPENDENCY_BOUNDARY_INVALID");
      }
    }
  }
  return releaseVersion;
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function aggregateHash(files: readonly ReleaseInventoryFile[]): string {
  const hash = createHash("sha256");
  for (const file of files) {
    hash.update(file.path);
    hash.update("\u0000");
    hash.update(String(file.bytes));
    hash.update("\u0000");
    hash.update(file.sha256);
    hash.update("\n");
  }
  return hash.digest("hex");
}

function assertExportedNumericConstant(root: string, path: string, name: string, expected: number, code: string): void {
  const source = readFileSync(join(root, ...path.split("/")), "utf8");
  const pattern = new RegExp(`(?:^|\\n)export const ${name} = ([0-9]+);(?:\\r?\\n|$)`, "u");
  const match = pattern.exec(source);
  if (match === null || Number(match[1]) !== expected) {
    fail(code);
  }
}

function inspectCandidate(rootDirectory: string, policy: ReleasePolicy): { readonly releaseVersion: string; readonly files: readonly ReleaseInventoryFile[] } {
  const root = resolve(rootDirectory);
  const expected = expectedFiles(policy);
  const actual = scanFiles(root);
  if (actual.length !== expected.length || actual.some((path, index) => path !== expected[index])) {
    fail("OPS_RELEASE_FILE_SET_MISMATCH");
  }
  const releaseVersion = assertPackageBoundaries(root, policy);
  const files = actual.map((path): ReleaseInventoryFile => {
    const bytes = readFileSync(join(root, ...path.split("/")));
    assertNoSecretContent(bytes);
    if (path.endsWith(".json")) {
      assertPortBoundaries(parseJson(bytes, "OPS_RELEASE_JSON_INVALID"));
    }
    return Object.freeze({ path, bytes: bytes.byteLength, sha256: sha256(bytes) });
  });
  assertExportedNumericConstant(root, "shared/dist/config.js", "PROTOCOL_VERSION", policy.protocolVersion, "OPS_RELEASE_PROTOCOL_VERSION_MISMATCH");
  assertExportedNumericConstant(
    root,
    "ops/dist/schema.js",
    "PRODUCTION_MANIFEST_SCHEMA_VERSION",
    policy.productionManifestSchemaVersion,
    "OPS_RELEASE_CONFIG_SCHEMA_MISMATCH"
  );
  assertExportedNumericConstant(
    root,
    "ops/dist/server-host.js",
    "SERVER_HOST_CONFIG_SCHEMA_VERSION",
    policy.serverHostConfigSchemaVersion,
    "OPS_RELEASE_CONFIG_SCHEMA_MISMATCH"
  );
  return Object.freeze({ releaseVersion, files: Object.freeze(files) });
}

function readPolicy(policyPath: string): { readonly policy: ReleasePolicy; readonly sha256: string } {
  let status: ReturnType<typeof lstatSync>;
  try {
    status = lstatSync(policyPath);
  } catch {
    return fail("OPS_RELEASE_POLICY_FILE_INVALID");
  }
  if (!status.isFile() || status.isSymbolicLink()) {
    return fail("OPS_RELEASE_POLICY_FILE_INVALID");
  }
  const bytes = readFileSync(policyPath);
  return Object.freeze({ policy: parseReleasePolicyJson(bytes.toString("utf8")), sha256: sha256(bytes) });
}

function result(releaseVersion: string, files: readonly ReleaseInventoryFile[], aggregateSha256: string): ReleaseVerificationResult {
  return Object.freeze({
    ok: true,
    releaseVersion,
    protocolVersion: PROTOCOL_VERSION,
    fileCount: files.length,
    byteCount: files.reduce((total, file) => total + file.bytes, 0),
    aggregateSha256
  });
}

export function createReleaseInventory(rootDirectory: string, policyPath: string, outputPath: string): ReleaseVerificationResult {
  const root = resolve(rootDirectory);
  const output = resolve(outputPath);
  const relativeOutput = relative(root, output);
  if (relativeOutput === "" || (!relativeOutput.startsWith(`..${sep}`) && relativeOutput !== ".." && !isAbsolute(relativeOutput))) {
    fail("OPS_RELEASE_INVENTORY_OUTPUT_INVALID");
  }
  const { policy, sha256: policySha256 } = readPolicy(resolve(policyPath));
  const candidate = inspectCandidate(root, policy);
  const aggregateSha256 = aggregateHash(candidate.files);
  const inventory: ReleaseInventory = Object.freeze({
    schemaVersion: RELEASE_INVENTORY_SCHEMA_VERSION,
    releaseVersion: candidate.releaseVersion,
    protocolVersion: PROTOCOL_VERSION,
    policySha256,
    aggregateSha256,
    files: candidate.files
  });
  let descriptor: number | undefined;
  try {
    descriptor = openSync(output, "wx", 0o600);
    writeFileSync(descriptor, `${JSON.stringify(inventory, null, 2)}\n`, "utf8");
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      return fail("OPS_RELEASE_INVENTORY_OUTPUT_EXISTS");
    }
    return fail("OPS_RELEASE_INVENTORY_WRITE_FAILED");
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
  }
  return result(candidate.releaseVersion, candidate.files, aggregateSha256);
}

export function stageReleaseCandidate(sourceDirectory: string, policyPath: string, outputDirectory: string): ReleaseVerificationResult {
  const source = resolve(sourceDirectory);
  const output = resolve(outputDirectory);
  const relativeOutput = relative(source, output);
  if (relativeOutput === "" || (!relativeOutput.startsWith(`..${sep}`) && relativeOutput !== ".." && !isAbsolute(relativeOutput))) {
    fail("OPS_RELEASE_STAGE_OUTPUT_INVALID");
  }
  if (existsSync(output)) {
    fail("OPS_RELEASE_STAGE_OUTPUT_EXISTS");
  }
  let realSource: string;
  try {
    const sourceStatus = lstatSync(source);
    if (!sourceStatus.isDirectory() || sourceStatus.isSymbolicLink()) {
      return fail("OPS_RELEASE_SOURCE_INVALID");
    }
    realSource = realpathSync(source);
  } catch {
    return fail("OPS_RELEASE_SOURCE_INVALID");
  }
  const { policy } = readPolicy(resolve(policyPath));
  const files = expectedFiles(policy);
  let createdOutput = false;
  try {
    mkdirSync(output, { mode: 0o700 });
    createdOutput = true;
    for (const path of files) {
      const sourcePath = join(source, ...path.split("/"));
      const status = lstatSync(sourcePath);
      const resolvedSourcePath = realpathSync(sourcePath);
      const sourceRelative = relative(realSource, resolvedSourcePath);
      if (!status.isFile() || status.isSymbolicLink() || sourceRelative === "" ||
          sourceRelative.startsWith(`..${sep}`) || sourceRelative === ".." || isAbsolute(sourceRelative)) {
        fail("OPS_RELEASE_SOURCE_FILE_INVALID");
      }
      const outputPath = join(output, ...path.split("/"));
      mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
      copyFileSync(sourcePath, outputPath);
    }
    const candidate = inspectCandidate(output, policy);
    const aggregateSha256 = aggregateHash(candidate.files);
    return result(candidate.releaseVersion, candidate.files, aggregateSha256);
  } catch (error: unknown) {
    if (createdOutput) {
      try {
        rmSync(output, { recursive: true, force: true });
      } catch {
        return fail("OPS_RELEASE_STAGE_CLEANUP_FAILED");
      }
    }
    if (error instanceof OpsError) {
      throw error;
    }
    return fail("OPS_RELEASE_STAGE_COPY_FAILED");
  }
}

function parseInventory(bytes: Buffer): ReleaseInventory {
  const root = record(parseJson(bytes, "OPS_RELEASE_INVENTORY_JSON_INVALID"), "OPS_RELEASE_INVENTORY_INVALID");
  exactFields(root, ["schemaVersion", "releaseVersion", "protocolVersion", "policySha256", "aggregateSha256", "files"], "OPS_RELEASE_INVENTORY_INVALID");
  if (root.schemaVersion !== RELEASE_INVENTORY_SCHEMA_VERSION) {
    fail("OPS_RELEASE_INVENTORY_VERSION_MISMATCH");
  }
  const releaseVersion = strictString(root.releaseVersion, VERSION_PATTERN, "OPS_RELEASE_VERSION_INVALID");
  if (root.protocolVersion !== PROTOCOL_VERSION) {
    fail("OPS_RELEASE_PROTOCOL_VERSION_MISMATCH");
  }
  const policySha256 = strictString(root.policySha256, SHA256_PATTERN, "OPS_RELEASE_INVENTORY_INVALID");
  const aggregateSha256 = strictString(root.aggregateSha256, SHA256_PATTERN, "OPS_RELEASE_INVENTORY_INVALID");
  if (!Array.isArray(root.files)) {
    return fail("OPS_RELEASE_INVENTORY_INVALID");
  }
  const files = root.files.map((entry): ReleaseInventoryFile => {
    const file = record(entry, "OPS_RELEASE_INVENTORY_INVALID");
    exactFields(file, ["path", "bytes", "sha256"], "OPS_RELEASE_INVENTORY_INVALID");
    const path = strictRelativePath(file.path, "OPS_RELEASE_INVENTORY_INVALID");
    if (!Number.isSafeInteger(file.bytes) || (file.bytes as number) < 0) {
      return fail("OPS_RELEASE_INVENTORY_INVALID");
    }
    return Object.freeze({ path, bytes: file.bytes as number, sha256: strictString(file.sha256, SHA256_PATTERN, "OPS_RELEASE_INVENTORY_INVALID") });
  });
  if (new Set(files.map(({ path }) => path)).size !== files.length || files.some((file, index) => index > 0 && file.path <= (files[index - 1]?.path ?? ""))) {
    fail("OPS_RELEASE_INVENTORY_INVALID");
  }
  return Object.freeze({
    schemaVersion: RELEASE_INVENTORY_SCHEMA_VERSION,
    releaseVersion,
    protocolVersion: PROTOCOL_VERSION,
    policySha256,
    aggregateSha256,
    files: Object.freeze(files)
  });
}

export function validateReleaseInventory(rootDirectory: string, policyPath: string, inventoryPath: string): ReleaseVerificationResult {
  let inventoryStatus: ReturnType<typeof lstatSync>;
  try {
    inventoryStatus = lstatSync(inventoryPath);
  } catch {
    return fail("OPS_RELEASE_INVENTORY_FILE_INVALID");
  }
  if (!inventoryStatus.isFile() || inventoryStatus.isSymbolicLink()) {
    return fail("OPS_RELEASE_INVENTORY_FILE_INVALID");
  }
  const inventory = parseInventory(readFileSync(inventoryPath));
  const { policy, sha256: policySha256 } = readPolicy(resolve(policyPath));
  if (inventory.policySha256 !== policySha256) {
    fail("OPS_RELEASE_POLICY_HASH_MISMATCH");
  }
  const candidate = inspectCandidate(rootDirectory, policy);
  if (inventory.releaseVersion !== candidate.releaseVersion || inventory.files.length !== candidate.files.length) {
    fail("OPS_RELEASE_INVENTORY_MISMATCH");
  }
  for (let index = 0; index < candidate.files.length; index += 1) {
    const expected = inventory.files[index];
    const actual = candidate.files[index];
    if (expected === undefined || actual === undefined || expected.path !== actual.path ||
        expected.bytes !== actual.bytes || expected.sha256 !== actual.sha256) {
      fail("OPS_RELEASE_INVENTORY_MISMATCH");
    }
  }
  const aggregateSha256 = aggregateHash(candidate.files);
  if (inventory.aggregateSha256 !== aggregateSha256) {
    fail("OPS_RELEASE_AGGREGATE_HASH_MISMATCH");
  }
  return result(candidate.releaseVersion, candidate.files, aggregateSha256);
}
