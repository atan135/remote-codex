/** v2 将认证 challenge 的 issuedAtMs 纳入 wire payload，避免 client 猜测认证窗口。 */
export const PROTOCOL_VERSION = 2 as const;

export interface AllowedDestination {
  readonly hostname: string;
  readonly port: 443;
}

export interface ResourceLimits {
  readonly maxConcurrentStreams: number;
  readonly maxBufferedBytesPerStream: number;
  readonly maxAggregateBufferedBytes: number;
  readonly maxFramePayloadBytes: number;
  readonly maxIdleMs: number;
  readonly connectTimeoutMs: number;
  readonly openTimeoutMs: number;
  readonly heartbeatIntervalMs: number;
  readonly heartbeatTimeoutMs: number;
  readonly reconnectInitialMs: number;
  readonly reconnectMaxMs: number;
  readonly maxReconnectAttempts: number;
}

export interface ServerConfig {
  readonly component: "server";
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly serverId: string;
  readonly allowedDestination: AllowedDestination;
  readonly limits: ResourceLimits;
}

export interface EgressAgentConfig {
  readonly component: "egress-agent";
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly agentId: string;
  readonly serverUrl: URL;
  readonly allowedDestination: AllowedDestination;
  readonly limits: ResourceLimits;
}

export interface EdgeClientConfig {
  readonly component: "edge-client";
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
  readonly serverUrl: URL;
  /** edge 代理只能暴露在 IPv4 loopback，禁止 IPv6 或任何公共监听地址。 */
  readonly listenHost: "127.0.0.1";
  readonly listenPort: number;
  readonly allowedDestination: AllowedDestination;
  readonly limits: ResourceLimits;
}

export type RuntimeConfig = ServerConfig | EgressAgentConfig | EdgeClientConfig;

export const DEFAULT_ALLOWED_DESTINATION: AllowedDestination = Object.freeze({
  hostname: "ai-coding-bj-pub.singularity-ai.com",
  port: 443
});

export const DEFAULT_RESOURCE_LIMITS: ResourceLimits = Object.freeze({
  maxConcurrentStreams: 32,
  maxBufferedBytesPerStream: 256 * 1024,
  maxAggregateBufferedBytes: 8 * 1024 * 1024,
  maxFramePayloadBytes: 16 * 1024,
  maxIdleMs: 120_000,
  connectTimeoutMs: 10_000,
  openTimeoutMs: 15_000,
  heartbeatIntervalMs: 15_000,
  heartbeatTimeoutMs: 45_000,
  reconnectInitialMs: 1_000,
  reconnectMaxMs: 30_000,
  maxReconnectAttempts: 12
});

export class ConfigError extends Error {
  public constructor(
    public readonly code: string,
    public readonly path: string
  ) {
    super(`${code}:${path}`);
    this.name = "ConfigError";
  }
}

type ConfigRecord = Record<string, unknown>;

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function fail(code: string, path: string): never {
  throw new ConfigError(code, path);
}

function asRecord(value: unknown, path: string): ConfigRecord {
  if (
    value === null ||
    typeof value !== "object" ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    return fail("CONFIG_EXPECTED_OBJECT", path);
  }

  return value as ConfigRecord;
}

function expectExactKeys(record: ConfigRecord, path: string, allowedKeys: readonly string[]): void {
  const allowed = new Set(allowedKeys);

  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      fail("CONFIG_UNKNOWN_FIELD", `${path}.${key}`);
    }
  }
}

function hasOwn(record: ConfigRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function requiredString(record: ConfigRecord, key: string, path: string): string {
  const value = record[key];

  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    return fail("CONFIG_EXPECTED_NONEMPTY_STRING", `${path}.${key}`);
  }

  return value;
}

function requiredIdentifier(record: ConfigRecord, key: string, path: string): string {
  const value = requiredString(record, key, path);

  if (!IDENTIFIER_PATTERN.test(value)) {
    return fail("CONFIG_INVALID_IDENTIFIER", `${path}.${key}`);
  }

  return value;
}

function requiredInteger(
  record: ConfigRecord,
  key: string,
  path: string,
  minimum: number,
  maximum: number
): number {
  const value = record[key];

  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    return fail("CONFIG_INVALID_INTEGER", `${path}.${key}`);
  }

  return value;
}

function parseAllowedDestination(value: unknown, path: string): AllowedDestination {
  const record = asRecord(value, path);
  expectExactKeys(record, path, ["hostname", "port"]);
  const hostname = requiredString(record, "hostname", path);

  if (
    hostname.length > 253 ||
    hostname.includes("/") ||
    hostname.includes("?") ||
    hostname.includes("#") ||
    hostname.includes("@")
  ) {
    return fail("CONFIG_INVALID_HOSTNAME", `${path}.hostname`);
  }

  if (requiredInteger(record, "port", path, 1, 65_535) !== 443) {
    return fail("CONFIG_DESTINATION_PORT_NOT_ALLOWED", `${path}.port`);
  }

  return Object.freeze({ hostname, port: 443 });
}

function parseSecureWebSocketUrl(value: unknown, path: string): URL {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    return fail("CONFIG_EXPECTED_NONEMPTY_STRING", path);
  }

  let url: URL;

  try {
    url = new URL(value);
  } catch {
    return fail("CONFIG_INVALID_WSS_URL", path);
  }

  if (
    url.protocol !== "wss:" ||
    url.hostname.length === 0 ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    return fail("CONFIG_INVALID_WSS_URL", path);
  }

  return url;
}

function parseListenHost(value: unknown, path: string): "127.0.0.1" {
  if (value === "127.0.0.1") {
    return value;
  }

  return fail("CONFIG_LISTEN_HOST_NOT_LOOPBACK", path);
}

function parseLimit(
  record: ConfigRecord,
  key: keyof ResourceLimits,
  minimum: number
): number {
  const defaultValue = DEFAULT_RESOURCE_LIMITS[key];

  if (!hasOwn(record, key)) {
    return defaultValue;
  }

  const value = record[key];

  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > defaultValue
  ) {
    return fail("CONFIG_LIMIT_OUT_OF_RANGE", `limits.${key}`);
  }

  return value;
}

export function parseResourceLimits(value: unknown): ResourceLimits {
  if (value === undefined) {
    return Object.freeze({ ...DEFAULT_RESOURCE_LIMITS });
  }

  const record = asRecord(value, "limits");
  const keys: readonly (keyof ResourceLimits)[] = [
    "maxConcurrentStreams",
    "maxBufferedBytesPerStream",
    "maxAggregateBufferedBytes",
    "maxFramePayloadBytes",
    "maxIdleMs",
    "connectTimeoutMs",
    "openTimeoutMs",
    "heartbeatIntervalMs",
    "heartbeatTimeoutMs",
    "reconnectInitialMs",
    "reconnectMaxMs",
    "maxReconnectAttempts"
  ];
  expectExactKeys(record, "limits", keys);

  const limits: ResourceLimits = {
    maxConcurrentStreams: parseLimit(record, "maxConcurrentStreams", 1),
    maxBufferedBytesPerStream: parseLimit(record, "maxBufferedBytesPerStream", 1_024),
    maxAggregateBufferedBytes: parseLimit(record, "maxAggregateBufferedBytes", 1_024),
    maxFramePayloadBytes: parseLimit(record, "maxFramePayloadBytes", 1_024),
    maxIdleMs: parseLimit(record, "maxIdleMs", 1_000),
    connectTimeoutMs: parseLimit(record, "connectTimeoutMs", 100),
    openTimeoutMs: parseLimit(record, "openTimeoutMs", 100),
    heartbeatIntervalMs: parseLimit(record, "heartbeatIntervalMs", 100),
    heartbeatTimeoutMs: parseLimit(record, "heartbeatTimeoutMs", 200),
    reconnectInitialMs: parseLimit(record, "reconnectInitialMs", 100),
    reconnectMaxMs: parseLimit(record, "reconnectMaxMs", 100),
    maxReconnectAttempts: parseLimit(record, "maxReconnectAttempts", 0)
  };

  if (limits.maxFramePayloadBytes > limits.maxBufferedBytesPerStream) {
    return fail("CONFIG_LIMIT_RELATION_INVALID", "limits.maxFramePayloadBytes");
  }

  if (limits.maxBufferedBytesPerStream > limits.maxAggregateBufferedBytes) {
    return fail("CONFIG_LIMIT_RELATION_INVALID", "limits.maxBufferedBytesPerStream");
  }

  if (limits.connectTimeoutMs > limits.openTimeoutMs || limits.openTimeoutMs > limits.maxIdleMs) {
    return fail("CONFIG_LIMIT_RELATION_INVALID", "limits.openTimeoutMs");
  }

  if (limits.heartbeatIntervalMs >= limits.heartbeatTimeoutMs) {
    return fail("CONFIG_LIMIT_RELATION_INVALID", "limits.heartbeatIntervalMs");
  }

  if (limits.reconnectInitialMs > limits.reconnectMaxMs) {
    return fail("CONFIG_LIMIT_RELATION_INVALID", "limits.reconnectInitialMs");
  }

  return Object.freeze(limits);
}

export function parseServerConfig(value: unknown): ServerConfig {
  const record = asRecord(value, "config");
  expectExactKeys(record, "config", ["component", "serverId", "allowedDestination", "limits"]);

  if (record.component !== "server") {
    return fail("CONFIG_COMPONENT_MISMATCH", "config.component");
  }

  return Object.freeze({
    component: "server",
    protocolVersion: PROTOCOL_VERSION,
    serverId: requiredIdentifier(record, "serverId", "config"),
    allowedDestination: parseAllowedDestination(record.allowedDestination, "config.allowedDestination"),
    limits: parseResourceLimits(record.limits)
  });
}

export function parseEgressAgentConfig(value: unknown): EgressAgentConfig {
  const record = asRecord(value, "config");
  expectExactKeys(record, "config", ["component", "agentId", "serverUrl", "allowedDestination", "limits"]);

  if (record.component !== "egress-agent") {
    return fail("CONFIG_COMPONENT_MISMATCH", "config.component");
  }

  return Object.freeze({
    component: "egress-agent",
    protocolVersion: PROTOCOL_VERSION,
    agentId: requiredIdentifier(record, "agentId", "config"),
    serverUrl: parseSecureWebSocketUrl(record.serverUrl, "config.serverUrl"),
    allowedDestination: parseAllowedDestination(record.allowedDestination, "config.allowedDestination"),
    limits: parseResourceLimits(record.limits)
  });
}

export function parseEdgeClientConfig(value: unknown): EdgeClientConfig {
  const record = asRecord(value, "config");
  expectExactKeys(record, "config", [
    "component",
    "edgeUserId",
    "edgeDeviceId",
    "serverUrl",
    "listenHost",
    "listenPort",
    "allowedDestination",
    "limits"
  ]);

  if (record.component !== "edge-client") {
    return fail("CONFIG_COMPONENT_MISMATCH", "config.component");
  }

  const listenHost = hasOwn(record, "listenHost")
    ? parseListenHost(record.listenHost, "config.listenHost")
    : "127.0.0.1";
  const listenPort = hasOwn(record, "listenPort")
    ? requiredInteger(record, "listenPort", "config", 1, 65_535)
    : 8_787;

  return Object.freeze({
    component: "edge-client",
    protocolVersion: PROTOCOL_VERSION,
    edgeUserId: requiredIdentifier(record, "edgeUserId", "config"),
    edgeDeviceId: requiredIdentifier(record, "edgeDeviceId", "config"),
    serverUrl: parseSecureWebSocketUrl(record.serverUrl, "config.serverUrl"),
    listenHost,
    listenPort,
    allowedDestination: parseAllowedDestination(record.allowedDestination, "config.allowedDestination"),
    limits: parseResourceLimits(record.limits)
  });
}

export function parseRuntimeConfig(value: unknown): RuntimeConfig {
  const record = asRecord(value, "config");

  if (record.component === "server") {
    return parseServerConfig(record);
  }

  if (record.component === "egress-agent") {
    return parseEgressAgentConfig(record);
  }

  if (record.component === "edge-client") {
    return parseEdgeClientConfig(record);
  }

  return fail("CONFIG_UNKNOWN_COMPONENT", "config.component");
}

export function parseRuntimeConfigJson(serializedConfig: string): RuntimeConfig {
  try {
    return parseRuntimeConfig(JSON.parse(serializedConfig) as unknown);
  } catch (error: unknown) {
    if (error instanceof ConfigError) {
      throw error;
    }

    return fail("CONFIG_INVALID_JSON", "config");
  }
}

export function assertTlsVerificationEnabled(environment: NodeJS.ProcessEnv): void {
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    fail("CONFIG_TLS_VERIFICATION_DISABLED", "environment.NODE_TLS_REJECT_UNAUTHORIZED");
  }
}
