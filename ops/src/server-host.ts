import {
  DEFAULT_SERVER_TRANSPORT_LIMITS,
  MAX_CONNECTION_RATE_WINDOW_MS,
  MIN_CONNECTION_RATE_WINDOW_MS,
  type ServerTransportLimits
} from "@remote-codex/server";
import { normalizeHostname } from "@remote-codex/shared";

import { fail } from "./errors.js";

export const SERVER_HOST_CONFIG_SCHEMA_VERSION = 2 as const;

export type ServerListenHost = "0.0.0.0" | "127.0.0.1";
export type ServerClientAddressSource = "socket" | "loopback-x-forwarded-for";
export type ServerTlsMinimumVersion = "TLSv1.2" | "TLSv1.3";

export interface ServerHostConfig {
  readonly schemaVersion: typeof SERVER_HOST_CONFIG_SCHEMA_VERSION;
  readonly listenHost: ServerListenHost;
  readonly listenPort: number;
  readonly publicHostname: string;
  readonly publicPort: number;
  readonly allowedOrigins: readonly string[];
  readonly tlsCertificatePath: string;
  readonly tlsPrivateKeyPath: string;
  readonly tlsMinimumVersion: ServerTlsMinimumVersion;
  readonly clientAddressSource: ServerClientAddressSource;
  readonly maxConnections: number;
  readonly listenBacklog: number;
  readonly shutdownTimeoutMs: number;
  readonly metricsIntervalMs: number;
  readonly transportLimits: ServerTransportLimits;
}

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown, path: string): JsonRecord {
  if (
    value === null ||
    typeof value !== "object" ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    return fail("OPS_EXPECTED_OBJECT", path);
  }
  return value as JsonRecord;
}

function exactKeys(record: JsonRecord, keys: readonly string[], path: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      fail("OPS_UNKNOWN_FIELD", `${path}.${key}`);
    }
  }
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      fail("OPS_REQUIRED_FIELD_MISSING", `${path}.${key}`);
    }
  }
}

function strictRelativePath(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value ||
    value.includes("\\") ||
    value.includes(":") ||
    value.includes("\0") ||
    value.startsWith("/") ||
    value.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")
  ) {
    return fail("OPS_PATH_NOT_STRICTLY_RELATIVE", path);
  }
  return value;
}

function integer(value: unknown, path: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    return fail("OPS_SERVER_HOST_INTEGER_INVALID", path);
  }
  return value as number;
}

function parsePublicHostname(value: unknown): string {
  if (typeof value !== "string") {
    return fail("OPS_SERVER_PUBLIC_HOSTNAME_INVALID", "serverHost.publicHostname");
  }
  try {
    const normalized = normalizeHostname(value);
    if (normalized !== value) {
      return fail("OPS_SERVER_PUBLIC_HOSTNAME_INVALID", "serverHost.publicHostname");
    }
    return normalized;
  } catch {
    return fail("OPS_SERVER_PUBLIC_HOSTNAME_INVALID", "serverHost.publicHostname");
  }
}

function parseAllowedOrigins(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    return fail("OPS_SERVER_ORIGINS_INVALID", "serverHost.allowedOrigins");
  }
  const origins = value.map((origin, index): string => {
    if (typeof origin !== "string") {
      return fail("OPS_SERVER_ORIGIN_INVALID", `serverHost.allowedOrigins[${index}]`);
    }
    try {
      const parsed = new URL(origin);
      const normalizedHostname = normalizeHostname(parsed.hostname);
      if (
        parsed.protocol !== "https:" ||
        parsed.origin !== origin ||
        parsed.hostname !== normalizedHostname
      ) {
        return fail("OPS_SERVER_ORIGIN_INVALID", `serverHost.allowedOrigins[${index}]`);
      }
      return origin;
    } catch {
      return fail("OPS_SERVER_ORIGIN_INVALID", `serverHost.allowedOrigins[${index}]`);
    }
  });
  if (new Set(origins).size !== origins.length) {
    return fail("OPS_SERVER_ORIGINS_DUPLICATED", "serverHost.allowedOrigins");
  }
  return Object.freeze(origins);
}

function parseListenHost(value: unknown): ServerListenHost {
  if (value === "0.0.0.0" || value === "127.0.0.1") {
    return value;
  }
  return fail("OPS_SERVER_LISTEN_HOST_INVALID", "serverHost.listenHost");
}

function parseTlsMinimumVersion(value: unknown): ServerTlsMinimumVersion {
  if (value === "TLSv1.2" || value === "TLSv1.3") {
    return value;
  }
  return fail("OPS_SERVER_TLS_MINIMUM_VERSION_INVALID", "serverHost.tlsMinimumVersion");
}

function parseClientAddressSource(value: unknown): ServerClientAddressSource {
  if (value === "socket" || value === "loopback-x-forwarded-for") {
    return value;
  }
  return fail("OPS_SERVER_CLIENT_ADDRESS_SOURCE_INVALID", "serverHost.clientAddressSource");
}

function parseTransportLimits(value: unknown): ServerTransportLimits {
  const record = asRecord(value, "serverHost.transportLimits");
  const keys = Object.keys(DEFAULT_SERVER_TRANSPORT_LIMITS) as (keyof ServerTransportLimits)[];
  exactKeys(record, keys, "serverHost.transportLimits");
  const parsed = Object.fromEntries(keys.map((key) => {
    if (key === "connectionRateWindowMs") {
      return [
        key,
        integer(
          record[key],
          `serverHost.transportLimits.${key}`,
          MIN_CONNECTION_RATE_WINDOW_MS,
          MAX_CONNECTION_RATE_WINDOW_MS
        )
      ];
    }
    const minimum = key === "maxUpgradeHeaderBytes" ? 512 : 1;
    return [
      key,
      integer(
        record[key],
        `serverHost.transportLimits.${key}`,
        minimum,
        DEFAULT_SERVER_TRANSPORT_LIMITS[key]
      )
    ];
  })) as unknown as ServerTransportLimits;
  return Object.freeze(parsed);
}

export function parseServerHostConfigJson(serialized: string): ServerHostConfig {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch {
    return fail("OPS_INVALID_JSON", "serverHost");
  }
  const record = asRecord(value, "serverHost");
  exactKeys(record, [
    "schemaVersion",
    "listenHost",
    "listenPort",
    "publicHostname",
    "publicPort",
    "allowedOrigins",
    "tlsCertificatePath",
    "tlsPrivateKeyPath",
    "tlsMinimumVersion",
    "clientAddressSource",
    "maxConnections",
    "listenBacklog",
    "shutdownTimeoutMs",
    "metricsIntervalMs",
    "transportLimits"
  ], "serverHost");
  if (record.schemaVersion !== SERVER_HOST_CONFIG_SCHEMA_VERSION) {
    return fail("OPS_SERVER_HOST_VERSION_MISMATCH", "serverHost.schemaVersion");
  }
  const listenHost = parseListenHost(record.listenHost);
  const listenPort = integer(record.listenPort, "serverHost.listenPort", 1, 65_535);
  const publicPort = integer(record.publicPort, "serverHost.publicPort", 1, 65_535);
  const clientAddressSource = parseClientAddressSource(record.clientAddressSource);
  if (listenHost === "0.0.0.0" && publicPort !== listenPort) {
    return fail("OPS_SERVER_PUBLIC_PORT_MISMATCH", "serverHost.publicPort");
  }
  if (clientAddressSource === "loopback-x-forwarded-for" && listenHost !== "127.0.0.1") {
    return fail("OPS_SERVER_PROXY_SOURCE_REQUIRES_LOOPBACK", "serverHost.clientAddressSource");
  }
  const tlsCertificatePath = strictRelativePath(record.tlsCertificatePath, "serverHost.tlsCertificatePath");
  const tlsPrivateKeyPath = strictRelativePath(record.tlsPrivateKeyPath, "serverHost.tlsPrivateKeyPath");
  if (tlsCertificatePath.toLowerCase() === tlsPrivateKeyPath.toLowerCase()) {
    return fail("OPS_SERVER_TLS_PATH_CONFLICT", "serverHost");
  }
  return Object.freeze({
    schemaVersion: SERVER_HOST_CONFIG_SCHEMA_VERSION,
    listenHost,
    listenPort,
    publicHostname: parsePublicHostname(record.publicHostname),
    publicPort,
    allowedOrigins: parseAllowedOrigins(record.allowedOrigins),
    tlsCertificatePath,
    tlsPrivateKeyPath,
    tlsMinimumVersion: parseTlsMinimumVersion(record.tlsMinimumVersion),
    clientAddressSource,
    maxConnections: integer(record.maxConnections, "serverHost.maxConnections", 1, 4_096),
    listenBacklog: integer(record.listenBacklog, "serverHost.listenBacklog", 1, 1_024),
    shutdownTimeoutMs: integer(record.shutdownTimeoutMs, "serverHost.shutdownTimeoutMs", 1_000, 30_000),
    metricsIntervalMs: integer(record.metricsIntervalMs, "serverHost.metricsIntervalMs", 10_000, 600_000),
    transportLimits: parseTransportLimits(record.transportLimits)
  });
}
