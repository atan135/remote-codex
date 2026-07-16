import { isIP } from "node:net";
import { domainToASCII } from "node:url";

import type { AllowedDestination } from "./config.js";

export interface ValidatedDestination {
  readonly hostname: string;
  readonly port: 443;
}

export class DestinationValidationError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "DestinationValidationError";
  }
}

const HOST_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const IPV4_COMPONENT = "(?:0x[0-9a-f]+|0[0-7]*|[0-9]+)";
const AMBIGUOUS_IPV4_PATTERN = new RegExp(`^${IPV4_COMPONENT}(?:\\.${IPV4_COMPONENT}){0,3}$`, "iu");

function fail(code: string): never {
  throw new DestinationValidationError(code);
}

function isBracketedIpLiteral(value: string): boolean {
  return value.startsWith("[") && value.endsWith("]") && isIP(value.slice(1, -1)) !== 0;
}

function hasForbiddenAuthoritySyntax(value: string): boolean {
  return /[/:?#@\\]/u.test(value);
}

export function normalizeHostname(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    return fail("DESTINATION_INVALID_HOSTNAME");
  }

  if (isIP(value) !== 0 || isBracketedIpLiteral(value) || AMBIGUOUS_IPV4_PATTERN.test(value)) {
    return fail("DESTINATION_IP_LITERAL_NOT_ALLOWED");
  }

  if (hasForbiddenAuthoritySyntax(value) || value.includes("*") || value.endsWith(".")) {
    return fail("DESTINATION_INVALID_HOSTNAME");
  }

  const hostname = domainToASCII(value).toLowerCase();

  if (
    hostname.length === 0 ||
    hostname.length > 253 ||
    isIP(hostname) !== 0 ||
    AMBIGUOUS_IPV4_PATTERN.test(hostname) ||
    hostname.endsWith(".")
  ) {
    return fail("DESTINATION_INVALID_HOSTNAME");
  }

  const labels = hostname.split(".");

  if (labels.length < 2 || labels.some((label) => !HOST_LABEL_PATTERN.test(label))) {
    return fail("DESTINATION_INVALID_HOSTNAME");
  }

  return hostname;
}

export function validateDestination(
  requestedHostname: unknown,
  requestedPort: unknown,
  allowedDestination: AllowedDestination
): ValidatedDestination {
  if (!Number.isSafeInteger(requestedPort) || requestedPort !== 443) {
    return fail("DESTINATION_PORT_NOT_ALLOWED");
  }

  if (allowedDestination.port !== 443) {
    return fail("DESTINATION_CONFIGURATION_INVALID");
  }

  const requested = normalizeHostname(requestedHostname);
  const allowed = normalizeHostname(allowedDestination.hostname);

  if (requested !== allowed) {
    return fail("DESTINATION_HOST_NOT_ALLOWED");
  }

  return Object.freeze({ hostname: allowed, port: 443 });
}
