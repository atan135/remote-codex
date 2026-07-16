import { describe, expect, it } from "vitest";

import { DEFAULT_ALLOWED_DESTINATION } from "./config.js";
import {
  DestinationValidationError,
  normalizeHostname,
  validateDestination
} from "./destination.js";

function expectDestinationError(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error("expected destination validation to fail");
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(DestinationValidationError);
    expect((error as DestinationValidationError).code).toBe(code);
  }
}

describe("destination validation", () => {
  it("normalizes case and validates the configured exact hostname", () => {
    const result = validateDestination(
      "AI-CODING-BJ-PUB.SINGULARITY-AI.COM",
      443,
      DEFAULT_ALLOWED_DESTINATION
    );

    expect(result).toEqual(DEFAULT_ALLOWED_DESTINATION);
  });

  it("normalizes Unicode hostnames to their ASCII form before comparison", () => {
    expect(normalizeHostname("b\u00fccher.example")).toBe("xn--bcher-kva.example");
  });

  it("rejects wildcard, suffix, trailing-dot, whitespace, and URL-style hostnames", () => {
    for (const hostname of [
      "*.singularity-ai.com",
      "not-ai-coding-bj-pub.singularity-ai.com",
      "ai-coding-bj-pub.singularity-ai.com.",
      " ai-coding-bj-pub.singularity-ai.com",
      "user@ai-coding-bj-pub.singularity-ai.com",
      "ai-coding-bj-pub.singularity-ai.com/path"
    ]) {
      expectDestinationError(
        () => validateDestination(hostname, 443, DEFAULT_ALLOWED_DESTINATION),
        hostname.startsWith("not-") ? "DESTINATION_HOST_NOT_ALLOWED" : "DESTINATION_INVALID_HOSTNAME"
      );
    }
  });

  it("rejects canonical and ambiguous IPv4 and IPv6 literals", () => {
    for (const hostname of [
      "127.0.0.1",
      "127.1",
      "0x7f000001",
      "0177.0.0.1",
      "2130706433",
      "::1",
      "[::1]"
    ]) {
      expectDestinationError(
        () => validateDestination(hostname, 443, DEFAULT_ALLOWED_DESTINATION),
        "DESTINATION_IP_LITERAL_NOT_ALLOWED"
      );
    }
  });

  it("rejects every port other than 443 before any match result", () => {
    expectDestinationError(
      () => validateDestination(DEFAULT_ALLOWED_DESTINATION.hostname, 80, DEFAULT_ALLOWED_DESTINATION),
      "DESTINATION_PORT_NOT_ALLOWED"
    );
  });

  it("does not include the rejected hostname in its error", () => {
    const rejectedHostname = "secret-hostname.example";

    try {
      validateDestination(rejectedHostname, 443, DEFAULT_ALLOWED_DESTINATION);
      throw new Error("expected destination validation to fail");
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(DestinationValidationError);
      expect((error as Error).message).not.toContain(rejectedHostname);
    }
  });
});
