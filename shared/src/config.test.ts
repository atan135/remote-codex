import { describe, expect, it } from "vitest";

import {
  assertTlsVerificationEnabled,
  ConfigError,
  DEFAULT_ALLOWED_DESTINATION,
  DEFAULT_RESOURCE_LIMITS,
  parseEgressAgentConfig,
  parseEdgeClientConfig,
  parseResourceLimits,
  parseRuntimeConfigJson,
  parseServerConfig
} from "./config.js";

const destination = {
  hostname: DEFAULT_ALLOWED_DESTINATION.hostname,
  port: DEFAULT_ALLOWED_DESTINATION.port
};

function expectConfigError(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error("expected config parsing to fail");
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as ConfigError).code).toBe(code);
  }
}

describe("runtime configuration", () => {
  it("parses strict server, agent, and edge configurations with shared defaults", () => {
    const server = parseServerConfig({
      component: "server",
      serverId: "public-server-1",
      allowedDestination: destination
    });
    const agent = parseEgressAgentConfig({
      component: "egress-agent",
      agentId: "company-agent-1",
      serverUrl: "wss://tunnel.example.test/v1",
      allowedDestination: destination
    });
    const edge = parseEdgeClientConfig({
      component: "edge-client",
      edgeUserId: "edge-user-1",
      edgeDeviceId: "edge-device-1",
      serverUrl: "wss://tunnel.example.test/v1",
      allowedDestination: destination
    });

    expect(server.limits).toEqual(DEFAULT_RESOURCE_LIMITS);
    expect(agent.limits).toEqual(DEFAULT_RESOURCE_LIMITS);
    expect(edge.limits).toEqual(DEFAULT_RESOURCE_LIMITS);
    expect(edge.listenHost).toBe("127.0.0.1");
    expect(edge.listenPort).toBe(8_787);
    expect(agent.serverUrl.href).toBe("wss://tunnel.example.test/v1");
  });

  it("allows only stricter limit overrides", () => {
    const limits = parseResourceLimits({
      maxConcurrentStreams: 4,
      maxBufferedBytesPerStream: 64 * 1024,
      maxAggregateBufferedBytes: 512 * 1024,
      maxFramePayloadBytes: 8 * 1024,
      maxIdleMs: 60_000,
      connectTimeoutMs: 5_000,
      openTimeoutMs: 7_500,
      heartbeatIntervalMs: 5_000,
      heartbeatTimeoutMs: 15_000,
      reconnectInitialMs: 500,
      reconnectMaxMs: 10_000,
      maxReconnectAttempts: 4
    });

    expect(limits.maxConcurrentStreams).toBe(4);
    expect(limits.maxFramePayloadBytes).toBe(8 * 1024);
  });

  it("rejects unknown fields, loose limits, and invalid field relationships", () => {
    expectConfigError(
      () =>
        parseServerConfig({
          component: "server",
          serverId: "public-server-1",
          allowedDestination: destination,
          unexpected: true
        }),
      "CONFIG_UNKNOWN_FIELD"
    );
    expectConfigError(
      () => parseResourceLimits({ maxFramePayloadBytes: DEFAULT_RESOURCE_LIMITS.maxFramePayloadBytes + 1 }),
      "CONFIG_LIMIT_OUT_OF_RANGE"
    );
    expectConfigError(
      () => parseResourceLimits({ heartbeatIntervalMs: 10_000, heartbeatTimeoutMs: 5_000 }),
      "CONFIG_LIMIT_RELATION_INVALID"
    );
  });

  it("rejects non-loopback edge listeners, non-WSS endpoints, and non-443 targets", () => {
    expectConfigError(
      () =>
        parseEdgeClientConfig({
          component: "edge-client",
          edgeUserId: "edge-user-1",
          edgeDeviceId: "edge-device-1",
          serverUrl: "wss://tunnel.example.test",
          listenHost: "0.0.0.0",
          allowedDestination: destination
        }),
      "CONFIG_LISTEN_HOST_NOT_LOOPBACK"
    );
    expectConfigError(
      () =>
        parseEdgeClientConfig({
          component: "edge-client",
          edgeUserId: "edge-user-1",
          edgeDeviceId: "edge-device-1",
          serverUrl: "wss://tunnel.example.test",
          listenHost: "::1",
          allowedDestination: destination
        }),
      "CONFIG_LISTEN_HOST_NOT_LOOPBACK"
    );
    expectConfigError(
      () =>
        parseEgressAgentConfig({
          component: "egress-agent",
          agentId: "company-agent-1",
          serverUrl: "ws://tunnel.example.test",
          allowedDestination: destination
        }),
      "CONFIG_INVALID_WSS_URL"
    );
    expectConfigError(
      () => parseServerConfig({ component: "server", serverId: "public-server-1", allowedDestination: { hostname: "example.test", port: 80 } }),
      "CONFIG_DESTINATION_PORT_NOT_ALLOWED"
    );
  });

  it("does not echo serialized configuration secrets in failures", () => {
    const secret = "not-for-logs";

    try {
      parseRuntimeConfigJson(`{"component":"server","credential":"${secret}"}`);
      throw new Error("expected config parsing to fail");
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as Error).message).not.toContain(secret);
    }
  });

  it("rejects a runtime with TLS verification disabled", () => {
    expectConfigError(
      () => assertTlsVerificationEnabled({ NODE_TLS_REJECT_UNAUTHORIZED: "0" }),
      "CONFIG_TLS_VERIFICATION_DISABLED"
    );
  });
});
