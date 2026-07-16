import { describe, expect, it } from "vitest";

import { serializeStreamAuditEvent, type StreamAuditEvent } from "./observability.js";

describe("server 审计序列化", () => {
  it("只序列化白名单元数据，即使上游对象意外携带请求内容或认证材料", () => {
    const serialized = serializeStreamAuditEvent({
      event: "stream.closed",
      occurredAtMs: 1_000,
      streamId: "stream-1",
      edgePeerId: "peer-edge-1",
      edgeUserId: "user-1",
      edgeDeviceId: "device-1",
      agentPeerId: "peer-agent-1",
      agentId: "agent-1",
      state: "closed",
      edgeToAgentBytes: 7,
      agentToEdgeBytes: 11,
      durationMs: 12,
      errorCode: "PEER_DISCONNECTED",
      closeCode: "PEER_DISCONNECTED",
      payload: "GET /secret HTTP/1.1",
      authorization: "Bearer very-secret-token",
      cookie: "session=very-secret-cookie",
      capability: "very-secret-capability",
      privateKey: "very-secret-key"
    } as unknown as StreamAuditEvent);

    const parsed = JSON.parse(serialized) as Record<string, unknown>;
    expect(parsed).toEqual({
      event: "stream.closed",
      occurredAtMs: 1_000,
      streamId: "stream-1",
      edgePeerId: "peer-edge-1",
      edgeUserId: "user-1",
      edgeDeviceId: "device-1",
      agentPeerId: "peer-agent-1",
      agentId: "agent-1",
      state: "closed",
      edgeToAgentBytes: 7,
      agentToEdgeBytes: 11,
      durationMs: 12,
      errorCode: "PEER_DISCONNECTED",
      closeCode: "PEER_DISCONNECTED"
    });
    expect(serialized).not.toContain("very-secret");
    expect(serialized).not.toContain("GET /secret");
  });
});
