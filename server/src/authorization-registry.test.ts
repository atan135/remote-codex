import { generateKeyPairSync } from "node:crypto";

import {
  createEdgeDeviceIdentity,
  createEgressAgentIdentity,
  createIdentityPublicKey,
  IdentityKeyRole,
  type EdgeDeviceIdentity,
  type EgressAgentIdentity
} from "@remote-codex/shared";
import { describe, expect, it } from "vitest";

import {
  AuthorizationRegistry,
  AuthorizationStatus,
  parseAuthorizationRegistryJson,
  type AuthorizationRegistration,
  type AuthorizationRegistryDocument,
  type ServerPeerIdentityRegistration
} from "./index.js";

interface AuthorizationFixture {
  readonly alice: EdgeDeviceIdentity;
  readonly bob: EdgeDeviceIdentity;
  readonly sharedAgent: EgressAgentIdentity;
  readonly otherAgent: EgressAgentIdentity;
  readonly peerIdentities: readonly ServerPeerIdentityRegistration[];
}

function createEdgeIdentity(edgeUserId: string, edgeDeviceId: string): EdgeDeviceIdentity {
  const keys = generateKeyPairSync("ed25519");
  return createEdgeDeviceIdentity({
    edgeUserId,
    edgeDeviceId,
    authenticationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: `${edgeDeviceId}-key` },
      keys.publicKey
    )
  });
}

function createAgentIdentity(agentId: string): EgressAgentIdentity {
  const keys = generateKeyPairSync("ed25519");
  return createEgressAgentIdentity({
    agentId,
    authenticationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: `${agentId}-key` },
      keys.publicKey
    )
  });
}

function createFixture(): AuthorizationFixture {
  const alice = createEdgeIdentity("edge-user-alice", "edge-device-alice");
  const bob = createEdgeIdentity("edge-user-bob", "edge-device-bob");
  const sharedAgent = createAgentIdentity("company-agent-shared");
  const otherAgent = createAgentIdentity("company-agent-other");

  return {
    alice,
    bob,
    sharedAgent,
    otherAgent,
    peerIdentities: Object.freeze([
      { identity: alice },
      { identity: bob },
      { identity: sharedAgent },
      { identity: otherAgent }
    ])
  };
}

function registration(
  edgeIdentity: EdgeDeviceIdentity,
  agentIdentity: EgressAgentIdentity,
  auditVersion: number,
  status: AuthorizationStatus = AuthorizationStatus.ACTIVE
): AuthorizationRegistration {
  return {
    edgeUserId: edgeIdentity.edgeUserId,
    edgeDeviceId: edgeIdentity.edgeDeviceId,
    agentId: agentIdentity.agentId,
    status,
    quota: { maxConcurrentStreams: 2, maxBufferedBytes: 16 * 1024 },
    createdAtMs: 1_000,
    ...(status === AuthorizationStatus.REVOKED ? { revokedAtMs: 1_001 } : {}),
    auditVersion
  };
}

function document(
  auditVersion: number,
  authorizations: readonly AuthorizationRegistration[]
): AuthorizationRegistryDocument {
  return { auditVersion, authorizations };
}

function edgeMetadata(identity: EdgeDeviceIdentity): {
  readonly kind: "edge-device";
  readonly edgeUserId: string;
  readonly edgeDeviceId: string;
} {
  return {
    kind: "edge-device",
    edgeUserId: identity.edgeUserId,
    edgeDeviceId: identity.edgeDeviceId
  };
}

function expectAuthorizationError(operation: () => unknown, code: string): void {
  let thrown: unknown;

  try {
    operation();
  } catch (error: unknown) {
    thrown = error;
  }

  expect(thrown).toMatchObject({ code });
}

describe("多用户共享 agent 授权注册表", () => {
  it("将多个用户和设备显式关联到同一 agent，且不接受请求选择其他 agent", () => {
    const fixture = createFixture();
    const registry = new AuthorizationRegistry({
      peerIdentities: fixture.peerIdentities,
      document: document(1, [
        registration(fixture.alice, fixture.sharedAgent, 1),
        registration(fixture.bob, fixture.sharedAgent, 1)
      ])
    });

    const aliceRoute = registry.resolveAgentForEdge(edgeMetadata(fixture.alice));
    const bobRoute = registry.resolveAgentForEdge(edgeMetadata(fixture.bob));
    const spoofedRequestMetadata = {
      ...edgeMetadata(fixture.alice),
      agentId: fixture.otherAgent.agentId
    };

    expect(aliceRoute).toMatchObject({
      agentId: fixture.sharedAgent.agentId,
      quota: { maxConcurrentStreams: 2, maxBufferedBytes: 16 * 1024 }
    });
    expect(bobRoute?.agentId).toBe(fixture.sharedAgent.agentId);
    expect(registry.resolveAgentForEdge(spoofedRequestMetadata)?.agentId).toBe(fixture.sharedAgent.agentId);
    expect(registry.getSnapshot().authorizations).toHaveLength(2);
  });

  it("拒绝未知身份、重复授权和同一 user/device 的冲突 active agent", () => {
    const fixture = createFixture();

    expectAuthorizationError(
      () =>
        new AuthorizationRegistry({
          peerIdentities: fixture.peerIdentities,
          document: document(1, [
            {
              ...registration(fixture.alice, fixture.sharedAgent, 1),
              edgeDeviceId: "unregistered-device"
            }
          ])
        }),
      "SERVER_AUTHORIZATION_EDGE_DEVICE_UNKNOWN"
    );

    expectAuthorizationError(
      () =>
        new AuthorizationRegistry({
          peerIdentities: fixture.peerIdentities,
          document: document(1, [
            registration(fixture.alice, fixture.sharedAgent, 1),
            registration(fixture.alice, fixture.sharedAgent, 1)
          ])
        }),
      "SERVER_AUTHORIZATION_DUPLICATE"
    );

    expectAuthorizationError(
      () =>
        new AuthorizationRegistry({
          peerIdentities: fixture.peerIdentities,
          document: document(1, [
            registration(fixture.alice, fixture.sharedAgent, 1),
            registration(fixture.alice, fixture.otherAgent, 1)
          ])
        }),
      "SERVER_AUTHORIZATION_EDGE_AGENT_CONFLICT"
    );
  });

  it("将 user/device 同时绑定到认证身份，阻止设备冒用和已撤销路由", () => {
    const fixture = createFixture();
    const registry = new AuthorizationRegistry({
      peerIdentities: fixture.peerIdentities,
      document: document(1, [
        registration(fixture.alice, fixture.sharedAgent, 1),
        registration(fixture.bob, fixture.otherAgent, 1, AuthorizationStatus.REVOKED)
      ])
    });

    expect(
      registry.resolveAgentForEdge({
        kind: "edge-device",
        edgeUserId: fixture.alice.edgeUserId,
        edgeDeviceId: fixture.bob.edgeDeviceId
      })
    ).toBeUndefined();
    expect(
      registry.resolveAgentForEdge({
        kind: "edge-device",
        edgeUserId: fixture.bob.edgeUserId,
        edgeDeviceId: fixture.alice.edgeDeviceId
      })
    ).toBeUndefined();
    expect(registry.resolveAgentForEdge(edgeMetadata(fixture.bob))).toBeUndefined();
  });

  it("严格解析 JSON，并在失败热更新时原子保留旧授权", () => {
    const fixture = createFixture();
    const registry = new AuthorizationRegistry({
      peerIdentities: fixture.peerIdentities,
      document: document(1, [registration(fixture.alice, fixture.sharedAgent, 1)])
    });
    const before = registry.getSnapshot();

    expectAuthorizationError(
      () => parseAuthorizationRegistryJson('{"auditVersion":2,"authorizations":[],"unexpected":true}'),
      "SERVER_AUTHORIZATION_DOCUMENT_UNKNOWN_FIELD"
    );
    expectAuthorizationError(
      () =>
        registry.replaceDocument(
          document(2, [
            {
              ...registration(fixture.alice, fixture.sharedAgent, 2),
              agentId: "unknown-agent"
            }
          ])
        ),
      "SERVER_AUTHORIZATION_AGENT_UNKNOWN"
    );
    expect(registry.getSnapshot()).toEqual(before);
    expect(registry.resolveAgentForEdge(edgeMetadata(fixture.alice))?.agentId).toBe(fixture.sharedAgent.agentId);

    const update = registry.replaceJson(
      JSON.stringify(document(2, [registration(fixture.alice, fixture.otherAgent, 2)]))
    );
    expect(update).toMatchObject({ auditVersion: 2, changed: true, revocations: [{ closeExistingStreams: true }] });
    expect(registry.resolveAgentForEdge(edgeMetadata(fixture.alice))?.agentId).toBe(fixture.otherAgent.agentId);
    expectAuthorizationError(
      () => registry.replaceDocument(document(1, [registration(fixture.alice, fixture.sharedAgent, 1)])),
      "SERVER_AUTHORIZATION_DOCUMENT_VERSION_STALE"
    );
  });

  it("按设备、用户和 agent 撤销新路由，并发布关闭存量流所需的受影响授权", () => {
    const fixture = createFixture();
    const registry = new AuthorizationRegistry({
      peerIdentities: fixture.peerIdentities,
      document: document(1, [
        registration(fixture.alice, fixture.sharedAgent, 1),
        registration(fixture.bob, fixture.sharedAgent, 1)
      ])
    });
    const received: unknown[] = [];
    const unsubscribe = registry.subscribeRevocations((result) => received.push(result));

    const deviceRevocation = registry.revokeByEdgeDevice(fixture.alice.edgeDeviceId, 2_000);
    expect(deviceRevocation).toMatchObject({
      auditVersion: 2,
      changed: true,
      revocations: [{ edgeDeviceId: fixture.alice.edgeDeviceId, reason: "edge-device", closeExistingStreams: true }]
    });
    expect(registry.resolveAgentForEdge(edgeMetadata(fixture.alice))).toBeUndefined();
    expect(registry.resolveAgentForEdge(edgeMetadata(fixture.bob))?.agentId).toBe(fixture.sharedAgent.agentId);

    const userRevocation = registry.revokeByEdgeUser(fixture.bob.edgeUserId, 2_001);
    expect(userRevocation.revocations).toMatchObject([
      { edgeUserId: fixture.bob.edgeUserId, reason: "edge-user", closeExistingStreams: true }
    ]);
    expect(registry.resolveAgentForEdge(edgeMetadata(fixture.bob))).toBeUndefined();

    const restored = new AuthorizationRegistry({
      peerIdentities: fixture.peerIdentities,
      document: document(1, [
        registration(fixture.alice, fixture.sharedAgent, 1),
        registration(fixture.bob, fixture.sharedAgent, 1)
      ])
    });
    const agentRevocation = restored.revokeByAgent(fixture.sharedAgent.agentId, 2_002);
    expect(agentRevocation.revocations).toHaveLength(2);
    expect(agentRevocation.revocations.every((item) => item.reason === "agent" && item.closeExistingStreams)).toBe(true);
    expect(received).toHaveLength(2);
    unsubscribe();
    expect(registry.revokeByAgent(fixture.sharedAgent.agentId, 2_002).changed).toBe(false);
  });
});
