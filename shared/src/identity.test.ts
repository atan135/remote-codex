import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import { DEFAULT_ALLOWED_DESTINATION } from "./config.js";
import {
  CapabilityReplayProtector,
  createEdgeDeviceIdentity,
  createEgressAgentIdentity,
  createIdentityPrivateKey,
  createIdentityPublicKey,
  createServerSigningCredentials,
  createServerSigningIdentity,
  IdentityError,
  IdentityKeyRole,
  issueAuthenticationChallenge,
  issueCapability,
  loadIdentityPublicKey,
  NonceReplayProtector,
  signAuthenticationChallenge,
  verifyAuthenticationChallenge,
  verifyCapability
} from "./identity.js";
import type { CapabilityBinding, ServerSigningCredentials, ServerSigningIdentity } from "./identity.js";
import { createStreamId, TunnelErrorCode } from "./protocol.js";

const NOW_MS = 1_784_562_400_000;

function deterministicBytes(seed: number): (size: number) => Uint8Array {
  return (size) => Uint8Array.from({ length: size }, (_, index) => (seed + index) % 256);
}

function expectIdentityError(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error("expected identity operation to fail");
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as IdentityError).code).toBe(code);
  }
}

function createFixture(): {
  readonly edgeIdentity: ReturnType<typeof createEdgeDeviceIdentity>;
  readonly edgePrivateKey: ReturnType<typeof createIdentityPrivateKey<typeof IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION>>;
  readonly agentIdentity: ReturnType<typeof createEgressAgentIdentity>;
  readonly serverIdentity: ServerSigningIdentity;
  readonly serverCredentials: ServerSigningCredentials;
} {
  const edgeKeys = generateKeyPairSync("ed25519");
  const agentKeys = generateKeyPairSync("ed25519");
  const serverKeys = generateKeyPairSync("ed25519");
  const edgePrivateKey = createIdentityPrivateKey(
    { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-auth-key-1" },
    edgeKeys.privateKey
  );
  const edgeIdentity = createEdgeDeviceIdentity({
    edgeUserId: "edge-user-1",
    edgeDeviceId: "edge-device-1",
    authenticationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-auth-key-1" },
      edgeKeys.publicKey
    )
  });
  const agentIdentity = createEgressAgentIdentity({
    agentId: "company-agent-1",
    authenticationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION, keyId: "agent-auth-key-1" },
      agentKeys.publicKey
    )
  });
  const serverIdentity = createServerSigningIdentity({
    serverId: "public-server-1",
    capabilityVerificationKey: createIdentityPublicKey(
      { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: "server-capability-key-1" },
      serverKeys.publicKey
    )
  });
  const serverCredentials = createServerSigningCredentials({
    identity: serverIdentity,
    capabilitySigningKey: createIdentityPrivateKey(
      { role: IdentityKeyRole.SERVER_CAPABILITY_SIGNING, keyId: "server-capability-key-1" },
      serverKeys.privateKey
    )
  });

  return { edgeIdentity, edgePrivateKey, agentIdentity, serverIdentity, serverCredentials };
}

function edgeRegistration(): {
  readonly role: "edge-client";
  readonly peerId: string;
  readonly nonce: Uint8Array;
} {
  return {
    role: "edge-client",
    peerId: "edge-device-1",
    nonce: deterministicBytes(1)(32)
  };
}

function binding(streamId = createStreamId()): CapabilityBinding {
  return {
    edgeUserId: "edge-user-1",
    edgeDeviceId: "edge-device-1",
    agentId: "company-agent-1",
    streamId,
    destination: DEFAULT_ALLOWED_DESTINATION
  };
}

describe("identity material and authentication", () => {
  it("loads role-specific public keys without exposing loader failures", () => {
    const keys = generateKeyPairSync("ed25519");
    const reference = { role: IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION, keyId: "edge-auth-key-1" } as const;
    const loaded = loadIdentityPublicKey(
      {
        loadPublicKey: () => keys.publicKey,
        loadPrivateKey: () => keys.privateKey
      },
      reference
    );

    expect(loaded.role).toBe(IdentityKeyRole.EDGE_DEVICE_AUTHENTICATION);
    expect(loaded.keyId).toBe("edge-auth-key-1");

    const privateMarker = "private-material-must-not-escape";
    try {
      loadIdentityPublicKey(
        {
          loadPublicKey: () => {
            throw new Error(privateMarker);
          },
          loadPrivateKey: () => keys.privateKey
        },
        reference
      );
      throw new Error("expected key loading to fail");
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(IdentityError);
      expect((error as Error).message).not.toContain(privateMarker);
    }
  });

  it("issues, signs, verifies, and consumes a one-time challenge", () => {
    const { edgeIdentity, edgePrivateKey } = createFixture();
    const registration = edgeRegistration();
    const challenge = issueAuthenticationChallenge({ nowMs: NOW_MS, ttlMs: 5_000, randomBytes: deterministicBytes(10) });
    const response = signAuthenticationChallenge({
      identity: edgeIdentity,
      signingKey: edgePrivateKey,
      registration,
      challenge
    });
    const replayProtector = new NonceReplayProtector();
    const input = { identity: edgeIdentity, registration, challenge, response, replayProtector, nowMs: NOW_MS + 1 };

    expect(verifyAuthenticationChallenge(input)).toEqual({ ok: true });
    expect(verifyAuthenticationChallenge(input)).toEqual({ ok: false, errorCode: TunnelErrorCode.AUTH_REPLAYED });
  });

  it("rejects tampered, expired, and mismatched authentication responses", () => {
    const { edgeIdentity, edgePrivateKey } = createFixture();
    const registration = edgeRegistration();
    const challenge = issueAuthenticationChallenge({ nowMs: NOW_MS, ttlMs: 100, randomBytes: deterministicBytes(20) });
    const response = signAuthenticationChallenge({
      identity: edgeIdentity,
      signingKey: edgePrivateKey,
      registration,
      challenge
    });
    const tampered = { ...response, signature: Uint8Array.from(response.signature) };
    tampered.signature[0] = (tampered.signature[0] ?? 0) ^ 1;
    const replayProtector = new NonceReplayProtector();

    expect(
      verifyAuthenticationChallenge({
        identity: edgeIdentity,
        registration,
        challenge,
        response: tampered,
        replayProtector,
        nowMs: NOW_MS + 1
      })
    ).toEqual({ ok: false, errorCode: TunnelErrorCode.AUTH_FAILED });
    expect(
      verifyAuthenticationChallenge({
        identity: edgeIdentity,
        registration,
        challenge,
        response,
        replayProtector,
        nowMs: NOW_MS + 1
      })
    ).toEqual({ ok: true });
    expect(
      verifyAuthenticationChallenge({
        identity: edgeIdentity,
        registration,
        challenge,
        response,
        replayProtector,
        nowMs: NOW_MS + 1
      })
    ).toEqual({ ok: false, errorCode: TunnelErrorCode.AUTH_REPLAYED });
    expect(
      verifyAuthenticationChallenge({
        identity: edgeIdentity,
        registration: { ...registration, peerId: "other-device" },
        challenge,
        response,
        replayProtector: new NonceReplayProtector(),
        nowMs: NOW_MS + 1
      })
    ).toEqual({ ok: false, errorCode: TunnelErrorCode.AUTH_FAILED });
    expect(
      verifyAuthenticationChallenge({
        identity: edgeIdentity,
        registration,
        challenge,
        response,
        replayProtector: new NonceReplayProtector(),
        nowMs: NOW_MS + 100
      })
    ).toEqual({ ok: false, errorCode: TunnelErrorCode.AUTH_EXPIRED });
  });

  it("prevents server and peer keys from being used across roles", () => {
    const { edgeIdentity, agentIdentity, edgePrivateKey, serverIdentity } = createFixture();
    const registration = edgeRegistration();
    const challenge = issueAuthenticationChallenge({ nowMs: NOW_MS, randomBytes: deterministicBytes(30) });

    expectIdentityError(
      () =>
        signAuthenticationChallenge({
          identity: agentIdentity,
          signingKey: edgePrivateKey,
          registration,
          challenge
        }),
      "IDENTITY_KEY_ROLE_MISMATCH"
    );
    expectIdentityError(
      () =>
        createServerSigningCredentials({
          identity: serverIdentity,
          capabilitySigningKey: edgePrivateKey as never
        }),
      "IDENTITY_KEY_ROLE_MISMATCH"
    );
    expect(edgeIdentity.authenticationKey.role).not.toBe(serverIdentity.capabilityVerificationKey.role);
  });
});

describe("short-lived stream capability", () => {
  it("creates a compact binary capability and accepts its exact binding once", () => {
    const { serverCredentials, serverIdentity } = createFixture();
    const expectedBinding = binding();
    const capability = issueCapability({
      credentials: serverCredentials,
      binding: expectedBinding,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      nowMs: NOW_MS,
      ttlMs: 5_000,
      randomBytes: deterministicBytes(40)
    });
    const replayProtector = new CapabilityReplayProtector();
    const input = {
      capability,
      serverIdentity,
      expectedBinding,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      replayProtector,
      nowMs: NOW_MS + 1
    };

    expect(capability.byteLength).toBeLessThan(1_024);
    expect(verifyCapability(input)).toMatchObject({ ok: true, capability: { binding: expectedBinding } });
    expect(verifyCapability(input)).toEqual({ ok: false, errorCode: TunnelErrorCode.CAPABILITY_INVALID });
  });

  it("rejects signature tampering, expiration, and capability issued in the future", () => {
    const { serverCredentials, serverIdentity } = createFixture();
    const expectedBinding = binding();
    const capability = issueCapability({
      credentials: serverCredentials,
      binding: expectedBinding,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      nowMs: NOW_MS,
      ttlMs: 100,
      randomBytes: deterministicBytes(50)
    });
    const tampered = Uint8Array.from(capability);
    tampered[tampered.byteLength - 1] = (tampered[tampered.byteLength - 1] ?? 0) ^ 1;
    const baseInput = {
      serverIdentity,
      expectedBinding,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION
    };

    expect(
      verifyCapability({ ...baseInput, capability: tampered, replayProtector: new CapabilityReplayProtector(), nowMs: NOW_MS + 1 })
    ).toEqual({ ok: false, errorCode: TunnelErrorCode.CAPABILITY_INVALID });
    expect(
      verifyCapability({ ...baseInput, capability, replayProtector: new CapabilityReplayProtector(), nowMs: NOW_MS + 100 })
    ).toEqual({ ok: false, errorCode: TunnelErrorCode.CAPABILITY_INVALID });

    const futureCapability = issueCapability({
      credentials: serverCredentials,
      binding: expectedBinding,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      nowMs: NOW_MS + 1,
      ttlMs: 100,
      randomBytes: deterministicBytes(60)
    });
    expect(
      verifyCapability({
        ...baseInput,
        capability: futureCapability,
        replayProtector: new CapabilityReplayProtector(),
        nowMs: NOW_MS
      })
    ).toEqual({ ok: false, errorCode: TunnelErrorCode.CAPABILITY_INVALID });
  });

  it("rejects every mismatched identity and stream binding without revealing why", () => {
    const { serverCredentials, serverIdentity } = createFixture();
    const expectedBinding = binding();
    const capability = issueCapability({
      credentials: serverCredentials,
      binding: expectedBinding,
      allowedDestination: DEFAULT_ALLOWED_DESTINATION,
      nowMs: NOW_MS,
      ttlMs: 5_000,
      randomBytes: deterministicBytes(70)
    });
    const mismatches: readonly CapabilityBinding[] = [
      { ...expectedBinding, edgeUserId: "other-user" },
      { ...expectedBinding, edgeDeviceId: "other-device" },
      { ...expectedBinding, agentId: "other-agent" },
      { ...expectedBinding, streamId: createStreamId() }
    ];

    for (const expectedBinding of mismatches) {
      expect(
        verifyCapability({
          capability,
          serverIdentity,
          expectedBinding,
          allowedDestination: DEFAULT_ALLOWED_DESTINATION,
          replayProtector: new CapabilityReplayProtector(),
          nowMs: NOW_MS + 1
        })
      ).toEqual({ ok: false, errorCode: TunnelErrorCode.CAPABILITY_INVALID });
    }
  });
});
