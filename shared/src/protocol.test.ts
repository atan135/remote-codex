import { describe, expect, it } from "vitest";

import { PROTOCOL_VERSION } from "./config.js";
import {
  connectionFrame,
  createStreamId,
  decodeFrame,
  decodeFramePayload,
  encodeAuthenticatePayload,
  encodeChallengePayload,
  encodeFrame,
  encodeHeartbeatPayload,
  encodeRegisterPayload,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
  encodeStreamErrorPayload,
  encodeStreamOpenPayload,
  FRAME_HEADER_BYTES,
  FrameType,
  MAX_CONTROL_PAYLOAD_BYTES,
  MAX_DATA_PAYLOAD_BYTES,
  MAX_FRAME_BYTES,
  ProtocolError,
  ProtocolErrorCode,
  streamFrame,
  StreamCloseCode,
  TunnelErrorCode
} from "./protocol.js";

function expectProtocolError(action: () => unknown, code: ProtocolErrorCode): void {
  try {
    action();
    throw new Error("expected protocol operation to fail");
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(ProtocolError);
    expect((error as ProtocolError).code).toBe(code);
  }
}

function nonce(seed = 1): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => (seed + index) % 256);
}

function frameSamples(): readonly ReturnType<typeof connectionFrame | typeof streamFrame>[] {
  const streamId = createStreamId();
  return [
    connectionFrame(
      FrameType.REGISTER,
      encodeRegisterPayload({ role: "edge-client", peerId: "edge-user-1", nonce: nonce() })
    ),
    connectionFrame(
      FrameType.CHALLENGE,
      encodeChallengePayload({ nonce: nonce(2), expiresAtMs: 1_784_562_400_000 })
    ),
    connectionFrame(
      FrameType.AUTHENTICATE,
      encodeAuthenticatePayload({ challengeNonce: nonce(3), signature: Uint8Array.of(1, 2, 3) })
    ),
    connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: 42 })),
    streamFrame(
      FrameType.STREAM_OPEN,
      streamId,
      encodeStreamOpenPayload({
        hostname: "ai-coding-bj-pub.singularity-ai.com",
        port: 443,
        capability: Uint8Array.of(7, 8, 9)
      })
    ),
    streamFrame(FrameType.STREAM_OPENED, streamId, new Uint8Array()),
    streamFrame(
      FrameType.STREAM_REJECTED,
      streamId,
      encodeStreamErrorPayload({ code: TunnelErrorCode.DESTINATION_REJECTED })
    ),
    streamFrame(
      FrameType.STREAM_ERROR,
      streamId,
      encodeStreamErrorPayload({ code: TunnelErrorCode.FLOW_CONTROL_VIOLATION })
    ),
    streamFrame(FrameType.STREAM_DATA, streamId, Uint8Array.of(3, 4, 5)),
    streamFrame(FrameType.STREAM_CREDIT, streamId, encodeStreamCreditPayload({ bytes: 16_384 })),
    streamFrame(
      FrameType.STREAM_CLOSE,
      streamId,
      encodeStreamClosePayload({ code: StreamCloseCode.PEER_DISCONNECTED })
    )
  ];
}

describe("binary tunnel frames", () => {
  it("round-trips every supported frame schema", () => {
    for (const frame of frameSamples()) {
      const decoded = decodeFrame(encodeFrame(frame));
      expect(decoded).toEqual(frame);
      expect(decodeFramePayload(decoded)).toEqual(decodeFramePayload(frame));
    }
  });

  it("uses one fixed 24-byte envelope header", () => {
    const streamId = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
    const frame = streamFrame(FrameType.STREAM_DATA, streamId, Uint8Array.of(7, 8));
    const encoded = encodeFrame(frame);

    expect(FRAME_HEADER_BYTES).toBe(24);
    expect(encoded.byteLength).toBe(FRAME_HEADER_BYTES + 2);
    expect(encoded[0]).toBe(PROTOCOL_VERSION);
    expect(encoded[1]).toBe(FrameType.STREAM_DATA);
    expect(encoded.subarray(4, 20)).toEqual(streamId);
    expect(new DataView(encoded.buffer).getUint32(20)).toBe(2);
  });

  it("rejects malformed headers, versions, types, flags, and lengths", () => {
    const encoded = encodeFrame(streamFrame(FrameType.STREAM_DATA, createStreamId(), Uint8Array.of(1)));
    const version = Uint8Array.from(encoded);
    const type = Uint8Array.from(encoded);
    const flags = Uint8Array.from(encoded);
    const length = Uint8Array.from(encoded);
    version[0] = PROTOCOL_VERSION + 1;
    type[1] = 255;
    flags[3] = 1;
    new DataView(length.buffer).setUint32(20, 2);

    expectProtocolError(() => decodeFrame(Uint8Array.of(1)), ProtocolErrorCode.FRAME_TRUNCATED);
    expectProtocolError(() => decodeFrame(version), ProtocolErrorCode.VERSION_UNSUPPORTED);
    expectProtocolError(() => decodeFrame(type), ProtocolErrorCode.UNKNOWN_FRAME_TYPE);
    expectProtocolError(() => decodeFrame(flags), ProtocolErrorCode.UNSUPPORTED_FLAGS);
    expectProtocolError(() => decodeFrame(length), ProtocolErrorCode.LENGTH_MISMATCH);
  });

  it("enforces stream ownership, frame-specific payloads, and bounded payloads", () => {
    expectProtocolError(
      () => connectionFrame(FrameType.STREAM_DATA, Uint8Array.of(1)),
      ProtocolErrorCode.EXPECTED_CONNECTION_FRAME
    );
    expectProtocolError(
      () => streamFrame(FrameType.STREAM_DATA, new Uint8Array(16), Uint8Array.of(1)),
      ProtocolErrorCode.STREAM_FRAME_WITHOUT_STREAM_ID
    );
    expectProtocolError(
      () => streamFrame(FrameType.STREAM_OPENED, createStreamId(), Uint8Array.of(1)),
      ProtocolErrorCode.MALFORMED_PAYLOAD
    );
    expectProtocolError(
      () => streamFrame(FrameType.STREAM_DATA, createStreamId(), new Uint8Array(MAX_DATA_PAYLOAD_BYTES + 1)),
      ProtocolErrorCode.PAYLOAD_TOO_LARGE
    );
    expectProtocolError(
      () => connectionFrame(FrameType.HEARTBEAT, new Uint8Array(MAX_CONTROL_PAYLOAD_BYTES + 1)),
      ProtocolErrorCode.PAYLOAD_TOO_LARGE
    );
  });

  it("accepts exact data and control size boundaries", () => {
    const data = streamFrame(FrameType.STREAM_DATA, createStreamId(), new Uint8Array(MAX_DATA_PAYLOAD_BYTES));
    const control = streamFrame(
      FrameType.STREAM_OPEN,
      createStreamId(),
      encodeStreamOpenPayload({
        hostname: "a".repeat(253),
        port: 443,
        capability: new Uint8Array(MAX_CONTROL_PAYLOAD_BYTES - 5 - 253)
      })
    );

    expect(decodeFrame(encodeFrame(data))).toEqual(data);
    expect(control.payload.byteLength).toBe(MAX_CONTROL_PAYLOAD_BYTES);
    expect(decodeFrame(encodeFrame(control))).toEqual(control);
    expectProtocolError(() => decodeFrame(new Uint8Array(MAX_FRAME_BYTES + 1)), ProtocolErrorCode.FRAME_TOO_LARGE);
  });

  it("copies input and output bytes so callers cannot mutate a parsed frame", () => {
    const streamId = createStreamId();
    const payload = Uint8Array.of(1, 2, 3);
    const frame = streamFrame(FrameType.STREAM_DATA, streamId, payload);
    streamId.fill(0);
    payload.fill(0);

    expect(frame.streamId).not.toEqual(streamId);
    expect(frame.payload).not.toEqual(payload);

    const encoded = encodeFrame(frame);
    const decoded = decodeFrame(encoded);
    encoded.fill(0);
    expect(decoded).toEqual(frame);
  });

  it("rejects every truncated header and deterministic fuzz samples without runtime parser errors", () => {
    for (let length = 0; length < FRAME_HEADER_BYTES; length += 1) {
      expectProtocolError(() => decodeFrame(new Uint8Array(length)), ProtocolErrorCode.FRAME_TRUNCATED);
    }

    let state = 0x6d2b79f5;
    for (let sample = 0; sample < 512; sample += 1) {
      state = (state * 1_664_525 + 1_013_904_223) >>> 0;
      const bytes = new Uint8Array(state % (MAX_FRAME_BYTES + 1));

      for (let index = 0; index < bytes.byteLength; index += 1) {
        state = (state * 1_664_525 + 1_013_904_223) >>> 0;
        bytes[index] = state & 0xff;
      }

      try {
        decodeFrame(bytes);
      } catch (error: unknown) {
        expect(error).toBeInstanceOf(ProtocolError);
      }
    }
  });
});
