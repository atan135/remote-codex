import { randomBytes } from "node:crypto";

import { PROTOCOL_VERSION } from "./config.js";

export const STREAM_ID_BYTES = 16;
export const FRAME_HEADER_BYTES = 24;
export const MAX_CONTROL_PAYLOAD_BYTES = 4 * 1024;
export const MAX_DATA_PAYLOAD_BYTES = 16 * 1024;
export const MAX_FRAME_BYTES = FRAME_HEADER_BYTES + MAX_DATA_PAYLOAD_BYTES;
export const MAX_PEER_ID_BYTES = 128;
export const MAX_HOSTNAME_BYTES = 253;
export const MIN_NONCE_BYTES = 16;
export const MAX_NONCE_BYTES = 64;
export const MAX_SIGNATURE_BYTES = 512;
export const MAX_CAPABILITY_BYTES = MAX_CONTROL_PAYLOAD_BYTES - 5 - MAX_HOSTNAME_BYTES;

export const FrameType = {
  REGISTER: 1,
  CHALLENGE: 2,
  AUTHENTICATE: 3,
  HEARTBEAT: 4,
  STREAM_OPEN: 16,
  STREAM_OPENED: 17,
  STREAM_REJECTED: 18,
  STREAM_ERROR: 19,
  STREAM_DATA: 20,
  STREAM_CREDIT: 21,
  STREAM_CLOSE: 22
} as const;

export type FrameType = (typeof FrameType)[keyof typeof FrameType];

export const TunnelErrorCode = {
  AUTH_FAILED: "AUTH_FAILED",
  AUTH_EXPIRED: "AUTH_EXPIRED",
  AUTH_REPLAYED: "AUTH_REPLAYED",
  AUTH_UNAUTHORIZED: "AUTH_UNAUTHORIZED",
  CAPABILITY_INVALID: "CAPABILITY_INVALID",
  DESTINATION_REJECTED: "DESTINATION_REJECTED",
  STREAM_LIMIT_EXCEEDED: "STREAM_LIMIT_EXCEEDED",
  CONNECT_FAILED: "CONNECT_FAILED",
  OPEN_TIMEOUT: "OPEN_TIMEOUT",
  IDLE_TIMEOUT: "IDLE_TIMEOUT",
  PEER_DISCONNECTED: "PEER_DISCONNECTED",
  FLOW_CONTROL_VIOLATION: "FLOW_CONTROL_VIOLATION",
  PROTOCOL_VIOLATION: "PROTOCOL_VIOLATION",
  INTERNAL_ERROR: "INTERNAL_ERROR"
} as const;

export type TunnelErrorCode = (typeof TunnelErrorCode)[keyof typeof TunnelErrorCode];

export const StreamCloseCode = {
  NORMAL: "NORMAL",
  PEER_DISCONNECTED: "PEER_DISCONNECTED",
  OPEN_TIMEOUT: "OPEN_TIMEOUT",
  IDLE_TIMEOUT: "IDLE_TIMEOUT",
  PROTOCOL_ERROR: "PROTOCOL_ERROR",
  RESOURCE_LIMIT: "RESOURCE_LIMIT",
  DESTINATION_REJECTED: "DESTINATION_REJECTED",
  CONNECT_FAILED: "CONNECT_FAILED"
} as const;

export type StreamCloseCode = (typeof StreamCloseCode)[keyof typeof StreamCloseCode];

export const ProtocolErrorCode = {
  INVALID_FRAME: "PROTOCOL_INVALID_FRAME",
  INVALID_FLAGS: "PROTOCOL_INVALID_FLAGS",
  UNSUPPORTED_FLAGS: "PROTOCOL_UNSUPPORTED_FLAGS",
  INVALID_STREAM_ID: "PROTOCOL_INVALID_STREAM_ID",
  FRAME_TRUNCATED: "PROTOCOL_FRAME_TRUNCATED",
  FRAME_TOO_LARGE: "PROTOCOL_FRAME_TOO_LARGE",
  VERSION_UNSUPPORTED: "PROTOCOL_VERSION_UNSUPPORTED",
  UNKNOWN_FRAME_TYPE: "PROTOCOL_UNKNOWN_FRAME_TYPE",
  LENGTH_MISMATCH: "PROTOCOL_LENGTH_MISMATCH",
  PAYLOAD_TOO_LARGE: "PROTOCOL_PAYLOAD_TOO_LARGE",
  CONNECTION_FRAME_WITH_STREAM_ID: "PROTOCOL_CONNECTION_FRAME_WITH_STREAM_ID",
  STREAM_FRAME_WITHOUT_STREAM_ID: "PROTOCOL_STREAM_FRAME_WITHOUT_STREAM_ID",
  EXPECTED_CONNECTION_FRAME: "PROTOCOL_EXPECTED_CONNECTION_FRAME",
  EXPECTED_STREAM_FRAME: "PROTOCOL_EXPECTED_STREAM_FRAME",
  MALFORMED_PAYLOAD: "PROTOCOL_MALFORMED_PAYLOAD"
} as const;

export type ProtocolErrorCode = (typeof ProtocolErrorCode)[keyof typeof ProtocolErrorCode];

export type PeerRole = "edge-client" | "egress-agent";

export interface RegisterPayload {
  readonly role: PeerRole;
  readonly peerId: string;
  readonly nonce: Uint8Array;
}

export interface ChallengePayload {
  readonly nonce: Uint8Array;
  readonly expiresAtMs: number;
}

export interface AuthenticatePayload {
  readonly challengeNonce: Uint8Array;
  readonly signature: Uint8Array;
}

export interface HeartbeatPayload {
  readonly sequence: number;
}

export interface StreamOpenPayload {
  readonly hostname: string;
  readonly port: 443;
  readonly capability: Uint8Array;
}

export interface StreamCreditPayload {
  readonly bytes: number;
}

export interface StreamClosePayload {
  readonly code: StreamCloseCode;
}

export interface StreamErrorPayload {
  readonly code: TunnelErrorCode;
}

export interface TunnelFrame {
  readonly type: FrameType;
  readonly flags: number;
  readonly streamId: Uint8Array;
  readonly payload: Uint8Array;
}

export type DecodedFramePayload =
  | RegisterPayload
  | ChallengePayload
  | AuthenticatePayload
  | HeartbeatPayload
  | StreamOpenPayload
  | StreamCreditPayload
  | StreamClosePayload
  | StreamErrorPayload
  | Uint8Array
  | undefined;

export class ProtocolError extends Error {
  public constructor(public readonly code: ProtocolErrorCode) {
    super(code);
    this.name = "ProtocolError";
  }
}

const CONNECTION_FRAME_TYPES = new Set<FrameType>([
  FrameType.REGISTER,
  FrameType.CHALLENGE,
  FrameType.AUTHENTICATE,
  FrameType.HEARTBEAT
]);
const STREAM_FRAME_TYPES = new Set<FrameType>([
  FrameType.STREAM_OPEN,
  FrameType.STREAM_OPENED,
  FrameType.STREAM_REJECTED,
  FrameType.STREAM_ERROR,
  FrameType.STREAM_DATA,
  FrameType.STREAM_CREDIT,
  FrameType.STREAM_CLOSE
]);
const KNOWN_FRAME_TYPES = new Set<FrameType>([
  ...CONNECTION_FRAME_TYPES,
  ...STREAM_FRAME_TYPES
]);
const ZERO_STREAM_ID = new Uint8Array(STREAM_ID_BYTES);
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const UINT32_MAX = 0xffff_ffff;
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

const PEER_ROLE_TO_WIRE: Readonly<Record<PeerRole, number>> = {
  "edge-client": 1,
  "egress-agent": 2
};
const WIRE_TO_PEER_ROLE: Readonly<Record<number, PeerRole | undefined>> = {
  1: "edge-client",
  2: "egress-agent"
};
const TUNNEL_ERROR_TO_WIRE: Readonly<Record<TunnelErrorCode, number>> = {
  AUTH_FAILED: 1,
  AUTH_EXPIRED: 2,
  AUTH_REPLAYED: 3,
  AUTH_UNAUTHORIZED: 4,
  CAPABILITY_INVALID: 5,
  DESTINATION_REJECTED: 6,
  STREAM_LIMIT_EXCEEDED: 7,
  CONNECT_FAILED: 8,
  OPEN_TIMEOUT: 9,
  IDLE_TIMEOUT: 10,
  PEER_DISCONNECTED: 11,
  FLOW_CONTROL_VIOLATION: 12,
  PROTOCOL_VIOLATION: 13,
  INTERNAL_ERROR: 14
};
const WIRE_TO_TUNNEL_ERROR = invertWireCodes(TUNNEL_ERROR_TO_WIRE);
const STREAM_CLOSE_TO_WIRE: Readonly<Record<StreamCloseCode, number>> = {
  NORMAL: 1,
  PEER_DISCONNECTED: 2,
  OPEN_TIMEOUT: 3,
  IDLE_TIMEOUT: 4,
  PROTOCOL_ERROR: 5,
  RESOURCE_LIMIT: 6,
  DESTINATION_REJECTED: 7,
  CONNECT_FAILED: 8
};
const WIRE_TO_STREAM_CLOSE = invertWireCodes(STREAM_CLOSE_TO_WIRE);

function invertWireCodes<T extends string>(codes: Readonly<Record<T, number>>): Readonly<Record<number, T | undefined>> {
  const inverted: Record<number, T | undefined> = {};

  for (const [code, value] of Object.entries(codes) as [T, number][]) {
    inverted[value] = code;
  }

  return inverted;
}

function fail(code: ProtocolErrorCode): never {
  throw new ProtocolError(code);
}

function isKnownFrameType(value: number): value is FrameType {
  return KNOWN_FRAME_TYPES.has(value as FrameType);
}

function isByteArray(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

function isZeroStreamId(streamId: Uint8Array): boolean {
  for (const byte of streamId) {
    if (byte !== 0) {
      return false;
    }
  }

  return true;
}

function payloadLimit(type: FrameType): number {
  return type === FrameType.STREAM_DATA ? MAX_DATA_PAYLOAD_BYTES : MAX_CONTROL_PAYLOAD_BYTES;
}

function validatePayloadBytes(value: unknown, limit: number): asserts value is Uint8Array {
  if (!isByteArray(value)) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  if (value.byteLength > limit) {
    fail(ProtocolErrorCode.PAYLOAD_TOO_LARGE);
  }
}

function validateFrame(frame: TunnelFrame): void {
  if (frame === null || typeof frame !== "object") {
    fail(ProtocolErrorCode.INVALID_FRAME);
  }

  if (!isKnownFrameType(frame.type)) {
    fail(ProtocolErrorCode.UNKNOWN_FRAME_TYPE);
  }

  if (!Number.isSafeInteger(frame.flags) || frame.flags < 0 || frame.flags > 0xffff) {
    fail(ProtocolErrorCode.INVALID_FLAGS);
  }

  if (frame.flags !== 0) {
    fail(ProtocolErrorCode.UNSUPPORTED_FLAGS);
  }

  if (!isByteArray(frame.streamId) || frame.streamId.byteLength !== STREAM_ID_BYTES) {
    fail(ProtocolErrorCode.INVALID_STREAM_ID);
  }

  validatePayloadBytes(frame.payload, payloadLimit(frame.type));

  if (CONNECTION_FRAME_TYPES.has(frame.type) && !isZeroStreamId(frame.streamId)) {
    fail(ProtocolErrorCode.CONNECTION_FRAME_WITH_STREAM_ID);
  }

  if (STREAM_FRAME_TYPES.has(frame.type) && isZeroStreamId(frame.streamId)) {
    fail(ProtocolErrorCode.STREAM_FRAME_WITHOUT_STREAM_ID);
  }

  validatePayloadForType(frame.type, frame.payload);
}

function ensureExactLength(payload: Uint8Array, expectedLength: number): void {
  if (payload.byteLength !== expectedLength) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }
}

function encodeText(value: string, maximumBytes: number): Uint8Array {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value || value.includes("\u0000")) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  if (value.length > maximumBytes) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const encoded = TEXT_ENCODER.encode(value);

  if (encoded.byteLength === 0 || encoded.byteLength > maximumBytes) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  return encoded;
}

function decodeText(payload: Uint8Array, maximumBytes: number): string {
  if (payload.byteLength === 0 || payload.byteLength > maximumBytes) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  let decoded: string;

  try {
    decoded = TEXT_DECODER.decode(payload);
  } catch {
    return fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  if (decoded.length === 0 || decoded.trim() !== decoded || decoded.includes("\u0000")) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  return decoded;
}

function validateNonce(value: unknown): asserts value is Uint8Array {
  validatePayloadBytes(value, MAX_NONCE_BYTES);

  if (value.byteLength < MIN_NONCE_BYTES) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }
}

function validateCapability(value: unknown): asserts value is Uint8Array {
  validatePayloadBytes(value, MAX_CAPABILITY_BYTES);

  if (value.byteLength === 0) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }
}

function validateSignature(value: unknown): asserts value is Uint8Array {
  validatePayloadBytes(value, MAX_SIGNATURE_BYTES);

  if (value.byteLength === 0) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }
}

function validateUint32(value: unknown, allowZero: boolean): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > UINT32_MAX ||
    (!allowZero && value === 0)
  ) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }
}

function validateTimestampMs(value: unknown): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }
}

function readUint16(payload: Uint8Array, offset: number): number {
  return new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint16(offset);
}

function readUint32(payload: Uint8Array, offset: number): number {
  return new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(offset);
}

function readTimestampMs(payload: Uint8Array, offset: number): number {
  const value = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getBigUint64(offset);

  if (value > MAX_SAFE_BIGINT) {
    return fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  return Number(value);
}

function codeFromWire<T extends string>(
  codes: Readonly<Record<number, T | undefined>>,
  wireCode: number
): T {
  const code = codes[wireCode];

  if (code === undefined) {
    return fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  return code;
}

function validatePayloadForType(type: FrameType, payload: Uint8Array): void {
  switch (type) {
    case FrameType.REGISTER:
      decodeRegisterPayload(payload);
      return;
    case FrameType.CHALLENGE:
      decodeChallengePayload(payload);
      return;
    case FrameType.AUTHENTICATE:
      decodeAuthenticatePayload(payload);
      return;
    case FrameType.HEARTBEAT:
      decodeHeartbeatPayload(payload);
      return;
    case FrameType.STREAM_OPEN:
      decodeStreamOpenPayload(payload);
      return;
    case FrameType.STREAM_OPENED:
      ensureExactLength(payload, 0);
      return;
    case FrameType.STREAM_REJECTED:
    case FrameType.STREAM_ERROR:
      decodeStreamErrorPayload(payload);
      return;
    case FrameType.STREAM_DATA:
      return;
    case FrameType.STREAM_CREDIT:
      decodeStreamCreditPayload(payload);
      return;
    case FrameType.STREAM_CLOSE:
      decodeStreamClosePayload(payload);
      return;
  }
}

export function createStreamId(): Uint8Array {
  let streamId: Uint8Array;

  do {
    streamId = Uint8Array.from(randomBytes(STREAM_ID_BYTES));
  } while (isZeroStreamId(streamId));

  return streamId;
}

export function encodeRegisterPayload(payload: RegisterPayload): Uint8Array {
  const peerId = encodeText(payload.peerId, MAX_PEER_ID_BYTES);
  validateNonce(payload.nonce);
  const encoded = new Uint8Array(3 + peerId.byteLength + payload.nonce.byteLength);
  const role = PEER_ROLE_TO_WIRE[payload.role];

  if (role === undefined) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  encoded[0] = role;
  encoded[1] = peerId.byteLength;
  encoded.set(peerId, 2);
  encoded[2 + peerId.byteLength] = payload.nonce.byteLength;
  encoded.set(payload.nonce, 3 + peerId.byteLength);
  return encoded;
}

export function decodeRegisterPayload(payload: Uint8Array): RegisterPayload {
  validatePayloadBytes(payload, MAX_CONTROL_PAYLOAD_BYTES);

  if (payload.byteLength < 3) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const role = WIRE_TO_PEER_ROLE[payload[0] ?? 0];
  const peerIdLength = payload[1] ?? 0;
  const nonceLengthOffset = 2 + peerIdLength;

  if (role === undefined || peerIdLength === 0 || nonceLengthOffset >= payload.byteLength) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const nonceLength = payload[nonceLengthOffset] ?? 0;
  const expectedLength = nonceLengthOffset + 1 + nonceLength;

  if (expectedLength !== payload.byteLength) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const peerId = decodeText(payload.subarray(2, nonceLengthOffset), MAX_PEER_ID_BYTES);
  const nonce = payload.subarray(nonceLengthOffset + 1);
  validateNonce(nonce);
  return { role, peerId, nonce: Uint8Array.from(nonce) };
}

export function encodeChallengePayload(payload: ChallengePayload): Uint8Array {
  validateNonce(payload.nonce);
  validateTimestampMs(payload.expiresAtMs);
  const encoded = new Uint8Array(9 + payload.nonce.byteLength);
  const view = new DataView(encoded.buffer);

  encoded[0] = payload.nonce.byteLength;
  encoded.set(payload.nonce, 1);
  view.setBigUint64(1 + payload.nonce.byteLength, BigInt(payload.expiresAtMs));
  return encoded;
}

export function decodeChallengePayload(payload: Uint8Array): ChallengePayload {
  validatePayloadBytes(payload, MAX_CONTROL_PAYLOAD_BYTES);

  if (payload.byteLength < 9) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const nonceLength = payload[0] ?? 0;

  if (payload.byteLength !== 9 + nonceLength) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const nonce = payload.subarray(1, 1 + nonceLength);
  validateNonce(nonce);
  return { nonce: Uint8Array.from(nonce), expiresAtMs: readTimestampMs(payload, 1 + nonceLength) };
}

export function encodeAuthenticatePayload(payload: AuthenticatePayload): Uint8Array {
  validateNonce(payload.challengeNonce);
  validateSignature(payload.signature);
  const encoded = new Uint8Array(3 + payload.challengeNonce.byteLength + payload.signature.byteLength);

  encoded[0] = payload.challengeNonce.byteLength;
  encoded.set(payload.challengeNonce, 1);
  new DataView(encoded.buffer).setUint16(1 + payload.challengeNonce.byteLength, payload.signature.byteLength);
  encoded.set(payload.signature, 3 + payload.challengeNonce.byteLength);
  return encoded;
}

export function decodeAuthenticatePayload(payload: Uint8Array): AuthenticatePayload {
  validatePayloadBytes(payload, MAX_CONTROL_PAYLOAD_BYTES);

  if (payload.byteLength < 3) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const nonceLength = payload[0] ?? 0;
  const signatureLengthOffset = 1 + nonceLength;

  if (signatureLengthOffset + 2 > payload.byteLength) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const signatureLength = readUint16(payload, signatureLengthOffset);

  if (signatureLengthOffset + 2 + signatureLength !== payload.byteLength) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const challengeNonce = payload.subarray(1, signatureLengthOffset);
  const signature = payload.subarray(signatureLengthOffset + 2);
  validateNonce(challengeNonce);
  validateSignature(signature);
  return {
    challengeNonce: Uint8Array.from(challengeNonce),
    signature: Uint8Array.from(signature)
  };
}

export function encodeHeartbeatPayload(payload: HeartbeatPayload): Uint8Array {
  validateUint32(payload.sequence, true);
  const encoded = new Uint8Array(4);
  new DataView(encoded.buffer).setUint32(0, payload.sequence);
  return encoded;
}

export function decodeHeartbeatPayload(payload: Uint8Array): HeartbeatPayload {
  validatePayloadBytes(payload, MAX_CONTROL_PAYLOAD_BYTES);
  ensureExactLength(payload, 4);
  return { sequence: readUint32(payload, 0) };
}

export function encodeStreamOpenPayload(payload: StreamOpenPayload): Uint8Array {
  const hostname = encodeText(payload.hostname, MAX_HOSTNAME_BYTES);
  validateCapability(payload.capability);

  if (payload.port !== 443) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const encoded = new Uint8Array(5 + hostname.byteLength + payload.capability.byteLength);
  const view = new DataView(encoded.buffer);

  encoded[0] = hostname.byteLength;
  encoded.set(hostname, 1);
  view.setUint16(1 + hostname.byteLength, payload.port);
  view.setUint16(3 + hostname.byteLength, payload.capability.byteLength);
  encoded.set(payload.capability, 5 + hostname.byteLength);
  return encoded;
}

export function decodeStreamOpenPayload(payload: Uint8Array): StreamOpenPayload {
  validatePayloadBytes(payload, MAX_CONTROL_PAYLOAD_BYTES);

  if (payload.byteLength < 5) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const hostnameLength = payload[0] ?? 0;
  const portOffset = 1 + hostnameLength;

  if (portOffset + 4 > payload.byteLength) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const port = readUint16(payload, portOffset);
  const capabilityLength = readUint16(payload, portOffset + 2);

  if (port !== 443 || portOffset + 4 + capabilityLength !== payload.byteLength) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const hostname = decodeText(payload.subarray(1, portOffset), MAX_HOSTNAME_BYTES);
  const capability = payload.subarray(portOffset + 4);
  validateCapability(capability);
  return { hostname, port: 443, capability: Uint8Array.from(capability) };
}

export function encodeStreamErrorPayload(payload: StreamErrorPayload): Uint8Array {
  const wireCode = TUNNEL_ERROR_TO_WIRE[payload.code];

  if (wireCode === undefined) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const encoded = new Uint8Array(2);
  new DataView(encoded.buffer).setUint16(0, wireCode);
  return encoded;
}

export function decodeStreamErrorPayload(payload: Uint8Array): StreamErrorPayload {
  validatePayloadBytes(payload, MAX_CONTROL_PAYLOAD_BYTES);
  ensureExactLength(payload, 2);
  return { code: codeFromWire(WIRE_TO_TUNNEL_ERROR, readUint16(payload, 0)) };
}

export function encodeStreamCreditPayload(payload: StreamCreditPayload): Uint8Array {
  validateUint32(payload.bytes, false);
  const encoded = new Uint8Array(4);
  new DataView(encoded.buffer).setUint32(0, payload.bytes);
  return encoded;
}

export function decodeStreamCreditPayload(payload: Uint8Array): StreamCreditPayload {
  validatePayloadBytes(payload, MAX_CONTROL_PAYLOAD_BYTES);
  ensureExactLength(payload, 4);
  const bytes = readUint32(payload, 0);
  validateUint32(bytes, false);
  return { bytes };
}

export function encodeStreamClosePayload(payload: StreamClosePayload): Uint8Array {
  const wireCode = STREAM_CLOSE_TO_WIRE[payload.code];

  if (wireCode === undefined) {
    fail(ProtocolErrorCode.MALFORMED_PAYLOAD);
  }

  const encoded = new Uint8Array(2);
  new DataView(encoded.buffer).setUint16(0, wireCode);
  return encoded;
}

export function decodeStreamClosePayload(payload: Uint8Array): StreamClosePayload {
  validatePayloadBytes(payload, MAX_CONTROL_PAYLOAD_BYTES);
  ensureExactLength(payload, 2);
  return { code: codeFromWire(WIRE_TO_STREAM_CLOSE, readUint16(payload, 0)) };
}

export function decodeFramePayload(frame: TunnelFrame): DecodedFramePayload {
  validateFrame(frame);

  switch (frame.type) {
    case FrameType.REGISTER:
      return decodeRegisterPayload(frame.payload);
    case FrameType.CHALLENGE:
      return decodeChallengePayload(frame.payload);
    case FrameType.AUTHENTICATE:
      return decodeAuthenticatePayload(frame.payload);
    case FrameType.HEARTBEAT:
      return decodeHeartbeatPayload(frame.payload);
    case FrameType.STREAM_OPEN:
      return decodeStreamOpenPayload(frame.payload);
    case FrameType.STREAM_OPENED:
      return undefined;
    case FrameType.STREAM_REJECTED:
    case FrameType.STREAM_ERROR:
      return decodeStreamErrorPayload(frame.payload);
    case FrameType.STREAM_DATA:
      return Uint8Array.from(frame.payload);
    case FrameType.STREAM_CREDIT:
      return decodeStreamCreditPayload(frame.payload);
    case FrameType.STREAM_CLOSE:
      return decodeStreamClosePayload(frame.payload);
  }
}

export function encodeFrame(frame: TunnelFrame): Uint8Array {
  validateFrame(frame);
  const encoded = new Uint8Array(FRAME_HEADER_BYTES + frame.payload.byteLength);
  const view = new DataView(encoded.buffer);

  encoded[0] = PROTOCOL_VERSION;
  encoded[1] = frame.type;
  view.setUint16(2, frame.flags);
  encoded.set(frame.streamId, 4);
  view.setUint32(20, frame.payload.byteLength);
  encoded.set(frame.payload, FRAME_HEADER_BYTES);
  return encoded;
}

export function decodeFrame(message: Uint8Array): TunnelFrame {
  if (!isByteArray(message)) {
    return fail(ProtocolErrorCode.INVALID_FRAME);
  }

  if (message.byteLength > MAX_FRAME_BYTES) {
    return fail(ProtocolErrorCode.FRAME_TOO_LARGE);
  }

  if (message.byteLength < FRAME_HEADER_BYTES) {
    return fail(ProtocolErrorCode.FRAME_TRUNCATED);
  }

  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);

  if (message[0] !== PROTOCOL_VERSION) {
    return fail(ProtocolErrorCode.VERSION_UNSUPPORTED);
  }

  const typeValue = message[1] ?? 0;

  if (!isKnownFrameType(typeValue)) {
    return fail(ProtocolErrorCode.UNKNOWN_FRAME_TYPE);
  }

  const payloadLength = view.getUint32(20);

  if (payloadLength > payloadLimit(typeValue)) {
    return fail(ProtocolErrorCode.PAYLOAD_TOO_LARGE);
  }

  if (message.byteLength !== FRAME_HEADER_BYTES + payloadLength) {
    return fail(ProtocolErrorCode.LENGTH_MISMATCH);
  }

  const frame: TunnelFrame = {
    type: typeValue,
    flags: view.getUint16(2),
    streamId: message.subarray(4, 4 + STREAM_ID_BYTES),
    payload: message.subarray(FRAME_HEADER_BYTES)
  };
  validateFrame(frame);
  return {
    ...frame,
    streamId: Uint8Array.from(frame.streamId),
    payload: Uint8Array.from(frame.payload)
  };
}

export function connectionFrame(type: FrameType, payload: Uint8Array, flags = 0): TunnelFrame {
  if (!CONNECTION_FRAME_TYPES.has(type)) {
    return fail(ProtocolErrorCode.EXPECTED_CONNECTION_FRAME);
  }

  const frame: TunnelFrame = { type, flags, streamId: ZERO_STREAM_ID, payload };
  validateFrame(frame);
  return {
    ...frame,
    streamId: Uint8Array.from(ZERO_STREAM_ID),
    payload: Uint8Array.from(payload)
  };
}

export function streamFrame(
  type: FrameType,
  streamId: Uint8Array,
  payload: Uint8Array,
  flags = 0
): TunnelFrame {
  if (!STREAM_FRAME_TYPES.has(type)) {
    return fail(ProtocolErrorCode.EXPECTED_STREAM_FRAME);
  }

  const frame: TunnelFrame = { type, flags, streamId, payload };
  validateFrame(frame);
  return {
    ...frame,
    streamId: Uint8Array.from(streamId),
    payload: Uint8Array.from(payload)
  };
}
