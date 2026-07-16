import type { ResourceLimits } from "./config.js";
import {
  decodeFramePayload,
  FrameType,
  ProtocolError,
  StreamCloseCode,
  type StreamCloseCode as StreamCloseCodeValue,
  TunnelErrorCode,
  type TunnelErrorCode as TunnelErrorCodeValue,
  type TunnelFrame
} from "./protocol.js";

export const DEFAULT_INITIAL_RECEIVE_CREDIT_BYTES = 64 * 1024;

export const StreamState = {
  REQUESTED: "requested",
  AUTHORIZED: "authorized",
  CONNECTING: "connecting",
  OPEN: "open",
  CLOSING: "closing",
  CLOSED: "closed",
  REJECTED: "rejected",
  FAILED: "failed"
} as const;

export type StreamState = (typeof StreamState)[keyof typeof StreamState];
export type StreamFrameDirection = "inbound" | "outbound";

export interface StreamLifecycleOptions {
  readonly streamId: Uint8Array;
  readonly sessionId: string;
  readonly limits: ResourceLimits;
  readonly bufferBudget?: StreamBufferBudget;
  readonly now?: () => number;
  readonly initialReceiveCreditBytes?: number;
}

export interface StreamLifecycleResult {
  readonly accepted: boolean;
  readonly state: StreamState;
  readonly shouldPauseProducer: boolean;
  readonly shouldSendClose: boolean;
  readonly pendingReceiveCreditBytes: number;
  readonly closeCode?: StreamCloseCodeValue;
  readonly errorCode?: TunnelErrorCodeValue;
}

export interface StreamCreditGrant {
  readonly bytes: number;
}

const TERMINAL_STATES = new Set<StreamState>([
  StreamState.CLOSED,
  StreamState.REJECTED,
  StreamState.FAILED
]);

function isByteCount(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function assertByteCount(value: number): void {
  if (!isByteCount(value)) {
    throw new TypeError("stream byte count must be a non-negative safe integer");
  }
}

function assertNonEmptyId(value: string, name: string): void {
  if (value.length === 0 || value.length > 256 || value.trim() !== value) {
    throw new TypeError(`${name} must be a trimmed identifier of at most 256 characters`);
  }
}

function streamIdKey(streamId: Uint8Array): string {
  if (streamId.byteLength !== 16) {
    throw new TypeError("streamId must contain 16 bytes");
  }

  let key = "";

  for (const byte of streamId) {
    key += byte.toString(16).padStart(2, "0");
  }

  return key;
}

function equalStreamIds(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }

  let different = 0;

  for (let index = 0; index < left.byteLength; index += 1) {
    different |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }

  return different === 0;
}

function isTerminal(state: StreamState): boolean {
  return TERMINAL_STATES.has(state);
}

function isTunnelErrorCode(value: string): value is TunnelErrorCodeValue {
  return Object.values(TunnelErrorCode).includes(value as TunnelErrorCodeValue);
}

function isStreamCloseCode(value: string): value is StreamCloseCodeValue {
  return Object.values(StreamCloseCode).includes(value as StreamCloseCodeValue);
}

function copyResult(
  accepted: boolean,
  state: StreamState,
  shouldPauseProducer: boolean,
  shouldSendClose: boolean,
  pendingReceiveCreditBytes: number,
  closeCode: StreamCloseCodeValue | undefined,
  errorCode: TunnelErrorCodeValue | undefined
): StreamLifecycleResult {
  return {
    accepted,
    state,
    shouldPauseProducer,
    shouldSendClose,
    pendingReceiveCreditBytes,
    ...(closeCode === undefined ? {} : { closeCode }),
    ...(errorCode === undefined ? {} : { errorCode })
  };
}

/**
 * Tracks buffered bytes across all streams that share one WSS session. Callers
 * must inject the same instance into every lifecycle in that session.
 */
export class StreamBufferBudget {
  private readonly perStreamLimit: number;
  private readonly aggregateLimit: number;
  private readonly bufferedByStream = new Map<string, number>();
  private aggregateBufferedBytes = 0;

  public constructor(limits: Pick<ResourceLimits, "maxBufferedBytesPerStream" | "maxAggregateBufferedBytes">) {
    this.perStreamLimit = limits.maxBufferedBytesPerStream;
    this.aggregateLimit = limits.maxAggregateBufferedBytes;

    assertByteCount(this.perStreamLimit);
    assertByteCount(this.aggregateLimit);

    if (this.perStreamLimit === 0 || this.aggregateLimit === 0 || this.perStreamLimit > this.aggregateLimit) {
      throw new TypeError("stream buffer limits are invalid");
    }
  }

  public get totalBufferedBytes(): number {
    return this.aggregateBufferedBytes;
  }

  public getBufferedBytes(streamKey: string): number {
    assertNonEmptyId(streamKey, "streamKey");
    return this.bufferedByStream.get(streamKey) ?? 0;
  }

  public canReserve(streamKey: string, bytes: number): boolean {
    assertNonEmptyId(streamKey, "streamKey");
    assertByteCount(bytes);
    const streamBufferedBytes = this.bufferedByStream.get(streamKey) ?? 0;

    return (
      bytes <= this.perStreamLimit - streamBufferedBytes &&
      bytes <= this.aggregateLimit - this.aggregateBufferedBytes
    );
  }

  public reserve(streamKey: string, bytes: number): boolean {
    if (!this.canReserve(streamKey, bytes)) {
      return false;
    }

    if (bytes === 0) {
      return true;
    }

    const streamBufferedBytes = this.bufferedByStream.get(streamKey) ?? 0;
    this.bufferedByStream.set(streamKey, streamBufferedBytes + bytes);
    this.aggregateBufferedBytes += bytes;
    return true;
  }

  public release(streamKey: string, bytes: number): void {
    assertNonEmptyId(streamKey, "streamKey");
    assertByteCount(bytes);
    const streamBufferedBytes = this.bufferedByStream.get(streamKey) ?? 0;

    if (bytes > streamBufferedBytes) {
      throw new RangeError("cannot release more buffered bytes than reserved");
    }

    if (bytes === 0) {
      return;
    }

    const remainingBytes = streamBufferedBytes - bytes;

    if (remainingBytes === 0) {
      this.bufferedByStream.delete(streamKey);
    } else {
      this.bufferedByStream.set(streamKey, remainingBytes);
    }

    this.aggregateBufferedBytes -= bytes;
  }

  public releaseAll(streamKey: string): void {
    const bufferedBytes = this.getBufferedBytes(streamKey);

    if (bufferedBytes > 0) {
      this.release(streamKey, bufferedBytes);
    }
  }
}

/**
 * One state machine represents one stream in one WSS session. It intentionally
 * has no rebind operation: a disconnected session terminates its streams.
 */
export class StreamLifecycle {
  private readonly id: Uint8Array;
  private readonly session: string;
  private readonly limits: ResourceLimits;
  private readonly clock: () => number;
  private readonly budget: StreamBufferBudget;
  private readonly budgetKey: string;
  private readonly initialReceiveCredit: number;
  private stateValue: StreamState = StreamState.REQUESTED;
  private readonly createdAtMs: number;
  private lastActivityAtMs: number;
  private receiveCreditBalance = 0;
  private sendCreditBalance = 0;
  private receivedUnacknowledgedBytes = 0;
  private pendingSentBytesValue = 0;
  private initialCreditPendingBytes: number;
  private replenishmentCreditPendingBytes = 0;
  private openFrameSeen = false;
  private localCloseSent = false;
  private peerCloseReceived = false;
  private closeCodeValue: StreamCloseCodeValue | undefined;
  private errorCodeValue: TunnelErrorCodeValue | undefined;

  public constructor(options: StreamLifecycleOptions) {
    this.id = Uint8Array.from(options.streamId);
    this.session = options.sessionId;
    this.limits = options.limits;
    this.clock = options.now ?? Date.now;
    assertNonEmptyId(this.session, "sessionId");
    this.budgetKey = `${this.session}:${streamIdKey(this.id)}`;
    this.budget = options.bufferBudget ?? new StreamBufferBudget(this.limits);
    this.initialReceiveCredit = this.resolveInitialReceiveCredit(options.initialReceiveCreditBytes);
    this.initialCreditPendingBytes = this.initialReceiveCredit;
    this.createdAtMs = this.readNow();
    this.lastActivityAtMs = this.createdAtMs;
  }

  public get streamId(): Uint8Array {
    return Uint8Array.from(this.id);
  }

  public get sessionId(): string {
    return this.session;
  }

  public get state(): StreamState {
    return this.stateValue;
  }

  public get terminal(): boolean {
    return isTerminal(this.stateValue);
  }

  public get closeCode(): StreamCloseCodeValue | undefined {
    return this.closeCodeValue;
  }

  public get errorCode(): TunnelErrorCodeValue | undefined {
    return this.errorCodeValue;
  }

  public get initialReceiveCreditBytes(): number {
    return this.initialReceiveCredit;
  }

  public get availableReceiveCreditBytes(): number {
    return this.receiveCreditBalance;
  }

  public get availableSendCreditBytes(): number {
    return this.sendCreditBalance;
  }

  public get unacknowledgedReceivedBytes(): number {
    return this.receivedUnacknowledgedBytes;
  }

  public get pendingSentBytes(): number {
    return this.pendingSentBytesValue;
  }

  public get bufferedBytes(): number {
    return this.budget.getBufferedBytes(this.budgetKey);
  }

  public get pendingReceiveCreditBytes(): number {
    return this.initialCreditPendingBytes + this.replenishmentCreditPendingBytes;
  }

  public get canReadFromProducer(): boolean {
    return (
      this.stateValue === StreamState.OPEN &&
      this.sendCreditBalance > 0 &&
      this.budget.canReserve(this.budgetKey, 1)
    );
  }

  public isBoundToSession(sessionId: string): boolean {
    return !this.terminal && sessionId === this.session;
  }

  public authorize(nowMs?: number): StreamLifecycleResult {
    if (this.stateValue !== StreamState.REQUESTED || !this.openFrameSeen) {
      return this.protocolViolation();
    }

    this.stateValue = StreamState.AUTHORIZED;
    this.recordActivity(nowMs);
    return this.result(true);
  }

  public beginConnecting(nowMs?: number): StreamLifecycleResult {
    if (this.stateValue !== StreamState.AUTHORIZED) {
      return this.protocolViolation();
    }

    this.stateValue = StreamState.CONNECTING;
    this.recordActivity(nowMs);
    return this.result(true);
  }

  public markOpened(nowMs?: number): StreamLifecycleResult {
    if (this.stateValue !== StreamState.CONNECTING) {
      return this.protocolViolation();
    }

    this.stateValue = StreamState.OPEN;
    this.recordActivity(nowMs);
    return this.result(true);
  }

  public reject(errorCode: TunnelErrorCodeValue = TunnelErrorCode.DESTINATION_REJECTED, nowMs?: number): StreamLifecycleResult {
    if (
      this.stateValue !== StreamState.REQUESTED &&
      this.stateValue !== StreamState.AUTHORIZED &&
      this.stateValue !== StreamState.CONNECTING
    ) {
      return this.protocolViolation();
    }

    this.stateValue = StreamState.REJECTED;
    this.errorCodeValue = errorCode;
    this.releaseBufferedBytes();
    this.recordActivity(nowMs);
    return this.result(true);
  }

  public fail(errorCode: TunnelErrorCodeValue = TunnelErrorCode.CONNECT_FAILED, nowMs?: number): StreamLifecycleResult {
    if (isTerminal(this.stateValue)) {
      return this.result(false);
    }

    this.stateValue = StreamState.FAILED;
    this.errorCodeValue = errorCode;
    this.closeCodeValue ??= this.closeCodeForError(errorCode);
    this.releaseBufferedBytes();
    this.recordActivity(nowMs);
    return this.result(true);
  }

  public requestClose(code: StreamCloseCodeValue = StreamCloseCode.NORMAL, nowMs?: number): StreamLifecycleResult {
    if (isTerminal(this.stateValue)) {
      return this.result(false);
    }

    this.closeCodeValue ??= code;
    this.stateValue = StreamState.CLOSING;
    this.recordActivity(nowMs);
    return this.result(true);
  }

  public completeClose(nowMs?: number): StreamLifecycleResult {
    if (this.stateValue !== StreamState.CLOSING) {
      return this.result(false);
    }

    this.stateValue = StreamState.CLOSED;
    this.releaseBufferedBytes();
    this.recordActivity(nowMs);
    return this.result(true);
  }

  public onSessionDisconnected(sessionId: string, nowMs?: number): StreamLifecycleResult {
    if (sessionId !== this.session || isTerminal(this.stateValue)) {
      return this.result(false);
    }

    this.stateValue = StreamState.CLOSED;
    this.closeCodeValue = StreamCloseCode.PEER_DISCONNECTED;
    this.errorCodeValue = TunnelErrorCode.PEER_DISCONNECTED;
    this.releaseBufferedBytes();
    this.recordActivity(nowMs);
    return this.result(true);
  }

  public queueReceiveCredit(bytes: number, nowMs?: number): StreamLifecycleResult & StreamCreditGrant {
    assertByteCount(bytes);

    if (
      this.stateValue !== StreamState.OPEN ||
      bytes === 0 ||
      bytes > this.receivedUnacknowledgedBytes - this.replenishmentCreditPendingBytes
    ) {
      return { ...this.protocolViolation(), bytes: 0 };
    }

    this.replenishmentCreditPendingBytes += bytes;
    this.recordActivity(nowMs);
    return { ...this.result(true), bytes };
  }

  public tick(nowMs?: number): StreamLifecycleResult {
    const now = this.readNow(nowMs);

    if (
      (this.stateValue === StreamState.REQUESTED ||
        this.stateValue === StreamState.AUTHORIZED ||
        this.stateValue === StreamState.CONNECTING) &&
      now - this.createdAtMs >= this.limits.openTimeoutMs
    ) {
      return this.fail(TunnelErrorCode.OPEN_TIMEOUT, now);
    }

    if (this.stateValue === StreamState.OPEN && now - this.lastActivityAtMs >= this.limits.maxIdleMs) {
      return this.requestClose(StreamCloseCode.IDLE_TIMEOUT, now);
    }

    return this.result(false);
  }

  public handleInbound(frame: TunnelFrame, sessionId: string, nowMs?: number): StreamLifecycleResult {
    return this.handleFrame("inbound", frame, sessionId, nowMs);
  }

  public handleOutbound(frame: TunnelFrame, sessionId: string, nowMs?: number): StreamLifecycleResult {
    return this.handleFrame("outbound", frame, sessionId, nowMs);
  }

  private handleFrame(
    direction: StreamFrameDirection,
    frame: TunnelFrame,
    sessionId: string,
    nowMs?: number
  ): StreamLifecycleResult {
    if (sessionId !== this.session || !equalStreamIds(frame.streamId, this.id)) {
      return this.protocolViolation();
    }

    if (isTerminal(this.stateValue)) {
      return this.result(false);
    }

    if (frame.payload.byteLength > this.limits.maxFramePayloadBytes) {
      return this.flowControlViolation();
    }

    let payload: ReturnType<typeof decodeFramePayload>;

    try {
      payload = decodeFramePayload(frame);
    } catch (error: unknown) {
      if (error instanceof ProtocolError) {
        return this.protocolViolation();
      }

      throw error;
    }

    switch (frame.type) {
      case FrameType.STREAM_OPEN:
        return this.handleOpen(direction, nowMs);
      case FrameType.STREAM_OPENED:
        return this.handleOpened(nowMs);
      case FrameType.STREAM_REJECTED:
        return this.handleRejected(payload, nowMs);
      case FrameType.STREAM_ERROR:
        return this.handleError(payload, nowMs);
      case FrameType.STREAM_DATA:
        return this.handleData(direction, payload, nowMs);
      case FrameType.STREAM_CREDIT:
        return this.handleCredit(direction, payload, nowMs);
      case FrameType.STREAM_CLOSE:
        return this.handleClose(direction, payload, nowMs);
      default:
        return this.protocolViolation();
    }
  }

  private handleOpen(direction: StreamFrameDirection, nowMs?: number): StreamLifecycleResult {
    if (this.stateValue !== StreamState.REQUESTED || this.openFrameSeen) {
      return this.protocolViolation();
    }

    // The authorization transition is explicit so the server can verify a capability first.
    void direction;
    this.openFrameSeen = true;
    this.recordActivity(nowMs);
    return this.result(true);
  }

  private handleOpened(nowMs?: number): StreamLifecycleResult {
    if (this.stateValue !== StreamState.CONNECTING) {
      return this.protocolViolation();
    }

    return this.markOpened(nowMs);
  }

  private handleRejected(
    payload: ReturnType<typeof decodeFramePayload>,
    nowMs?: number
  ): StreamLifecycleResult {
    if (
      this.stateValue !== StreamState.REQUESTED &&
      this.stateValue !== StreamState.AUTHORIZED &&
      this.stateValue !== StreamState.CONNECTING
    ) {
      return this.protocolViolation();
    }

    if (
      payload === undefined ||
      payload instanceof Uint8Array ||
      !("code" in payload) ||
      !isTunnelErrorCode(payload.code)
    ) {
      return this.protocolViolation();
    }

    return this.reject(payload.code, nowMs);
  }

  private handleError(payload: ReturnType<typeof decodeFramePayload>, nowMs?: number): StreamLifecycleResult {
    if (this.stateValue !== StreamState.CONNECTING && this.stateValue !== StreamState.OPEN) {
      return this.protocolViolation();
    }

    if (
      payload === undefined ||
      payload instanceof Uint8Array ||
      !("code" in payload) ||
      !isTunnelErrorCode(payload.code)
    ) {
      return this.protocolViolation();
    }

    return this.fail(payload.code, nowMs);
  }

  private handleData(
    direction: StreamFrameDirection,
    payload: ReturnType<typeof decodeFramePayload>,
    nowMs?: number
  ): StreamLifecycleResult {
    if (this.stateValue !== StreamState.OPEN || !(payload instanceof Uint8Array) || payload.byteLength === 0) {
      return this.protocolViolation();
    }

    if (direction === "inbound") {
      if (payload.byteLength > this.receiveCreditBalance || !this.reserveBufferedBytes(payload.byteLength)) {
        return this.flowControlViolation();
      }

      this.receiveCreditBalance -= payload.byteLength;
      this.receivedUnacknowledgedBytes += payload.byteLength;
    } else {
      if (payload.byteLength > this.sendCreditBalance || !this.reserveBufferedBytes(payload.byteLength)) {
        return this.flowControlViolation();
      }

      this.sendCreditBalance -= payload.byteLength;
      this.pendingSentBytesValue += payload.byteLength;
    }

    this.recordActivity(nowMs);
    return this.result(true);
  }

  private handleCredit(
    direction: StreamFrameDirection,
    payload: ReturnType<typeof decodeFramePayload>,
    nowMs?: number
  ): StreamLifecycleResult {
    if (this.stateValue !== StreamState.OPEN || payload === undefined || payload instanceof Uint8Array || !("bytes" in payload)) {
      return this.protocolViolation();
    }

    if (direction === "inbound") {
      const releasedBytes = Math.min(payload.bytes, this.pendingSentBytesValue);
      const nextSendCreditBalance = this.sendCreditBalance + payload.bytes;
      const nextPendingSentBytes = this.pendingSentBytesValue - releasedBytes;

      if (nextSendCreditBalance + nextPendingSentBytes > this.initialReceiveCredit) {
        return this.flowControlViolation();
      }

      this.sendCreditBalance = nextSendCreditBalance;
      this.pendingSentBytesValue = nextPendingSentBytes;
      this.releaseBufferedBytes(releasedBytes);
    } else {
      if (payload.bytes > this.pendingReceiveCreditBytes) {
        return this.protocolViolation();
      }

      const initialBytes = Math.min(payload.bytes, this.initialCreditPendingBytes);
      const replenishmentBytes = payload.bytes - initialBytes;

      if (this.receiveCreditBalance + payload.bytes > this.initialReceiveCredit) {
        return this.flowControlViolation();
      }

      this.initialCreditPendingBytes -= initialBytes;
      this.replenishmentCreditPendingBytes -= replenishmentBytes;
      this.receiveCreditBalance += payload.bytes;
      this.receivedUnacknowledgedBytes -= replenishmentBytes;
      this.releaseBufferedBytes(replenishmentBytes);
    }

    this.recordActivity(nowMs);
    return this.result(true);
  }

  private handleClose(
    direction: StreamFrameDirection,
    payload: ReturnType<typeof decodeFramePayload>,
    nowMs?: number
  ): StreamLifecycleResult {
    if (
      payload === undefined ||
      payload instanceof Uint8Array ||
      !("code" in payload) ||
      !isStreamCloseCode(payload.code)
    ) {
      return this.protocolViolation();
    }

    if (direction === "outbound" && this.closeCodeValue !== undefined && payload.code !== this.closeCodeValue) {
      return this.protocolViolation();
    }

    this.closeCodeValue ??= payload.code;

    if (direction === "inbound") {
      this.peerCloseReceived = true;
      this.stateValue = this.localCloseSent ? StreamState.CLOSED : StreamState.CLOSING;

      if (this.stateValue === StreamState.CLOSED) {
        this.releaseBufferedBytes();
      }
    } else {
      this.localCloseSent = true;
      this.stateValue = this.peerCloseReceived ? StreamState.CLOSED : StreamState.CLOSING;

      if (this.stateValue === StreamState.CLOSED) {
        this.releaseBufferedBytes();
      }
    }

    this.recordActivity(nowMs);
    return this.result(true);
  }

  private protocolViolation(): StreamLifecycleResult {
    if (isTerminal(this.stateValue)) {
      return this.result(false);
    }

    this.errorCodeValue ??= TunnelErrorCode.PROTOCOL_VIOLATION;
    this.closeCodeValue ??= StreamCloseCode.PROTOCOL_ERROR;
    this.stateValue = StreamState.CLOSING;
    return this.result(false);
  }

  private flowControlViolation(): StreamLifecycleResult {
    if (isTerminal(this.stateValue)) {
      return this.result(false);
    }

    this.errorCodeValue ??= TunnelErrorCode.FLOW_CONTROL_VIOLATION;
    this.closeCodeValue ??= StreamCloseCode.RESOURCE_LIMIT;
    this.stateValue = StreamState.CLOSING;
    return this.result(false);
  }

  private result(accepted: boolean): StreamLifecycleResult {
    return copyResult(
      accepted,
      this.stateValue,
      !this.canReadFromProducer,
      this.stateValue === StreamState.CLOSING && !this.localCloseSent,
      this.pendingReceiveCreditBytes,
      this.closeCodeValue,
      this.errorCodeValue
    );
  }

  private recordActivity(nowMs?: number): void {
    this.lastActivityAtMs = this.readNow(nowMs);
  }

  private readNow(providedNowMs?: number): number {
    const now = providedNowMs ?? this.clock();

    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError("clock must return a non-negative safe integer millisecond timestamp");
    }

    return now;
  }

  private resolveInitialReceiveCredit(providedCredit: number | undefined): number {
    const maximumSafeCredit = Math.min(
      DEFAULT_INITIAL_RECEIVE_CREDIT_BYTES,
      this.limits.maxBufferedBytesPerStream,
      Math.floor(this.limits.maxAggregateBufferedBytes / this.limits.maxConcurrentStreams)
    );
    const credit = providedCredit ?? maximumSafeCredit;

    if (!Number.isSafeInteger(credit) || credit <= 0 || credit > maximumSafeCredit) {
      throw new RangeError("initial receive credit exceeds the configured buffer window");
    }

    return credit;
  }

  private reserveBufferedBytes(bytes: number): boolean {
    return this.budget.reserve(this.budgetKey, bytes);
  }

  private releaseBufferedBytes(bytes?: number): void {
    if (bytes === undefined) {
      this.budget.releaseAll(this.budgetKey);
      this.receivedUnacknowledgedBytes = 0;
      this.pendingSentBytesValue = 0;
      this.initialCreditPendingBytes = 0;
      this.replenishmentCreditPendingBytes = 0;
      this.receiveCreditBalance = 0;
      this.sendCreditBalance = 0;
      return;
    }

    if (bytes > 0) {
      this.budget.release(this.budgetKey, bytes);
    }
  }

  private closeCodeForError(errorCode: TunnelErrorCodeValue): StreamCloseCodeValue {
    switch (errorCode) {
      case TunnelErrorCode.OPEN_TIMEOUT:
        return StreamCloseCode.OPEN_TIMEOUT;
      case TunnelErrorCode.IDLE_TIMEOUT:
        return StreamCloseCode.IDLE_TIMEOUT;
      case TunnelErrorCode.PEER_DISCONNECTED:
        return StreamCloseCode.PEER_DISCONNECTED;
      case TunnelErrorCode.DESTINATION_REJECTED:
        return StreamCloseCode.DESTINATION_REJECTED;
      case TunnelErrorCode.CONNECT_FAILED:
        return StreamCloseCode.CONNECT_FAILED;
      case TunnelErrorCode.FLOW_CONTROL_VIOLATION:
        return StreamCloseCode.RESOURCE_LIMIT;
      default:
        return StreamCloseCode.PROTOCOL_ERROR;
    }
  }
}
