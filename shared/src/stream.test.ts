import { describe, expect, it } from "vitest";

import { DEFAULT_RESOURCE_LIMITS, type ResourceLimits } from "./config.js";
import {
  createStreamId,
  encodeStreamClosePayload,
  encodeStreamCreditPayload,
  encodeStreamErrorPayload,
  encodeStreamOpenPayload,
  FrameType,
  streamFrame,
  StreamCloseCode,
  TunnelErrorCode
} from "./protocol.js";
import { StreamBufferBudget, StreamLifecycle, StreamState } from "./stream.js";

const SESSION_ID = "wss-session-1";

function limits(overrides: Partial<ResourceLimits> = {}): ResourceLimits {
  return { ...DEFAULT_RESOURCE_LIMITS, ...overrides };
}

function openPayload(): Uint8Array {
  return encodeStreamOpenPayload({
    hostname: "ai-coding-bj-pub.singularity-ai.com",
    port: 443,
    capability: Uint8Array.of(1)
  });
}

function stream(
  type: FrameType,
  streamId: Uint8Array,
  payload: Uint8Array = new Uint8Array()
): ReturnType<typeof streamFrame> {
  return streamFrame(type, streamId, payload);
}

function createLifecycle(
  options: Partial<{
    streamId: Uint8Array;
    sessionId: string;
    limits: ResourceLimits;
    bufferBudget: StreamBufferBudget;
    now: () => number;
    initialReceiveCreditBytes: number;
  }> = {}
): StreamLifecycle {
  return new StreamLifecycle({
    streamId: options.streamId ?? createStreamId(),
    sessionId: options.sessionId ?? SESSION_ID,
    limits: options.limits ?? limits(),
    ...(options.bufferBudget === undefined ? {} : { bufferBudget: options.bufferBudget }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.initialReceiveCreditBytes === undefined
      ? {}
      : { initialReceiveCreditBytes: options.initialReceiveCreditBytes })
  });
}

function advanceToOpen(lifecycle: StreamLifecycle, nowMs = 0): void {
  expect(lifecycle.handleInbound(stream(FrameType.STREAM_OPEN, lifecycle.streamId, openPayload()), SESSION_ID, nowMs)).toMatchObject({
    accepted: true,
    state: StreamState.REQUESTED
  });
  expect(lifecycle.authorize(nowMs)).toMatchObject({ accepted: true, state: StreamState.AUTHORIZED });
  expect(lifecycle.beginConnecting(nowMs)).toMatchObject({ accepted: true, state: StreamState.CONNECTING });
  expect(lifecycle.handleOutbound(stream(FrameType.STREAM_OPENED, lifecycle.streamId), SESSION_ID, nowMs)).toMatchObject({
    accepted: true,
    state: StreamState.OPEN
  });
}

function grantInitialCredit(lifecycle: StreamLifecycle, bytes: number, nowMs = 0): void {
  expect(
    lifecycle.handleOutbound(
      stream(FrameType.STREAM_CREDIT, lifecycle.streamId, encodeStreamCreditPayload({ bytes })),
      SESSION_ID,
      nowMs
    )
  ).toMatchObject({ accepted: true });
  expect(
    lifecycle.handleInbound(
      stream(FrameType.STREAM_CREDIT, lifecycle.streamId, encodeStreamCreditPayload({ bytes })),
      SESSION_ID,
      nowMs
    )
  ).toMatchObject({ accepted: true });
}

describe("stream lifecycle", () => {
  it("requires each explicit transition before opening and sends initial receive credit", () => {
    const lifecycle = createLifecycle({ initialReceiveCreditBytes: 32 });

    advanceToOpen(lifecycle);

    expect(lifecycle.state).toBe(StreamState.OPEN);
    expect(lifecycle.pendingReceiveCreditBytes).toBe(32);
    expect(lifecycle.availableReceiveCreditBytes).toBe(0);
    expect(lifecycle.canReadFromProducer).toBe(false);
  });

  it("requires exactly one open frame before authorization", () => {
    const premature = createLifecycle();
    expect(premature.authorize()).toMatchObject({ accepted: false, state: StreamState.CLOSING });

    const duplicate = createLifecycle();
    expect(duplicate.handleOutbound(stream(FrameType.STREAM_OPEN, duplicate.streamId, openPayload()), SESSION_ID)).toMatchObject({
      accepted: true,
      state: StreamState.REQUESTED
    });
    expect(duplicate.handleInbound(stream(FrameType.STREAM_OPEN, duplicate.streamId, openPayload()), SESSION_ID)).toMatchObject({
      accepted: false,
      state: StreamState.CLOSING,
      errorCode: TunnelErrorCode.PROTOCOL_VIOLATION
    });
  });

  it("closes only the stream with an illegal transition", () => {
    const invalid = createLifecycle();
    const independent = createLifecycle();
    const result = invalid.handleInbound(
      stream(FrameType.STREAM_DATA, invalid.streamId, Uint8Array.of(1)),
      SESSION_ID
    );

    expect(result).toMatchObject({
      accepted: false,
      state: StreamState.CLOSING,
      shouldSendClose: true,
      closeCode: StreamCloseCode.PROTOCOL_ERROR,
      errorCode: TunnelErrorCode.PROTOCOL_VIOLATION
    });
    expect(independent.state).toBe(StreamState.REQUESTED);
  });

  it("accounts for initial credit, credit replenishment, acknowledgements, and producer pause", () => {
    const lifecycle = createLifecycle({ initialReceiveCreditBytes: 16 });
    advanceToOpen(lifecycle);
    grantInitialCredit(lifecycle, 16);

    expect(lifecycle.availableReceiveCreditBytes).toBe(16);
    expect(lifecycle.availableSendCreditBytes).toBe(16);
    expect(lifecycle.canReadFromProducer).toBe(true);

    expect(lifecycle.handleOutbound(stream(FrameType.STREAM_DATA, lifecycle.streamId, new Uint8Array(16)), SESSION_ID)).toMatchObject({
      accepted: true,
      shouldPauseProducer: true
    });
    expect(lifecycle.pendingSentBytes).toBe(16);
    expect(lifecycle.bufferedBytes).toBe(16);

    expect(
      lifecycle.handleInbound(
        stream(FrameType.STREAM_CREDIT, lifecycle.streamId, encodeStreamCreditPayload({ bytes: 16 })),
        SESSION_ID
      )
    ).toMatchObject({ accepted: true });
    expect(lifecycle.availableSendCreditBytes).toBe(16);
    expect(lifecycle.pendingSentBytes).toBe(0);
    expect(lifecycle.bufferedBytes).toBe(0);

    expect(lifecycle.handleInbound(stream(FrameType.STREAM_DATA, lifecycle.streamId, new Uint8Array(16)), SESSION_ID)).toMatchObject({
      accepted: true
    });
    expect(lifecycle.availableReceiveCreditBytes).toBe(0);
    expect(lifecycle.unacknowledgedReceivedBytes).toBe(16);
    expect(lifecycle.bufferedBytes).toBe(16);

    expect(lifecycle.queueReceiveCredit(16)).toMatchObject({ accepted: true, bytes: 16 });
    expect(
      lifecycle.handleOutbound(
        stream(FrameType.STREAM_CREDIT, lifecycle.streamId, encodeStreamCreditPayload({ bytes: 16 })),
        SESSION_ID
      )
    ).toMatchObject({ accepted: true });
    expect(lifecycle.availableReceiveCreditBytes).toBe(16);
    expect(lifecycle.unacknowledgedReceivedBytes).toBe(0);
    expect(lifecycle.bufferedBytes).toBe(0);
  });

  it("enforces a shared aggregate budget without affecting already valid streams", () => {
    const constrainedLimits = limits({
      maxConcurrentStreams: 2,
      maxBufferedBytesPerStream: 8,
      maxAggregateBufferedBytes: 8
    });
    const budget = new StreamBufferBudget(constrainedLimits);
    const first = createLifecycle({ limits: constrainedLimits, bufferBudget: budget, initialReceiveCreditBytes: 4 });
    const second = createLifecycle({ limits: constrainedLimits, bufferBudget: budget, initialReceiveCreditBytes: 4 });

    advanceToOpen(first);
    advanceToOpen(second);
    grantInitialCredit(first, 4);
    grantInitialCredit(second, 4);

    expect(first.handleOutbound(stream(FrameType.STREAM_DATA, first.streamId, new Uint8Array(4)), SESSION_ID)).toMatchObject({
      accepted: true
    });
    expect(first.handleInbound(stream(FrameType.STREAM_DATA, first.streamId, new Uint8Array(4)), SESSION_ID)).toMatchObject({
      accepted: true
    });
    expect(budget.totalBufferedBytes).toBe(8);

    expect(second.handleOutbound(stream(FrameType.STREAM_DATA, second.streamId, new Uint8Array(1)), SESSION_ID)).toMatchObject({
      accepted: false,
      state: StreamState.CLOSING,
      errorCode: TunnelErrorCode.FLOW_CONTROL_VIOLATION
    });
    expect(first.state).toBe(StreamState.OPEN);
  });

  it("makes close idempotent and terminates a disconnected WSS session without resuming", () => {
    const budget = new StreamBufferBudget(limits());
    const lifecycle = createLifecycle({ bufferBudget: budget, initialReceiveCreditBytes: 8 });
    advanceToOpen(lifecycle);
    grantInitialCredit(lifecycle, 8);
    lifecycle.handleOutbound(stream(FrameType.STREAM_DATA, lifecycle.streamId, new Uint8Array(8)), SESSION_ID);

    expect(lifecycle.requestClose(StreamCloseCode.IDLE_TIMEOUT)).toMatchObject({
      accepted: true,
      shouldSendClose: true,
      closeCode: StreamCloseCode.IDLE_TIMEOUT
    });
    expect(
      lifecycle.handleOutbound(
        stream(
          FrameType.STREAM_CLOSE,
          lifecycle.streamId,
          encodeStreamClosePayload({ code: StreamCloseCode.IDLE_TIMEOUT })
        ),
        SESSION_ID
      )
    ).toMatchObject({ accepted: true, state: StreamState.CLOSING, shouldSendClose: false });
    expect(lifecycle.requestClose(StreamCloseCode.IDLE_TIMEOUT)).toMatchObject({
      accepted: true,
      state: StreamState.CLOSING,
      shouldSendClose: false
    });
    expect(
      lifecycle.handleInbound(
        stream(
          FrameType.STREAM_CLOSE,
          lifecycle.streamId,
          encodeStreamClosePayload({ code: StreamCloseCode.IDLE_TIMEOUT })
        ),
        SESSION_ID
      )
    ).toMatchObject({ accepted: true, state: StreamState.CLOSED });
    expect(
      lifecycle.handleInbound(
        stream(
          FrameType.STREAM_CLOSE,
          lifecycle.streamId,
          encodeStreamClosePayload({ code: StreamCloseCode.IDLE_TIMEOUT })
        ),
        SESSION_ID
      )
    ).toMatchObject({ accepted: false, state: StreamState.CLOSED });
    expect(budget.totalBufferedBytes).toBe(0);

    const disconnected = createLifecycle({ bufferBudget: budget, initialReceiveCreditBytes: 8 });
    advanceToOpen(disconnected);
    grantInitialCredit(disconnected, 8);
    disconnected.handleOutbound(stream(FrameType.STREAM_DATA, disconnected.streamId, new Uint8Array(8)), SESSION_ID);
    expect(disconnected.onSessionDisconnected(SESSION_ID)).toMatchObject({
      accepted: true,
      state: StreamState.CLOSED,
      closeCode: StreamCloseCode.PEER_DISCONNECTED,
      errorCode: TunnelErrorCode.PEER_DISCONNECTED
    });
    expect(budget.totalBufferedBytes).toBe(0);
    expect(disconnected.isBoundToSession(SESSION_ID)).toBe(false);
    expect(disconnected.handleInbound(stream(FrameType.STREAM_DATA, disconnected.streamId, Uint8Array.of(1)), "new-wss-session")).toMatchObject({
      accepted: false,
      state: StreamState.CLOSED
    });
  });

  it("uses an injected clock for open and idle timeouts", () => {
    let now = 0;
    const lifecycle = createLifecycle({
      now: () => now,
      limits: limits({ openTimeoutMs: 10, maxIdleMs: 20 }),
      initialReceiveCreditBytes: 8
    });

    now = 9;
    expect(lifecycle.tick()).toMatchObject({ accepted: false, state: StreamState.REQUESTED });
    now = 10;
    expect(lifecycle.tick()).toMatchObject({
      accepted: true,
      state: StreamState.FAILED,
      closeCode: StreamCloseCode.OPEN_TIMEOUT,
      errorCode: TunnelErrorCode.OPEN_TIMEOUT
    });

    now = 100;
    const idleLifecycle = createLifecycle({
      now: () => now,
      limits: limits({ openTimeoutMs: 10, maxIdleMs: 20 }),
      initialReceiveCreditBytes: 8
    });
    advanceToOpen(idleLifecycle, now);
    now = 119;
    expect(idleLifecycle.tick()).toMatchObject({ accepted: false, state: StreamState.OPEN });
    now = 120;
    expect(idleLifecycle.tick()).toMatchObject({
      accepted: true,
      state: StreamState.CLOSING,
      closeCode: StreamCloseCode.IDLE_TIMEOUT,
      shouldSendClose: true
    });
  });

  it("rejects out-of-order opened, credit overflow, and stream errors after open", () => {
    const lifecycle = createLifecycle({ initialReceiveCreditBytes: 8 });

    expect(lifecycle.handleInbound(stream(FrameType.STREAM_OPENED, lifecycle.streamId), SESSION_ID)).toMatchObject({
      accepted: false,
      state: StreamState.CLOSING
    });

    const flow = createLifecycle({ initialReceiveCreditBytes: 8 });
    advanceToOpen(flow);
    expect(
      flow.handleInbound(
        stream(FrameType.STREAM_CREDIT, flow.streamId, encodeStreamCreditPayload({ bytes: 8 })),
        SESSION_ID
      )
    ).toMatchObject({ accepted: true });
    expect(
      flow.handleInbound(
        stream(FrameType.STREAM_CREDIT, flow.streamId, encodeStreamCreditPayload({ bytes: 1 })),
        SESSION_ID
      )
    ).toMatchObject({
      accepted: false,
      state: StreamState.CLOSING,
      errorCode: TunnelErrorCode.FLOW_CONTROL_VIOLATION
    });

    const errored = createLifecycle({ initialReceiveCreditBytes: 8 });
    advanceToOpen(errored);
    expect(
      errored.handleInbound(
        stream(
          FrameType.STREAM_ERROR,
          errored.streamId,
          encodeStreamErrorPayload({ code: TunnelErrorCode.CONNECT_FAILED })
        ),
        SESSION_ID
      )
    ).toMatchObject({
      accepted: true,
      state: StreamState.FAILED,
      errorCode: TunnelErrorCode.CONNECT_FAILED
    });

    const rejected = createLifecycle({ initialReceiveCreditBytes: 8 });
    expect(
      rejected.handleInbound(
        stream(
          FrameType.STREAM_REJECTED,
          rejected.streamId,
          encodeStreamErrorPayload({ code: TunnelErrorCode.DESTINATION_REJECTED })
        ),
        SESSION_ID
      )
    ).toMatchObject({
      accepted: true,
      state: StreamState.REJECTED,
      errorCode: TunnelErrorCode.DESTINATION_REJECTED
    });
  });
});
