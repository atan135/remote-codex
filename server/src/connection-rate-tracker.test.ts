import { describe, expect, it, vi } from "vitest";

import {
  ConnectionRateTracker,
  type ConnectionRateTrackerScheduler
} from "./connection-rate-tracker.js";

function schedulerFixture(): {
  readonly scheduler: ConnectionRateTrackerScheduler;
  readonly clearInterval: ReturnType<typeof vi.fn>;
  runCleanup(): void;
} {
  let cleanup: (() => void) | undefined;
  const clearInterval = vi.fn();
  return {
    clearInterval,
    scheduler: {
      setInterval: (callback, delayMs) => {
        expect(delayMs).toBe(60_000);
        cleanup = callback;
        return "timer-01";
      },
      clearInterval
    },
    runCleanup: () => cleanup?.()
  };
}

describe("connection rate tracker", () => {
  it("地址达到上限后拒绝新地址，但已有地址继续按窗口计数", () => {
    const fixture = schedulerFixture();
    const tracker = new ConnectionRateTracker({
      maxTrackedConnectionAddresses: 1,
      maxConnectionsPerWindow: 2,
      connectionRateWindowMs: 60_000
    }, () => 1_000, fixture.scheduler);

    expect(tracker.record("203.0.113.1")).toBe("allowed");
    expect(tracker.record("203.0.113.2")).toBe("address-capacity-exceeded");
    expect(tracker.record("203.0.113.1")).toBe("allowed");
    expect(tracker.record("203.0.113.1")).toBe("rate-exceeded");
    tracker.close();
  });

  it("窗口过期清理后允许新地址，并在 close 时清理 timer 与状态", () => {
    let now = 1_000;
    const fixture = schedulerFixture();
    const tracker = new ConnectionRateTracker({
      maxTrackedConnectionAddresses: 1,
      maxConnectionsPerWindow: 1,
      connectionRateWindowMs: 60_000
    }, () => now, fixture.scheduler);

    expect(tracker.record("203.0.113.1")).toBe("allowed");
    now += 60_001;
    fixture.runCleanup();
    expect(tracker.trackedAddressCount()).toBe(0);
    expect(tracker.record("203.0.113.2")).toBe("allowed");
    tracker.close();
    expect(fixture.clearInterval).toHaveBeenCalledOnce();
    expect(fixture.clearInterval).toHaveBeenCalledWith("timer-01");
    expect(tracker.trackedAddressCount()).toBe(0);
    expect(tracker.record("203.0.113.3")).toBe("address-capacity-exceeded");
  });

  it("已有地址热路径只裁剪自身，新地址撞满容量时才全表回收", () => {
    let now = 1_000;
    const fixture = schedulerFixture();
    const tracker = new ConnectionRateTracker({
      maxTrackedConnectionAddresses: 2,
      maxConnectionsPerWindow: 2,
      connectionRateWindowMs: 60_000
    }, () => now, fixture.scheduler);

    expect(tracker.record("203.0.113.1")).toBe("allowed");
    expect(tracker.record("203.0.113.2")).toBe("allowed");
    now += 60_001;
    expect(tracker.record("203.0.113.1")).toBe("allowed");
    expect(tracker.trackedAddressCount()).toBe(2);

    expect(tracker.record("203.0.113.3")).toBe("allowed");
    expect(tracker.trackedAddressCount()).toBe(2);
    expect(tracker.record("203.0.113.1")).toBe("allowed");
    expect(tracker.record("203.0.113.1")).toBe("rate-exceeded");
    tracker.close();
  });

  it("拒绝会放宽速率限制并制造高频 timer 的短窗口", () => {
    const fixture = schedulerFixture();
    expect(() => new ConnectionRateTracker({
      maxTrackedConnectionAddresses: 1,
      maxConnectionsPerWindow: 1,
      connectionRateWindowMs: 1
    }, Date.now, fixture.scheduler)).toThrow("SERVER_CONNECTION_RATE_WINDOW_INVALID");
    expect(fixture.clearInterval).not.toHaveBeenCalled();
  });
});
