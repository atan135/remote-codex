export const MIN_CONNECTION_RATE_WINDOW_MS = 60_000;
export const MAX_CONNECTION_RATE_WINDOW_MS = 600_000;

export interface ConnectionRateTrackerLimits {
  readonly maxTrackedConnectionAddresses: number;
  readonly maxConnectionsPerWindow: number;
  readonly connectionRateWindowMs: number;
}

export interface ConnectionRateTrackerScheduler {
  readonly setInterval: (callback: () => void, delayMs: number) => unknown;
  readonly clearInterval: (handle: unknown) => void;
}

export type ConnectionRateDecision = "allowed" | "address-capacity-exceeded" | "rate-exceeded";

interface ConnectionRateRecord {
  readonly timestamps: number[];
}

function positiveInteger(value: number, code: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(code);
  }
}

function defaultScheduler(): ConnectionRateTrackerScheduler {
  return Object.freeze({
    setInterval: (callback: () => void, delayMs: number): unknown => {
      const timer = setInterval(callback, delayMs);
      timer.unref();
      return timer;
    },
    clearInterval: (handle: unknown): void => clearInterval(handle as ReturnType<typeof setInterval>)
  });
}

/** 只记录连接元数据；地址数量、窗口和 timer 都有显式边界与清理。 */
export class ConnectionRateTracker {
  private readonly records = new Map<string, ConnectionRateRecord>();
  private readonly cleanupTimer: unknown;
  private closed = false;

  public constructor(
    private readonly limits: ConnectionRateTrackerLimits,
    private readonly now: () => number = Date.now,
    private readonly scheduler: ConnectionRateTrackerScheduler = defaultScheduler()
  ) {
    positiveInteger(limits.maxTrackedConnectionAddresses, "SERVER_CONNECTION_RATE_ADDRESS_LIMIT_INVALID");
    positiveInteger(limits.maxConnectionsPerWindow, "SERVER_CONNECTION_RATE_COUNT_INVALID");
    if (
      !Number.isSafeInteger(limits.connectionRateWindowMs) ||
      limits.connectionRateWindowMs < MIN_CONNECTION_RATE_WINDOW_MS ||
      limits.connectionRateWindowMs > MAX_CONNECTION_RATE_WINDOW_MS
    ) {
      throw new RangeError("SERVER_CONNECTION_RATE_WINDOW_INVALID");
    }
    this.cleanupTimer = scheduler.setInterval(() => this.pruneAll(this.now()), limits.connectionRateWindowMs);
  }

  public record(address: string): ConnectionRateDecision {
    if (this.closed) {
      return "address-capacity-exceeded";
    }
    const now = this.now();
    const existing = this.records.get(address);
    if (existing !== undefined) {
      const timestamps = this.pruneAddress(address, existing, now);
      if (timestamps.length >= this.limits.maxConnectionsPerWindow) {
        return "rate-exceeded";
      }
      this.records.set(address, { timestamps: [...timestamps, now] });
      return "allowed";
    }

    if (this.records.size >= this.limits.maxTrackedConnectionAddresses) {
      this.pruneAll(now);
      if (this.records.size >= this.limits.maxTrackedConnectionAddresses) {
        return "address-capacity-exceeded";
      }
    }
    this.records.set(address, { timestamps: [now] });
    return "allowed";
  }

  public trackedAddressCount(): number {
    return this.records.size;
  }

  public close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.scheduler.clearInterval(this.cleanupTimer);
    this.records.clear();
  }

  private pruneAll(now: number): void {
    for (const [address, record] of this.records) {
      this.pruneAddress(address, record, now);
    }
  }

  private pruneAddress(address: string, record: ConnectionRateRecord, now: number): readonly number[] {
    const oldestAllowed = now - this.limits.connectionRateWindowMs;
    let firstRecentIndex = 0;
    while (
      firstRecentIndex < record.timestamps.length &&
      (record.timestamps[firstRecentIndex] ?? Number.NEGATIVE_INFINITY) <= oldestAllowed
    ) {
      firstRecentIndex += 1;
    }
    if (firstRecentIndex === 0) {
      return record.timestamps;
    }
    if (firstRecentIndex >= record.timestamps.length) {
      this.records.delete(address);
      return [];
    }
    const recent = record.timestamps.slice(firstRecentIndex);
    this.records.set(address, { timestamps: recent });
    return recent;
  }
}
