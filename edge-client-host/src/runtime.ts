import {
  EdgeClientRuntime,
  LOOPBACK_LISTEN_HOST,
  LoopbackConnectProxy,
  type EdgeClientRuntimeOptions,
  type EdgeClientStatusListener,
  type EdgeClientStatusSnapshot,
  type EdgeStreamGateway,
  type LoopbackConnectProxyAddress,
  type LoopbackConnectProxyOptions
} from "@remote-codex/edge-client";
import {
  loadProductionBundle,
  PRODUCTION_LISTEN_PORT_MAX,
  PRODUCTION_LISTEN_PORT_MIN,
  type LoadedEdgeClientProductionBundle,
  type LoadedProductionBundle
} from "@remote-codex/ops";
import { normalizeHostname } from "@remote-codex/shared";

import { SafeEdgeProcessLogger } from "./logging.js";
import { createPersistentEdgeStatusLog, type EdgeProcessLogSink } from "./persistent-log.js";

const TUNNEL_PATH = "/tunnel";
const TERMINAL_ERROR_CODES = new Set([
  "AUTH_EXPIRED",
  "AUTH_FAILED",
  "AUTH_REPLAYED",
  "AUTH_UNAUTHORIZED",
  "EDGE_RECONNECT_JITTER_INVALID",
  "RECONNECT_LIMIT_EXCEEDED"
]);

export interface EdgeRuntimeHandle extends EdgeStreamGateway {
  start(): void;
  stop(): void;
  getStatus(): EdgeClientStatusSnapshot;
  subscribeStatus(listener: EdgeClientStatusListener): () => void;
}

export interface EdgeProxyHandle {
  start(): Promise<LoopbackConnectProxyAddress>;
  stop(): Promise<void>;
}

export interface ProcessLifetimeLease {
  release(): void;
}

export interface EdgeClientHostDependencies {
  readonly loadBundle: (rootDirectory: string, manifestPath: string) => LoadedProductionBundle;
  readonly createRuntime: (options: EdgeClientRuntimeOptions) => EdgeRuntimeHandle;
  readonly createProxy: (options: LoopbackConnectProxyOptions) => EdgeProxyHandle;
  readonly createLogSink: (rootDirectory: string) => EdgeProcessLogSink;
  readonly acquireLifetimeLease: () => ProcessLifetimeLease;
  readonly onTerminalFailure: (code: string) => void;
}

export interface RunningEdgeClientHost {
  getStatus(): EdgeClientStatusSnapshot;
  close(): Promise<void>;
}

export class EdgeClientHostError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "EdgeClientHostError";
  }
}

function safeErrorCode(error: unknown, fallback: string): string {
  if (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string" &&
    /^[A-Z][A-Z0-9_]{0,127}$/u.test(error.code)
  ) {
    return error.code;
  }
  return fallback;
}

function requireEdgeBundle(bundle: LoadedProductionBundle): LoadedEdgeClientProductionBundle {
  if (bundle.component !== "edge-client") {
    throw new EdgeClientHostError("EDGE_HOST_COMPONENT_MISMATCH");
  }
  return bundle;
}

function validateProductionBundle(bundle: LoadedEdgeClientProductionBundle): string {
  const serverUrl = bundle.config.serverUrl;
  let serverHostname: string;
  let destinationHostname: string;
  try {
    serverHostname = normalizeHostname(serverUrl.hostname);
    destinationHostname = normalizeHostname(bundle.config.allowedDestination.hostname);
  } catch {
    throw new EdgeClientHostError("EDGE_HOST_NETWORK_POLICY_INVALID");
  }
  const serverPort = Number(serverUrl.port);
  if (
    serverUrl.protocol !== "wss:" ||
    serverUrl.hostname !== serverHostname ||
    !Number.isSafeInteger(serverPort) ||
    serverPort < PRODUCTION_LISTEN_PORT_MIN ||
    serverPort > PRODUCTION_LISTEN_PORT_MAX ||
    serverUrl.pathname !== TUNNEL_PATH ||
    serverUrl.username.length > 0 ||
    serverUrl.password.length > 0 ||
    serverUrl.search.length > 0 ||
    serverUrl.hash.length > 0
  ) {
    throw new EdgeClientHostError("EDGE_HOST_SERVER_URL_INVALID");
  }
  if (
    bundle.config.listenHost !== LOOPBACK_LISTEN_HOST ||
    !Number.isSafeInteger(bundle.config.listenPort) ||
    bundle.config.listenPort < PRODUCTION_LISTEN_PORT_MIN ||
    bundle.config.listenPort > PRODUCTION_LISTEN_PORT_MAX
  ) {
    throw new EdgeClientHostError("EDGE_HOST_LISTENER_INVALID");
  }
  if (
    bundle.config.allowedDestination.hostname !== destinationHostname ||
    bundle.config.allowedDestination.port !== 443
  ) {
    throw new EdgeClientHostError("EDGE_HOST_DESTINATION_INVALID");
  }
  return `https://${serverUrl.host}`;
}

export function acquireProcessLifetimeLease(): ProcessLifetimeLease {
  const keepAliveTimer = setInterval(() => undefined, 60_000);
  let released = false;
  return Object.freeze({
    release: (): void => {
      if (released) {
        return;
      }
      released = true;
      clearInterval(keepAliveTimer);
    }
  });
}

const DEFAULT_DEPENDENCIES: EdgeClientHostDependencies = Object.freeze({
  loadBundle: loadProductionBundle,
  createRuntime: (options: EdgeClientRuntimeOptions) => new EdgeClientRuntime(options),
  createProxy: (options: LoopbackConnectProxyOptions) => new LoopbackConnectProxy(options),
  createLogSink: createPersistentEdgeStatusLog,
  acquireLifetimeLease: acquireProcessLifetimeLease,
  onTerminalFailure: () => {
    process.exitCode = 1;
  }
});

export async function startEdgeClientHost(
  rootDirectory: string,
  manifestPath = "manifest.json",
  dependencies: Partial<EdgeClientHostDependencies> = {}
): Promise<RunningEdgeClientHost> {
  const resolved: EdgeClientHostDependencies = { ...DEFAULT_DEPENDENCIES, ...dependencies };
  let bundle: LoadedEdgeClientProductionBundle;
  let origin: string;
  try {
    bundle = requireEdgeBundle(resolved.loadBundle(rootDirectory, manifestPath));
    origin = validateProductionBundle(bundle);
  } catch (error: unknown) {
    throw new EdgeClientHostError(safeErrorCode(error, "EDGE_HOST_START_FAILED"));
  }

  let logSink: EdgeProcessLogSink | undefined;
  let runtime: EdgeRuntimeHandle | undefined;
  let proxy: EdgeProxyHandle | undefined;
  let lifetimeLease: ProcessLifetimeLease | undefined;
  try {
    logSink = resolved.createLogSink(rootDirectory);
    runtime = resolved.createRuntime({
      config: bundle.config,
      authenticationIdentity: bundle.identity,
      authenticationKey: bundle.authenticationPrivateKey,
      origin
    });
    proxy = resolved.createProxy({
      allowedDestination: bundle.config.allowedDestination,
      limits: bundle.config.limits,
      streamGateway: runtime,
      listenPort: bundle.config.listenPort
    });
    lifetimeLease = resolved.acquireLifetimeLease();
  } catch (error: unknown) {
    try {
      runtime?.stop();
    } catch {
      // runtime 初始化后的失败不能阻止其余本地资源清理。
    }
    try {
      logSink?.close();
    } catch {
      // 日志关闭失败不能阻止进程 lease 释放。
    }
    try {
      lifetimeLease?.release();
    } catch {
      // 初始化失败仍返回原始稳定错误码。
    }
    throw new EdgeClientHostError(safeErrorCode(error, "EDGE_HOST_START_FAILED"));
  }

  const runningLogSink = logSink;
  const runningRuntime = runtime;
  const runningProxy = proxy;
  const runningLifetimeLease = lifetimeLease;
  const logger = new SafeEdgeProcessLogger((line) => runningLogSink.write(line));
  let unsubscribe: (() => void) | undefined;
  let shutdownPromise: Promise<void> | undefined;
  let terminalReported = false;

  const shutdown = (terminalCode?: string, startupCode?: string): Promise<void> => {
    if (shutdownPromise !== undefined) {
      return shutdownPromise;
    }
    shutdownPromise = (async (): Promise<void> => {
      if (startupCode === undefined) {
        logger.lifecycle("edge.stopping", runningRuntime.getStatus());
      } else {
        logger.lifecycle("edge.start_failed", {
          state: "offline",
          reconnectAttempts: 0,
          lastErrorCode: startupCode
        });
      }
      try {
        runningRuntime.stop();
      } catch {
        process.exitCode = 1;
      }
      try {
        unsubscribe?.();
        unsubscribe = undefined;
      } catch {
        process.exitCode = 1;
      }
      try {
        await runningProxy.stop();
      } catch {
        process.exitCode = 1;
      }
      if (startupCode === undefined) {
        logger.lifecycle("edge.stopped", runningRuntime.getStatus());
      }
      try {
        runningLogSink.close();
      } catch {
        // 日志 sink 故障不能阻止进程 lease 释放或 terminal 失败退出。
      }
      try {
        runningLifetimeLease.release();
      } catch {
        process.exitCode = 1;
      }
      if (terminalCode !== undefined) {
        try {
          resolved.onTerminalFailure(terminalCode);
        } catch {
          process.exitCode = 1;
        }
      }
    })();
    return shutdownPromise;
  };

  const rejectTerminalDuringStart = async (): Promise<void> => {
    if (shutdownPromise === undefined) {
      return;
    }
    try {
      unsubscribe?.();
      unsubscribe = undefined;
    } catch {
      process.exitCode = 1;
    }
    await shutdownPromise;
    throw new EdgeClientHostError("EDGE_HOST_TERMINATED_DURING_START");
  };

  try {
    unsubscribe = runningRuntime.subscribeStatus((status) => {
      logger.lifecycle("edge.state_changed", status);
      if (
        !terminalReported &&
        status.state === "offline" &&
        status.lastErrorCode !== undefined &&
        TERMINAL_ERROR_CODES.has(status.lastErrorCode)
      ) {
        terminalReported = true;
        logger.lifecycle("edge.terminal_failure", status);
        void shutdown(status.lastErrorCode);
      }
    });
    await rejectTerminalDuringStart();
    await runningProxy.start();
    runningRuntime.start();
    await rejectTerminalDuringStart();
    logger.lifecycle("edge.started", runningRuntime.getStatus());
  } catch (error: unknown) {
    const code = safeErrorCode(error, "EDGE_HOST_START_FAILED");
    await shutdown(undefined, code);
    throw new EdgeClientHostError(code);
  }

  return Object.freeze({
    getStatus: (): EdgeClientStatusSnapshot => runningRuntime.getStatus(),
    close: (): Promise<void> => shutdown()
  });
}
