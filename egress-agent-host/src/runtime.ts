import {
  EgressAgentRuntime,
  type EgressAgentRuntimeOptions,
  type EgressAgentStatusListener,
  type EgressAgentStatusSnapshot
} from "@remote-codex/egress-agent";
import {
  loadProductionBundle,
  PRODUCTION_LISTEN_PORT_MAX,
  PRODUCTION_LISTEN_PORT_MIN,
  type LoadedEgressAgentProductionBundle,
  type LoadedProductionBundle
} from "@remote-codex/ops";
import { normalizeHostname } from "@remote-codex/shared";

import { SafeEgressAgentProcessLogger } from "./logging.js";
import {
  createPersistentAgentStatusLog,
  type AgentProcessLogSink
} from "./persistent-log.js";

const TUNNEL_PATH = "/tunnel";
const TERMINAL_ERROR_CODES = new Set([
  "AUTH_EXPIRED",
  "AUTH_FAILED",
  "AUTH_REPLAYED",
  "AUTH_UNAUTHORIZED",
  "AGENT_STREAM_CLEANUP_FAILED",
  "RECONNECT_LIMIT_EXCEEDED"
]);

export interface EgressAgentRuntimeHandle {
  start(): void;
  stop(): void;
  getStatus(): EgressAgentStatusSnapshot;
  subscribeStatus(listener: EgressAgentStatusListener): () => void;
}

export interface ProcessLifetimeLease {
  release(): void;
}

export interface EgressAgentHostDependencies {
  readonly loadBundle: (rootDirectory: string, manifestPath: string) => LoadedProductionBundle;
  readonly createRuntime: (options: EgressAgentRuntimeOptions) => EgressAgentRuntimeHandle;
  readonly createLogSink: (rootDirectory: string) => AgentProcessLogSink;
  readonly acquireLifetimeLease: () => ProcessLifetimeLease;
  readonly onTerminalFailure: (code: string) => void;
}

export interface RunningEgressAgentHost {
  getStatus(): EgressAgentStatusSnapshot;
  close(): void;
}

export class EgressAgentHostError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "EgressAgentHostError";
  }
}

const SAFE_AGENT_HOST_ERROR_CODES = new Set([
  "AGENT_HOST_COMPONENT_MISMATCH",
  "AGENT_HOST_LIFETIME_INIT_FAILED",
  "AGENT_HOST_SERVER_URL_INVALID",
  "AGENT_HOST_START_FAILED"
]);

function safeErrorCode(error: unknown, fallback: string): string {
  if (error instanceof EgressAgentHostError && SAFE_AGENT_HOST_ERROR_CODES.has(error.code)) {
    return error.code;
  }
  return fallback;
}

function requireAgentBundle(bundle: LoadedProductionBundle): LoadedEgressAgentProductionBundle {
  if (bundle.component !== "egress-agent") {
    throw new EgressAgentHostError("AGENT_HOST_COMPONENT_MISMATCH");
  }
  return bundle;
}

function validateServerUrl(serverUrl: URL): string {
  let normalizedHostname: string;
  try {
    normalizedHostname = normalizeHostname(serverUrl.hostname);
  } catch {
    throw new EgressAgentHostError("AGENT_HOST_SERVER_URL_INVALID");
  }
  const port = Number(serverUrl.port);
  if (
    serverUrl.protocol !== "wss:" ||
    serverUrl.hostname !== normalizedHostname ||
    !Number.isSafeInteger(port) ||
    port < PRODUCTION_LISTEN_PORT_MIN ||
    port > PRODUCTION_LISTEN_PORT_MAX ||
    serverUrl.pathname !== TUNNEL_PATH ||
    serverUrl.username.length > 0 ||
    serverUrl.password.length > 0 ||
    serverUrl.search.length > 0 ||
    serverUrl.hash.length > 0
  ) {
    throw new EgressAgentHostError("AGENT_HOST_SERVER_URL_INVALID");
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

const DEFAULT_DEPENDENCIES: EgressAgentHostDependencies = Object.freeze({
  loadBundle: loadProductionBundle,
  createRuntime: (options: EgressAgentRuntimeOptions) => new EgressAgentRuntime(options),
  createLogSink: createPersistentAgentStatusLog,
  acquireLifetimeLease: acquireProcessLifetimeLease,
  onTerminalFailure: () => {
    process.exitCode = 1;
  }
});

export function startEgressAgentHost(
  rootDirectory: string,
  manifestPath = "manifest.json",
  dependencies: Partial<EgressAgentHostDependencies> = {}
): RunningEgressAgentHost {
  const resolved: EgressAgentHostDependencies = { ...DEFAULT_DEPENDENCIES, ...dependencies };
  let logSink: AgentProcessLogSink | undefined;
  let logger: SafeEgressAgentProcessLogger | undefined;
  let runtime: EgressAgentRuntimeHandle | undefined;
  try {
    const bundle = requireAgentBundle(resolved.loadBundle(rootDirectory, manifestPath));
    const origin = validateServerUrl(bundle.config.serverUrl);
    logSink = resolved.createLogSink(rootDirectory);
    logger = new SafeEgressAgentProcessLogger((line) => logSink?.write(line));
    runtime = resolved.createRuntime({
      config: bundle.config,
      authenticationIdentity: bundle.identity,
      authenticationKey: bundle.authenticationPrivateKey,
      capabilityServerIdentity: bundle.serverIdentity,
      origin
    });
  } catch (error: unknown) {
    const code = safeErrorCode(error, "AGENT_HOST_START_FAILED");
    logger?.lifecycle("agent.start_failed", { state: "offline", reconnectAttempts: 0, lastErrorCode: code });
    logSink?.close();
    throw new EgressAgentHostError(code);
  }

  const runningRuntime = runtime;
  const runningLogSink = logSink;
  const runningLogger = logger;
  let lifetimeLease: ProcessLifetimeLease;
  try {
    lifetimeLease = resolved.acquireLifetimeLease();
  } catch {
    runningRuntime.stop();
    runningLogger.lifecycle("agent.start_failed", {
      state: "offline",
      reconnectAttempts: 0,
      lastErrorCode: "AGENT_HOST_LIFETIME_INIT_FAILED"
    });
    runningLogSink.close();
    throw new EgressAgentHostError("AGENT_HOST_LIFETIME_INIT_FAILED");
  }
  let processResourcesReleased = false;
  const releaseProcessResources = (): void => {
    if (processResourcesReleased) {
      return;
    }
    processResourcesReleased = true;
    try {
      runningLogSink.close();
    } catch {
      // 注入或平台日志 sink 失败不能阻止进程 lease 释放。
    } finally {
      lifetimeLease.release();
    }
  };
  let terminalReported = false;
  let closed = false;
  let unsubscribe = (): void => undefined;

  try {
    unsubscribe = runningRuntime.subscribeStatus((status) => {
      runningLogger.lifecycle("agent.state_changed", status);
      if (
        !terminalReported &&
        status.state === "offline" &&
        status.lastErrorCode !== undefined &&
        TERMINAL_ERROR_CODES.has(status.lastErrorCode)
      ) {
        terminalReported = true;
        runningLogger.lifecycle("agent.terminal_failure", status);
        releaseProcessResources();
        resolved.onTerminalFailure(status.lastErrorCode);
      }
    });
    runningRuntime.start();
    runningLogger.lifecycle("agent.started", runningRuntime.getStatus());
  } catch (error: unknown) {
    unsubscribe();
    runningRuntime.stop();
    const code = safeErrorCode(error, "AGENT_HOST_START_FAILED");
    runningLogger.lifecycle("agent.start_failed", { state: "offline", reconnectAttempts: 0, lastErrorCode: code });
    releaseProcessResources();
    throw new EgressAgentHostError(code);
  }

  return Object.freeze({
    getStatus: (): EgressAgentStatusSnapshot => runningRuntime.getStatus(),
    close: (): void => {
      if (closed) {
        return;
      }
      closed = true;
      runningLogger.lifecycle("agent.stopping", runningRuntime.getStatus());
      runningRuntime.stop();
      unsubscribe();
      runningLogger.lifecycle("agent.stopped", runningRuntime.getStatus());
      releaseProcessResources();
    }
  });
}
