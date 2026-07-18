import { createSecureContext } from "node:tls";

import {
  loadProductionBundle,
  type LoadedProductionBundle,
  type LoadedServerProductionBundle
} from "@remote-codex/ops";
import {
  createTunnelServer,
  HEALTH_CHECK_PATH,
  TUNNEL_WEBSOCKET_PATH,
  type TunnelServer,
  type TunnelServerOptions
} from "@remote-codex/server";

import { SafeServerProcessLogger, type ProcessLogWriter } from "./logging.js";
import { fingerprintNonTlsServerBundle } from "./bundle-fingerprint.js";

export interface ServerHostDependencies {
  readonly loadBundle: (rootDirectory: string, manifestPath: string) => LoadedProductionBundle;
  readonly createServer: (options: TunnelServerOptions) => TunnelServer;
  readonly validateTls: (certificate: Buffer, privateKey: Buffer) => void;
  readonly listen: (server: TunnelServer, host: string, port: number, backlog: number) => Promise<void>;
  readonly writeLog: ProcessLogWriter;
}

export interface RunningServerHost {
  readonly publicWssUrl: string;
  readonly healthUrl: string;
  reloadTls(): Promise<boolean>;
  close(): Promise<void>;
}

export class ServerHostError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "ServerHostError";
  }
}

const SAFE_SERVER_HOST_ERROR_CODES = new Set([
  "SERVER_HOST_COMPONENT_MISMATCH",
  "SERVER_HOST_LISTEN_FAILED",
  "SERVER_HOST_RELOAD_REQUIRES_RESTART",
  "SERVER_HOST_START_FAILED",
  "SERVER_HOST_TLS_CREDENTIALS_INVALID",
  "SERVER_HOST_TLS_RELOAD_FAILED"
]);

function safeErrorCode(error: unknown, fallback: string): string {
  if (error instanceof ServerHostError && SAFE_SERVER_HOST_ERROR_CODES.has(error.code)) {
    return error.code;
  }
  return fallback;
}

function validateTls(certificate: Buffer, privateKey: Buffer): void {
  try {
    createSecureContext({ cert: certificate, key: privateKey, minVersion: "TLSv1.3" });
  } catch {
    throw new ServerHostError("SERVER_HOST_TLS_CREDENTIALS_INVALID");
  }
}

function listen(
  server: TunnelServer,
  host: string,
  port: number,
  backlog: number
): Promise<void> {
  return new Promise((resolve, reject) => {
    const handleError = (): void => {
      server.httpsServer.off("listening", handleListening);
      reject(new ServerHostError("SERVER_HOST_LISTEN_FAILED"));
    };
    const handleListening = (): void => {
      server.httpsServer.off("error", handleError);
      resolve();
    };
    server.httpsServer.once("error", handleError);
    server.httpsServer.once("listening", handleListening);
    server.httpsServer.listen({ host, port, backlog, exclusive: true });
  });
}

const DEFAULT_DEPENDENCIES: ServerHostDependencies = Object.freeze({
  loadBundle: loadProductionBundle,
  createServer: createTunnelServer,
  validateTls,
  listen,
  writeLog: (line: string) => process.stdout.write(line)
});

function requireServerBundle(bundle: LoadedProductionBundle): LoadedServerProductionBundle {
  if (bundle.component !== "server") {
    throw new ServerHostError("SERVER_HOST_COMPONENT_MISMATCH");
  }
  return bundle;
}

function createOptions(
  bundle: LoadedServerProductionBundle,
  logger: SafeServerProcessLogger
): TunnelServerOptions {
  return {
    tls: bundle.tls,
    allowedOrigins: bundle.hostConfig.allowedOrigins,
    limits: bundle.hostConfig.transportLimits,
    peerIdentities: bundle.peerIdentities,
    heartbeatTimeoutMs: bundle.config.limits.heartbeatTimeoutMs,
    authenticationTimeoutMs: bundle.config.limits.openTimeoutMs,
    authorizationDocument: bundle.authorizationDocument,
    streamAuthorization: {
      signingCredentials: bundle.signingCredentials,
      allowedDestination: bundle.config.allowedDestination,
      resourceLimits: bundle.config.limits,
      auditLogger: (event) => logger.audit(event)
    }
  };
}

export async function startServerHost(
  rootDirectory: string,
  manifestPath = "manifest.json",
  dependencies: Partial<ServerHostDependencies> = {}
): Promise<RunningServerHost> {
  const resolved: ServerHostDependencies = { ...DEFAULT_DEPENDENCIES, ...dependencies };
  const logger = new SafeServerProcessLogger(resolved.writeLog);
  let bundle: LoadedServerProductionBundle;
  let initialNonTlsFingerprint: string;
  let server: TunnelServer | undefined;
  try {
    bundle = requireServerBundle(resolved.loadBundle(rootDirectory, manifestPath));
    initialNonTlsFingerprint = fingerprintNonTlsServerBundle(bundle);
    resolved.validateTls(bundle.tls.certificate, bundle.tls.privateKey);
    server = resolved.createServer(createOptions(bundle, logger));
    server.httpsServer.maxConnections = bundle.hostConfig.maxConnections;
    await resolved.listen(
      server,
      bundle.hostConfig.listenHost,
      bundle.hostConfig.listenPort,
      bundle.hostConfig.listenBacklog
    );
  } catch (error: unknown) {
    await server?.close().catch(() => undefined);
    const code = safeErrorCode(error, "SERVER_HOST_START_FAILED");
    logger.lifecycle("server.start_failed", { code });
    throw new ServerHostError(code);
  }

  const runningServer = server;
  const publicWssUrl = `wss://${bundle.hostConfig.publicHostname}:${bundle.hostConfig.listenPort}${TUNNEL_WEBSOCKET_PATH}`;
  const healthUrl = `https://${bundle.hostConfig.publicHostname}:${bundle.hostConfig.listenPort}${HEALTH_CHECK_PATH}`;
  let closing: Promise<void> | undefined;
  const metricsTimer = setInterval(() => {
    const snapshot = runningServer.getMetrics?.();
    if (snapshot !== undefined) {
      logger.metrics(snapshot);
    }
  }, bundle.hostConfig.metricsIntervalMs);
  metricsTimer.unref();

  logger.lifecycle("server.started", {
    listenPort: bundle.hostConfig.listenPort
  });

  return Object.freeze({
    publicWssUrl,
    healthUrl,
    reloadTls: async (): Promise<boolean> => {
      try {
        const reloaded = requireServerBundle(resolved.loadBundle(rootDirectory, manifestPath));
        if (fingerprintNonTlsServerBundle(reloaded) !== initialNonTlsFingerprint) {
          throw new ServerHostError("SERVER_HOST_RELOAD_REQUIRES_RESTART");
        }
        resolved.validateTls(reloaded.tls.certificate, reloaded.tls.privateKey);
        runningServer.httpsServer.setSecureContext({
          cert: reloaded.tls.certificate,
          key: reloaded.tls.privateKey,
          minVersion: "TLSv1.3"
        });
        logger.lifecycle("server.tls_reloaded");
        return true;
      } catch (error: unknown) {
        logger.lifecycle("server.tls_reload_failed", {
          code: safeErrorCode(error, "SERVER_HOST_TLS_RELOAD_FAILED")
        });
        return false;
      }
    },
    close: (): Promise<void> => {
      closing ??= (async (): Promise<void> => {
        clearInterval(metricsTimer);
        logger.lifecycle("server.stopping");
        const forceTimer = setTimeout(
          () => runningServer.httpsServer.closeAllConnections(),
          bundle.hostConfig.shutdownTimeoutMs
        );
        forceTimer.unref();
        try {
          await runningServer.close();
        } finally {
          clearTimeout(forceTimer);
          logger.lifecycle("server.stopped");
        }
      })();
      return closing;
    }
  });
}
