import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server as HttpsServer } from "node:https";
import type { Duplex } from "node:stream";

import {
  assertTlsVerificationEnabled,
  type AllowedDestination,
  type ResourceLimits,
  type ServerSigningCredentials
} from "@remote-codex/shared";
import { WebSocketServer, type WebSocket } from "ws";

import { PeerSessionManager, type ServerPeerIdentityRegistration } from "./peer-session.js";
import {
  AuthorizationRegistry,
  type AuthorizationRegistryDocument,
  type AuthorizationRevocationListener
} from "./authorization-registry.js";
import { StreamOpenCoordinator } from "./stream-open.js";
import type { StreamAuditLogger, StreamMetricsSnapshot } from "./observability.js";
import type { StreamQuotaLimits } from "./stream-open.js";
import {
  ConnectionRateTracker,
  MAX_CONNECTION_RATE_WINDOW_MS,
  MIN_CONNECTION_RATE_WINDOW_MS
} from "./connection-rate-tracker.js";

export const HEALTH_CHECK_PATH = "/health" as const;
export const TUNNEL_WEBSOCKET_PATH = "/tunnel" as const;

export interface TlsCredentialPaths {
  readonly certificatePath: string;
  readonly privateKeyPath: string;
}

export interface TlsCredentials {
  readonly certificate: Buffer;
  readonly privateKey: Buffer;
}

export interface ServerTransportLimits {
  readonly maxUpgradeHeaderBytes: number;
  readonly maxUpgradeHeaderCount: number;
  readonly maxConcurrentHandshakes: number;
  readonly maxTrackedConnectionAddresses: number;
  readonly maxConnectionsPerWindow: number;
  readonly connectionRateWindowMs: number;
  readonly handshakeTimeoutMs: number;
  readonly maxMessageBytes: number;
}

export const DEFAULT_SERVER_TRANSPORT_LIMITS: ServerTransportLimits = Object.freeze({
  maxUpgradeHeaderBytes: 16 * 1024,
  maxUpgradeHeaderCount: 64,
  maxConcurrentHandshakes: 32,
  maxTrackedConnectionAddresses: 4_096,
  maxConnectionsPerWindow: 30,
  connectionRateWindowMs: 60_000,
  handshakeTimeoutMs: 10_000,
  maxMessageBytes: 32 * 1024
});

export const DEFAULT_PEER_HEARTBEAT_TIMEOUT_MS = 45_000;

/** 开流授权所需的独立 server 签名身份与固定目标配置。 */
export interface ServerStreamAuthorizationOptions {
  readonly signingCredentials: ServerSigningCredentials;
  readonly allowedDestination: AllowedDestination;
  readonly resourceLimits?: ResourceLimits;
  readonly capabilityTtlMs?: number;
  /** user/device/agent/global 四维 stream 资源与开流频率限制。 */
  readonly quotaLimits?: StreamQuotaLimits;
  /** 仅接收白名单序列化审计记录的日志适配器。 */
  readonly auditLogger?: StreamAuditLogger;
  readonly now?: () => number;
}

export interface TunnelServerOptions {
  readonly tls: TlsCredentials;
  readonly allowedOrigins: readonly string[];
  readonly limits?: Partial<ServerTransportLimits>;
  /** 仅接受由进程内配置注入的公钥身份；不得从连接请求读取凭据。 */
  readonly peerIdentities?: readonly ServerPeerIdentityRegistration[];
  readonly authenticationTimeoutMs?: number;
  readonly heartbeatTimeoutMs?: number;
  /** 启动时严格校验的 edge user/device-to-agent 授权文件。 */
  readonly authorizationDocument?: AuthorizationRegistryDocument;
  /** 授权撤销后由后续 stream 层订阅并关闭受影响存量流。 */
  readonly onAuthorizationRevocation?: AuthorizationRevocationListener;
  /** 未配置时 server 不接受 stream 帧；绝不降级为通用中继。 */
  readonly streamAuthorization?: ServerStreamAuthorizationOptions;
}

export interface TunnelServer {
  readonly httpsServer: HttpsServer;
  readonly webSocketServer: WebSocketServer;
  readonly peerSessions: PeerSessionManager;
  readonly authorizationRegistry: AuthorizationRegistry;
  readonly streamOpenCoordinator?: StreamOpenCoordinator;
  /** 受控进程内指标快照，不新增 HTTP 端点或泄露 stream 内容。 */
  readonly getMetrics?: () => StreamMetricsSnapshot;
  close(): Promise<void>;
}

export class ServerStartupError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "ServerStartupError";
  }
}

function startupFailure(code: string): never {
  throw new ServerStartupError(code);
}

function requirePath(value: string, code: string): void {
  if (value.length === 0 || value.trim() !== value) {
    startupFailure(code);
  }
}

function requirePositiveInteger(value: number, code: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    startupFailure(code);
  }
}

function resolveTransportLimits(
  configuredLimits: Partial<ServerTransportLimits> | undefined
): ServerTransportLimits {
  const limits: ServerTransportLimits = {
    ...DEFAULT_SERVER_TRANSPORT_LIMITS,
    ...configuredLimits
  };

  for (const [key, value] of Object.entries(limits)) {
    requirePositiveInteger(value, `SERVER_TRANSPORT_LIMIT_INVALID_${key}`);
  }

  if (limits.maxUpgradeHeaderBytes < 512) {
    startupFailure("SERVER_TRANSPORT_LIMIT_HEADER_BYTES_TOO_SMALL");
  }
  if (
    limits.connectionRateWindowMs < MIN_CONNECTION_RATE_WINDOW_MS ||
    limits.connectionRateWindowMs > MAX_CONNECTION_RATE_WINDOW_MS
  ) {
    startupFailure("SERVER_TRANSPORT_LIMIT_CONNECTION_RATE_WINDOW_INVALID");
  }

  return Object.freeze(limits);
}

function validateAllowedOrigins(origins: readonly string[]): ReadonlySet<string> {
  if (origins.length === 0) {
    startupFailure("SERVER_ORIGIN_POLICY_REQUIRED");
  }

  const allowedOrigins = new Set<string>();

  for (const origin of origins) {
    let parsedOrigin: URL;

    try {
      parsedOrigin = new URL(origin);
    } catch {
      startupFailure("SERVER_ORIGIN_POLICY_INVALID");
    }

    if (parsedOrigin.protocol !== "https:" || parsedOrigin.origin !== origin) {
      startupFailure("SERVER_ORIGIN_POLICY_INVALID");
    }

    allowedOrigins.add(origin);
  }

  return allowedOrigins;
}

function validateTlsCredentials(credentials: TlsCredentials): void {
  if (credentials.certificate.byteLength === 0 || credentials.privateKey.byteLength === 0) {
    startupFailure("SERVER_TLS_CREDENTIALS_EMPTY");
  }
}

function upgradeHeaderBytes(request: IncomingMessage): number {
  let total = Buffer.byteLength(`${request.method ?? ""} ${request.url ?? ""} HTTP/${request.httpVersion}\r\n`);

  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index] ?? "";
    const value = request.rawHeaders[index + 1] ?? "";
    total += Buffer.byteLength(`${name}: ${value}\r\n`);
  }

  return total + 2;
}

function requestHasUnexpectedBody(request: IncomingMessage): boolean {
  const contentLength = request.headers["content-length"];

  if (contentLength !== undefined && contentLength !== "0") {
    return true;
  }

  return request.headers["transfer-encoding"] !== undefined || request.headers.expect !== undefined;
}

function hasWebSocketUpgradeHeaders(request: IncomingMessage): boolean {
  const upgrade = request.headers.upgrade;
  const connection = request.headers.connection;

  return (
    typeof upgrade === "string" &&
    upgrade.toLowerCase() === "websocket" &&
    typeof connection === "string" &&
    connection.toLowerCase().split(",").some((value) => value.trim() === "upgrade") &&
    request.headers["sec-websocket-version"] === "13"
  );
}

function rejectUpgrade(socket: Duplex, statusCode: 400 | 403 | 404 | 429 | 431 | 503): void {
  if (socket.writable) {
    socket.write(`HTTP/1.1 ${statusCode}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  }

  socket.destroy();
}

function writeHttpResponse(response: ServerResponse, statusCode: 404 | 405 | 426): void {
  response.writeHead(statusCode, {
    "content-length": "0",
    "cache-control": "no-store"
  });
  response.end();
}

function writeHealthResponse(response: ServerResponse): void {
  const body = "{\"status\":\"ok\"}";
  response.writeHead(200, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body).toString(),
    "cache-control": "no-store"
  });
  response.end(body);
}

function createHttpRequestHandler(): (request: IncomingMessage, response: ServerResponse) => void {
  return (request, response): void => {
    if (request.method === "GET" && request.url === HEALTH_CHECK_PATH) {
      writeHealthResponse(response);
      return;
    }

    if (request.url === TUNNEL_WEBSOCKET_PATH && request.method === "GET") {
      writeHttpResponse(response, 426);
      return;
    }

    writeHttpResponse(response, request.url === HEALTH_CHECK_PATH ? 405 : 404);
  };
}

/** 从显式路径读取 TLS 凭据；不会回退到环境变量或其他项目的配置。 */
export async function loadTlsCredentials(paths: TlsCredentialPaths): Promise<TlsCredentials> {
  requirePath(paths.certificatePath, "SERVER_TLS_CERTIFICATE_PATH_INVALID");
  requirePath(paths.privateKeyPath, "SERVER_TLS_PRIVATE_KEY_PATH_INVALID");

  try {
    const [certificate, privateKey] = await Promise.all([
      readFile(paths.certificatePath),
      readFile(paths.privateKeyPath)
    ]);
    const credentials = Object.freeze({ certificate, privateKey });
    validateTlsCredentials(credentials);
    return credentials;
  } catch (error: unknown) {
    if (error instanceof ServerStartupError) {
      throw error;
    }

    return startupFailure("SERVER_TLS_CREDENTIALS_LOAD_FAILED");
  }
}

/**
 * 创建唯一的 HTTPS/WSS 入口。该进程只处理 HTTP(S) 和 WebSocket 握手，
 * 不会建立任何目标 TCP 连接。
 */
export function createTunnelServer(options: TunnelServerOptions): TunnelServer {
  assertTlsVerificationEnabled(process.env);
  validateTlsCredentials(options.tls);
  const allowedOrigins = validateAllowedOrigins(options.allowedOrigins);
  const limits = resolveTransportLimits(options.limits);
  let httpsServer: HttpsServer;

  try {
    httpsServer = createServer(
      {
        cert: options.tls.certificate,
        key: options.tls.privateKey,
        minVersion: "TLSv1.3",
        maxHeaderSize: limits.maxUpgradeHeaderBytes
      },
      createHttpRequestHandler()
    );
  } catch {
    return startupFailure("SERVER_TLS_CREDENTIALS_INVALID");
  }

  httpsServer.headersTimeout = limits.handshakeTimeoutMs;
  httpsServer.requestTimeout = limits.handshakeTimeoutMs;
  httpsServer.on("clientError", (error, socket) => {
    if (socket.writable) {
      const statusCode = (error as NodeJS.ErrnoException).code === "HPE_HEADER_OVERFLOW" ? 431 : 400;
      socket.end(`HTTP/1.1 ${statusCode}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    }
  });

  const webSocketServer = new WebSocketServer({
    clientTracking: false,
    maxPayload: limits.maxMessageBytes,
    noServer: true,
    perMessageDeflate: false
  });
  const peerSessions = new PeerSessionManager({
    heartbeatTimeoutMs: options.heartbeatTimeoutMs ?? DEFAULT_PEER_HEARTBEAT_TIMEOUT_MS,
    ...(options.peerIdentities === undefined ? {} : { peerIdentities: options.peerIdentities }),
    ...(options.authenticationTimeoutMs === undefined ? {} : { authenticationTimeoutMs: options.authenticationTimeoutMs })
  });
  const authorizationRegistry = new AuthorizationRegistry({
    peerIdentities: options.peerIdentities ?? [],
    ...(options.authorizationDocument === undefined ? {} : { document: options.authorizationDocument }),
    ...(options.onAuthorizationRevocation === undefined
      ? {}
      : { onRevocation: options.onAuthorizationRevocation })
  });
  const streamOpenCoordinator =
    options.streamAuthorization === undefined
      ? undefined
      : new StreamOpenCoordinator({
          peerSessions,
          authorizationRegistry,
          ...options.streamAuthorization
        });
  const streamExpirationTimer =
    streamOpenCoordinator === undefined
      ? undefined
      : setInterval(
          () => streamOpenCoordinator.expireOpenStreams(),
          Math.max(
            10,
            Math.floor(
              Math.min(
                options.streamAuthorization?.resourceLimits?.openTimeoutMs ?? 15_000,
                options.streamAuthorization?.capabilityTtlMs ?? 30_000
              ) / 2
            )
          )
        );
  streamExpirationTimer?.unref();
  const connectionRates = new ConnectionRateTracker(limits);
  let pendingHandshakes = 0;

  webSocketServer.on("connection", (socket: WebSocket) => {
    // ws 会在超大或畸形 frame 时发出 error；消费错误以避免进程异常退出。
    socket.on("error", () => undefined);
    peerSessions.attach(socket);
  });

  httpsServer.on("upgrade", (request, socket, head) => {
    if (request.method !== "GET" || request.url !== TUNNEL_WEBSOCKET_PATH) {
      rejectUpgrade(socket, 404);
      return;
    }

    if (
      request.rawHeaders.length / 2 > limits.maxUpgradeHeaderCount ||
      upgradeHeaderBytes(request) > limits.maxUpgradeHeaderBytes
    ) {
      rejectUpgrade(socket, 431);
      return;
    }

    if (requestHasUnexpectedBody(request) || !hasWebSocketUpgradeHeaders(request)) {
      rejectUpgrade(socket, 400);
      return;
    }

    const origin = request.headers.origin;
    if (typeof origin !== "string" || !allowedOrigins.has(origin)) {
      rejectUpgrade(socket, 403);
      return;
    }

    const connectionKey = request.socket.remoteAddress ?? "unknown";
    const connectionRateDecision = connectionRates.record(connectionKey);
    if (connectionRateDecision === "address-capacity-exceeded") {
      rejectUpgrade(socket, 503);
      return;
    }
    if (connectionRateDecision === "rate-exceeded") {
      rejectUpgrade(socket, 429);
      return;
    }

    if (pendingHandshakes >= limits.maxConcurrentHandshakes) {
      rejectUpgrade(socket, 503);
      return;
    }

    pendingHandshakes += 1;

    try {
      webSocketServer.handleUpgrade(request, socket, head, (webSocket) => {
        pendingHandshakes -= 1;
        webSocketServer.emit("connection", webSocket, request);
      });
    } catch {
      pendingHandshakes -= 1;
      rejectUpgrade(socket, 400);
    }
  });

  return Object.freeze({
    httpsServer,
    webSocketServer,
    peerSessions,
    authorizationRegistry,
    ...(streamOpenCoordinator === undefined ? {} : { streamOpenCoordinator }),
    ...(streamOpenCoordinator === undefined ? {} : { getMetrics: () => streamOpenCoordinator.getMetrics() }),
    close: async (): Promise<void> => {
      if (streamExpirationTimer !== undefined) {
        clearInterval(streamExpirationTimer);
      }
      connectionRates.close();
      streamOpenCoordinator?.close();
      peerSessions.close();
      webSocketServer.close();
      await new Promise<void>((resolve, reject) => {
        httpsServer.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  });
}
