import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server as HttpsServer } from "node:https";
import type { Duplex } from "node:stream";

import { assertTlsVerificationEnabled } from "@remote-codex/shared";
import { WebSocketServer, type WebSocket } from "ws";

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
  readonly maxConnectionsPerWindow: number;
  readonly connectionRateWindowMs: number;
  readonly handshakeTimeoutMs: number;
  readonly maxMessageBytes: number;
}

export const DEFAULT_SERVER_TRANSPORT_LIMITS: ServerTransportLimits = Object.freeze({
  maxUpgradeHeaderBytes: 16 * 1024,
  maxUpgradeHeaderCount: 64,
  maxConcurrentHandshakes: 32,
  maxConnectionsPerWindow: 30,
  connectionRateWindowMs: 60_000,
  handshakeTimeoutMs: 10_000,
  maxMessageBytes: 32 * 1024
});

export interface TunnelServerOptions {
  readonly tls: TlsCredentials;
  readonly allowedOrigins: readonly string[];
  readonly limits?: Partial<ServerTransportLimits>;
}

export interface TunnelServer {
  readonly httpsServer: HttpsServer;
  readonly webSocketServer: WebSocketServer;
  close(): Promise<void>;
}

export class ServerStartupError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "ServerStartupError";
  }
}

interface ConnectionRateRecord {
  readonly timestamps: number[];
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
  const connectionRates = new Map<string, ConnectionRateRecord>();
  let pendingHandshakes = 0;

  webSocketServer.on("connection", (socket: WebSocket) => {
    // ws 会在超大或畸形 frame 时发出 error；消费错误以避免进程异常退出。
    socket.on("error", () => undefined);
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

    const now = Date.now();
    const connectionKey = request.socket.remoteAddress ?? "unknown";
    const existingRate = connectionRates.get(connectionKey);
    const recentTimestamps = (existingRate?.timestamps ?? []).filter(
      (timestamp) => now - timestamp < limits.connectionRateWindowMs
    );

    if (recentTimestamps.length >= limits.maxConnectionsPerWindow) {
      rejectUpgrade(socket, 429);
      return;
    }

    recentTimestamps.push(now);
    connectionRates.set(connectionKey, { timestamps: recentTimestamps });

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
    close: async (): Promise<void> => {
      webSocketServer.close();
      await new Promise<void>((resolve, reject) => {
        httpsServer.close((error) => (error === undefined ? resolve() : reject(error)));
      });
    }
  });
}
