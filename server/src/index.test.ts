import { once } from "node:events";
import { get as httpGet } from "node:http";
import { get, request } from "node:https";

import selfsigned from "selfsigned";
import WebSocket from "ws";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  createTunnelServer,
  loadTlsCredentials,
  packageName,
  sharedProtocolVersion,
  type ServerStartupError,
  type TlsCredentials,
  type TunnelServer
} from "./index.js";
import { listenOnApprovedTestPort } from "./test-port-helper.js";

const TEST_ORIGIN = "https://edge.example.test";
let testTlsCredentials: TlsCredentials;
let runningServer: TunnelServer | undefined;
const initialTlsVerificationSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

beforeAll(() => {
  delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const certificate = selfsigned.generate([{ name: "commonName", value: "localhost" }], {
    algorithm: "sha256",
    days: 1,
    keySize: 2048
  });
  testTlsCredentials = {
    certificate: Buffer.from(certificate.cert),
    privateKey: Buffer.from(certificate.private)
  };
});

afterAll(() => {
  if (initialTlsVerificationSetting === undefined) {
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    return;
  }

  process.env.NODE_TLS_REJECT_UNAUTHORIZED = initialTlsVerificationSetting;
});

afterEach(async () => {
  await runningServer?.close();
  runningServer = undefined;
});

interface ServerFixtureOptions {
  readonly maxMessageBytes?: number;
  readonly tlsMinimumVersion?: "TLSv1.2" | "TLSv1.3";
  readonly clientAddressSource?: "socket" | "loopback-x-forwarded-for";
  readonly maxConnectionsPerWindow?: number;
}

async function startServer(options: ServerFixtureOptions = {}): Promise<string> {
  runningServer = createTunnelServer({
    tls: testTlsCredentials,
    ...(options.tlsMinimumVersion === undefined ? {} : { tlsMinimumVersion: options.tlsMinimumVersion }),
    allowedOrigins: [TEST_ORIGIN],
    ...(options.clientAddressSource === undefined ? {} : { clientAddressSource: options.clientAddressSource }),
    limits: {
      maxMessageBytes: options.maxMessageBytes ?? 64,
      ...(options.maxConnectionsPerWindow === undefined
        ? {}
        : { maxConnectionsPerWindow: options.maxConnectionsPerWindow }),
      maxUpgradeHeaderBytes: 4 * 1024
    }
  });
  const port = await listenOnApprovedTestPort(runningServer.httpsServer);
  return `wss://127.0.0.1:${port}`;
}

function openSocket(url: string, headers: Record<string, string> = {}): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, {
      headers,
      origin: TEST_ORIGIN,
      rejectUnauthorized: false
    });
    socket.once("open", () => resolve(socket));
    socket.once("error", reject);
  });
}

function rejectSocket(url: string, headers: Record<string, string> = {}): Promise<Error> {
  return new Promise((resolve) => {
    const socket = new WebSocket(url, {
      headers,
      origin: TEST_ORIGIN,
      rejectUnauthorized: false
    });
    socket.once("error", (error) => resolve(error));
  });
}

describe("server package", () => {
  it("exports its stable package name", () => {
    expect(packageName).toBe("@remote-codex/server");
    expect(sharedProtocolVersion).toBe(2);
  });
});

describe("受限 HTTPS/WSS 入口", () => {
  it("拒绝禁用全局 TLS 验证的进程配置", () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    expect(() =>
      createTunnelServer({
        tls: testTlsCredentials,
        allowedOrigins: [TEST_ORIGIN]
      })
    ).toThrow("CONFIG_TLS_VERIFICATION_DISABLED");
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  });

  it("显式 TLS 文件缺失时受控失败", async () => {
    await expect(
      loadTlsCredentials({
        certificatePath: "C:\\definitely-missing-certificate.pem",
        privateKeyPath: "C:\\definitely-missing-private-key.pem"
      })
    ).rejects.toMatchObject({ code: "SERVER_TLS_CREDENTIALS_LOAD_FAILED" } satisfies Partial<ServerStartupError>);
  });

  it("启动时严格加载授权文件并拒绝未知 peer 身份", () => {
    expect(() =>
      createTunnelServer({
        tls: testTlsCredentials,
        allowedOrigins: [TEST_ORIGIN],
        peerIdentities: [],
        authorizationDocument: {
          auditVersion: 1,
          authorizations: [
            {
              edgeUserId: "edge-user-unregistered",
              edgeDeviceId: "edge-device-unregistered",
              agentId: "agent-unregistered",
              status: "active",
              quota: { maxConcurrentStreams: 1, maxBufferedBytes: 1024 },
              createdAtMs: 0,
              auditVersion: 1
            }
          ]
        }
      })
    ).toThrow("SERVER_AUTHORIZATION_EDGE_DEVICE_UNKNOWN");
  });

  it("直接 runtime 也拒绝会放宽连接速率的过短窗口", () => {
    expect(() => createTunnelServer({
      tls: testTlsCredentials,
      allowedOrigins: [TEST_ORIGIN],
      limits: { connectionRateWindowMs: 1 }
    })).toThrow("SERVER_TRANSPORT_LIMIT_CONNECTION_RATE_WINDOW_INVALID");
  });

  it("仅在独立健康检查端点返回固定状态", async () => {
    const baseUrl = await startServer();
    const result = await new Promise<{ readonly body: string; readonly statusCode: number | undefined }>(
      (resolve, reject) => {
        const healthRequest = get(`${baseUrl.replace("wss:", "https:")}/health`, { rejectUnauthorized: false }, (response) => {
          let body = "";
          response.setEncoding("utf8");
          response.on("data", (chunk: string) => {
            body += chunk;
          });
          response.on("end", () => resolve({ body, statusCode: response.statusCode }));
        });
        healthRequest.once("error", reject);
      }
    );

    expect(result).toEqual({ body: "{\"status\":\"ok\"}", statusCode: 200 });

    const wrongMethod = await new Promise<number | undefined>((resolve, reject) => {
      const healthRequest = request(
        `${baseUrl.replace("wss:", "https:")}/health`,
        { method: "POST", rejectUnauthorized: false },
        (response) => resolve(response.statusCode)
      );
      healthRequest.once("error", reject);
      healthRequest.end();
    });
    expect(wrongMethod).toBe(405);
  });

  it("拒绝未使用 TLS 的请求", async () => {
    const baseUrl = await startServer();
    const port = Number(new URL(baseUrl).port);
    const failure = await new Promise<Error>((resolve, reject) => {
      const plainRequest = httpGet({ hostname: "127.0.0.1", port, path: "/health" }, () => {
        reject(new Error("plain HTTP request unexpectedly succeeded"));
      });
      plainRequest.once("error", resolve);
    });

    expect(failure).toBeInstanceOf(Error);
  });

  it("拒绝错误 WebSocket 路径和未明确允许的 Origin", async () => {
    const baseUrl = await startServer();
    expect((await rejectSocket(`${baseUrl}/wrong-path`)).message).toContain("Unexpected server response: 404");

    const originFailure = await new Promise<Error>((resolve) => {
      const socket = new WebSocket(`${baseUrl}/tunnel`, {
        origin: "https://untrusted.example.test",
        rejectUnauthorized: false
      });
      socket.once("error", resolve);
    });
    expect(originFailure.message).toContain("Unexpected server response: 403");
  });

  it("拒绝超过升级 headers 上限的 WebSocket 请求", async () => {
    const baseUrl = await startServer();
    expect((await rejectSocket(`${baseUrl}/tunnel`, { "x-padding": "x".repeat(8 * 1024) })).message).toContain(
      "Unexpected server response: 431"
    );
  });

  it("拒绝超过单条消息上限的 WebSocket frame", async () => {
    const baseUrl = await startServer({ maxMessageBytes: 8 });
    const socket = await openSocket(`${baseUrl}/tunnel`);
    const closed = once(socket, "close");
    socket.send(Buffer.alloc(9));
    const [closeCode] = await closed;
    expect(closeCode).toBe(1009);
  });

  it("拒绝低于 TLS 1.3 的连接", async () => {
    const baseUrl = await startServer();
    const failure = await new Promise<Error>((resolve, reject) => {
      const tls12Request = request(
        `${baseUrl.replace("wss:", "https:")}/health`,
        {
          maxVersion: "TLSv1.2",
          minVersion: "TLSv1.2",
          rejectUnauthorized: false
        },
        () => reject(new Error("TLS 1.2 request unexpectedly succeeded"))
      );
      tls12Request.once("error", resolve);
      tls12Request.end();
    });

    expect(failure).toBeInstanceOf(Error);
  });

  it("可在明确配置后接受 TLS 1.2", async () => {
    const baseUrl = await startServer({ tlsMinimumVersion: "TLSv1.2" });
    const statusCode = await new Promise<number | undefined>((resolve, reject) => {
      const tls12Request = request(
        `${baseUrl.replace("wss:", "https:")}/health`,
        {
          maxVersion: "TLSv1.2",
          minVersion: "TLSv1.2",
          rejectUnauthorized: false
        },
        (response) => resolve(response.statusCode)
      );
      tls12Request.once("error", reject);
      tls12Request.end();
    });
    expect(statusCode).toBe(200);
  });

  it("loopback 反代模式要求单个合法 X-Forwarded-For，并按该地址限流", async () => {
    const baseUrl = await startServer({
      clientAddressSource: "loopback-x-forwarded-for",
      maxConnectionsPerWindow: 1
    });
    expect((await rejectSocket(`${baseUrl}/tunnel`)).message).toContain("Unexpected server response: 400");

    const first = await openSocket(`${baseUrl}/tunnel`, { "x-forwarded-for": "198.51.100.10" });
    const firstClosed = new Promise<void>((resolve) => first.once("close", () => resolve()));
    first.close();
    await firstClosed;

    const second = await openSocket(`${baseUrl}/tunnel`, { "x-forwarded-for": "198.51.100.11" });
    second.close();
    expect((await rejectSocket(`${baseUrl}/tunnel`, { "x-forwarded-for": "198.51.100.10" })).message).toContain(
      "Unexpected server response: 429"
    );
    expect((await rejectSocket(`${baseUrl}/tunnel`, { "x-forwarded-for": "198.51.100.10, 198.51.100.12" })).message).toContain(
      "Unexpected server response: 400"
    );
  });
});
