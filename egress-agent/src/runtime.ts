import { randomBytes as nodeRandomBytes } from "node:crypto";

import {
  assertTlsVerificationEnabled,
  connectionFrame,
  decodeChallengePayload,
  decodeFrame,
  decodeFramePayload,
  encodeAuthenticatePayload,
  encodeFrame,
  encodeHeartbeatPayload,
  encodeRegisterPayload,
  FrameType,
  IdentityKeyRole,
  parseEgressAgentConfig,
  signAuthenticationChallenge,
  type EgressAgentConfig,
  type EgressAgentIdentity,
  type IdentityPrivateKey,
  type RegisterPayload
} from "@remote-codex/shared";
import WebSocket from "ws";
import type { RawData } from "ws";

const WEBSOCKET_CLOSE_CODE_PROTOCOL = 1002;
const AUTHENTICATION_FAILURE_CODES = new Set(["AUTH_FAILED", "AUTH_EXPIRED", "AUTH_REPLAYED", "AUTH_UNAUTHORIZED"]);

export type EgressAgentState = "offline" | "connecting" | "authenticating" | "online" | "backoff" | "stopped";

export interface EgressAgentStatusSnapshot {
  readonly state: EgressAgentState;
  readonly reconnectAttempts: number;
  readonly lastErrorCode?: string;
}

export type EgressAgentStatusListener = (status: EgressAgentStatusSnapshot) => void;

/**
 * 阶段 2 的拨号器会实现此接口。会话失效时必须停止读取并销毁所有关联 TCP
 * socket，且清空 stream 到 socket 的映射。此阶段只调用该清理边界，不创建 TCP
 * 连接。
 */
export interface EgressAgentStreamResources {
  closeAll(): void;
}

export interface AgentSocket {
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  onOpen(listener: () => void): void;
  onMessage(listener: (data: Uint8Array | undefined, isBinary: boolean) => void): void;
  onClose(listener: (code: number, reason: string) => void): void;
  onError(listener: () => void): void;
}

export interface AgentSocketFactory {
  connect(serverUrl: URL, origin: string): AgentSocket;
}

export interface EgressAgentRuntimeOptions {
  /** 已由本地部署加载并严格解析的配置，不能由任何 stream 帧覆盖。 */
  readonly config: EgressAgentConfig;
  /** agent 专用的公钥身份，必须与本地 agentId 完全一致。 */
  readonly authenticationIdentity: EgressAgentIdentity;
  /** agent 专用私钥，仅用于对服务端 challenge 签名。 */
  readonly authenticationKey: IdentityPrivateKey<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
  /** 由本地部署配置的 HTTPS Origin；不得从服务端或 stream 读取。 */
  readonly origin: string;
  readonly streamResources?: EgressAgentStreamResources;
  readonly socketFactory?: AgentSocketFactory;
  readonly now?: () => number;
  readonly random?: () => number;
  readonly randomBytes?: (size: number) => Uint8Array;
}

interface ConnectionFailure {
  readonly code: string;
  readonly terminal: boolean;
}

type ConnectionPhase = "connecting" | "awaiting-challenge" | "awaiting-confirmation" | "online";

interface AgentConnection {
  readonly socket: AgentSocket;
  phase: ConnectionPhase;
  registration: RegisterPayload | undefined;
  failure: ConnectionFailure | undefined;
  finalized: boolean;
}

export class EgressAgentRuntimeError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "EgressAgentRuntimeError";
  }
}

function fail(code: string): never {
  throw new EgressAgentRuntimeError(code);
}

function rawDataToBytes(data: RawData): Uint8Array | undefined {
  if (data instanceof Buffer) {
    return Uint8Array.from(data);
  }

  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data.slice(0));
  }

  if (Array.isArray(data)) {
    return Uint8Array.from(Buffer.concat(data));
  }

  return undefined;
}

function safeCloseReason(reason: Buffer): string {
  const decoded = reason.toString("utf8");
  return /^[A-Z_]{1,64}$/u.test(decoded) ? decoded : "WSS_DISCONNECTED";
}

class WsAgentSocket implements AgentSocket {
  public constructor(private readonly socket: WebSocket) {}

  public send(data: Uint8Array): void {
    this.socket.send(data, { binary: true });
  }

  public close(code?: number, reason?: string): void {
    this.socket.close(code, reason);
  }

  public onOpen(listener: () => void): void {
    this.socket.once("open", listener);
  }

  public onMessage(listener: (data: Uint8Array | undefined, isBinary: boolean) => void): void {
    this.socket.on("message", (data: RawData, isBinary: boolean) => listener(rawDataToBytes(data), isBinary));
  }

  public onClose(listener: (code: number, reason: string) => void): void {
    this.socket.once("close", (code: number, reason: Buffer) => listener(code, safeCloseReason(reason)));
  }

  public onError(listener: () => void): void {
    this.socket.once("error", listener);
  }
}

class DefaultAgentSocketFactory implements AgentSocketFactory {
  public connect(serverUrl: URL, origin: string): AgentSocket {
    return new WsAgentSocket(new WebSocket(serverUrl, { origin, perMessageDeflate: false }));
  }
}

function parseOrigin(origin: string): string {
  let parsed: URL;

  try {
    parsed = new URL(origin);
  } catch {
    return fail("AGENT_ORIGIN_INVALID");
  }

  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== origin ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.search.length > 0 ||
    parsed.hash.length > 0
  ) {
    return fail("AGENT_ORIGIN_INVALID");
  }

  return origin;
}

function normalizedConfig(config: EgressAgentConfig): EgressAgentConfig {
  return parseEgressAgentConfig({
    component: config.component,
    agentId: config.agentId,
    serverUrl: config.serverUrl.href,
    allowedDestination: {
      hostname: config.allowedDestination.hostname,
      port: config.allowedDestination.port
    },
    limits: { ...config.limits }
  });
}

function closeCodeIsAuthenticationFailure(code: string): boolean {
  return AUTHENTICATION_FAILURE_CODES.has(code);
}

function timerUnref(timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>): void {
  if (typeof timer === "object" && "unref" in timer && typeof timer.unref === "function") {
    timer.unref();
  }
}

/** 计算上限受配置约束的指数退避，含 [50%, 100%] 的等比例抖动。 */
export function calculateReconnectDelayMs(
  reconnectAttempt: number,
  limits: Pick<EgressAgentConfig["limits"], "reconnectInitialMs" | "reconnectMaxMs">,
  random: () => number = Math.random
): number {
  if (!Number.isSafeInteger(reconnectAttempt) || reconnectAttempt < 1) {
    return fail("AGENT_RECONNECT_ATTEMPT_INVALID");
  }

  const randomValue = random();
  if (!Number.isFinite(randomValue) || randomValue < 0 || randomValue > 1) {
    return fail("AGENT_RECONNECT_JITTER_INVALID");
  }

  const exponent = reconnectAttempt - 1;
  const uncappedDelay =
    exponent > 52 ? Number.MAX_SAFE_INTEGER : limits.reconnectInitialMs * 2 ** exponent;
  const cappedDelay = Math.min(limits.reconnectMaxMs, uncappedDelay);
  return Math.max(1, Math.floor(cappedDelay * (0.5 + randomValue * 0.5)));
}

/** 从本地配置文本加载 agent 配置。认证私钥始终通过独立 options 注入。 */
export function loadEgressAgentConfig(serializedConfig: string): EgressAgentConfig {
  try {
    return parseEgressAgentConfig(JSON.parse(serializedConfig) as unknown);
  } catch (error: unknown) {
    if (error instanceof EgressAgentRuntimeError) {
      throw error;
    }

    return fail("AGENT_CONFIG_LOAD_FAILED");
  }
}

/**
 * 只维护 egress agent 到 server 的受认证 WSS 会话。它没有 TCP listener，且本
 * 阶段不会建立任何目标 TCP 连接。
 */
export class EgressAgentRuntime {
  private readonly config: EgressAgentConfig;
  private readonly authenticationIdentity: EgressAgentIdentity;
  private readonly authenticationKey: IdentityPrivateKey<typeof IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION>;
  private readonly origin: string;
  private readonly streamResources: EgressAgentStreamResources;
  private readonly socketFactory: AgentSocketFactory;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly randomBytes: (size: number) => Uint8Array;
  private readonly statusListeners = new Set<EgressAgentStatusListener>();
  private activeConnection: AgentConnection | undefined;
  private heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  private reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  private state: EgressAgentState = "offline";
  private reconnectAttempts = 0;
  private lastErrorCode: string | undefined;
  private stopped = false;
  private heartbeatSequence = 0;

  public constructor(options: EgressAgentRuntimeOptions) {
    this.config = normalizedConfig(options.config);
    this.authenticationIdentity = options.authenticationIdentity;
    this.authenticationKey = options.authenticationKey;
    this.origin = parseOrigin(options.origin);
    this.streamResources = options.streamResources ?? { closeAll: () => undefined };
    this.socketFactory = options.socketFactory ?? new DefaultAgentSocketFactory();
    this.now = options.now ?? Date.now;
    this.random = options.random ?? Math.random;
    this.randomBytes = options.randomBytes ?? ((size: number) => Uint8Array.from(nodeRandomBytes(size)));

    if (
      this.authenticationIdentity.kind !== "egress-agent" ||
      this.authenticationIdentity.agentId !== this.config.agentId ||
      this.authenticationKey.role !== IdentityKeyRole.EGRESS_AGENT_AUTHENTICATION
    ) {
      fail("AGENT_SERVICE_IDENTITY_INVALID");
    }
  }

  /** 启动是幂等的；配置或 TLS 校验失败会在建立 WSS 前直接失败。 */
  public start(): void {
    if (this.stopped) {
      fail("AGENT_RUNTIME_STOPPED");
    }

    if (this.activeConnection !== undefined || this.reconnectTimer !== undefined) {
      return;
    }

    assertTlsVerificationEnabled(process.env);
    this.connect();
  }

  /** 停止所有重连、心跳及已绑定的 stream 资源；停止后的实例不允许复用。 */
  public stop(): void {
    if (this.stopped) {
      return;
    }

    this.stopped = true;
    this.clearReconnectTimer();
    this.clearHeartbeatTimer();
    const connection = this.activeConnection;
    this.activeConnection = undefined;

    if (connection !== undefined) {
      connection.finalized = true;
      try {
        connection.socket.close();
      } catch {
        // socket 已经处于关闭状态时仍须继续清理本地 stream 资源。
      }
    }

    const cleanupSucceeded = this.closeAllStreams();
    this.transition("stopped", cleanupSucceeded ? undefined : "AGENT_STREAM_CLEANUP_FAILED");
  }

  public getStatus(): EgressAgentStatusSnapshot {
    return Object.freeze({
      state: this.state,
      reconnectAttempts: this.reconnectAttempts,
      ...(this.lastErrorCode === undefined ? {} : { lastErrorCode: this.lastErrorCode })
    });
  }

  /** 返回不可变本地策略快照；stream.open 的 hostname、port、agentId 不会改写它。 */
  public getLocalPolicy(): Readonly<{
    agentId: string;
    maxConcurrentStreams: number;
    allowedDestination: Readonly<{ hostname: string; port: 443 }>;
  }> {
    return Object.freeze({
      agentId: this.config.agentId,
      maxConcurrentStreams: this.config.limits.maxConcurrentStreams,
      allowedDestination: Object.freeze({ ...this.config.allowedDestination })
    });
  }

  public subscribeStatus(listener: EgressAgentStatusListener): () => void {
    this.statusListeners.add(listener);
    try {
      listener(this.getStatus());
    } catch {
      // 初始状态订阅者同样不能影响受认证连接或重连状态机。
    }
    return (): void => {
      this.statusListeners.delete(listener);
    };
  }

  private connect(): void {
    if (this.stopped || this.activeConnection !== undefined) {
      return;
    }

    this.transition("connecting");
    let socket: AgentSocket;

    try {
      socket = this.socketFactory.connect(this.config.serverUrl, this.origin);
    } catch {
      this.scheduleReconnect({ code: "WSS_CONNECTION_FAILED", terminal: false });
      return;
    }

    const connection: AgentConnection = {
      socket,
      phase: "connecting",
      registration: undefined,
      failure: undefined,
      finalized: false
    };
    this.activeConnection = connection;
    socket.onOpen(() => this.handleOpen(connection));
    socket.onMessage((data, isBinary) => this.handleMessage(connection, data, isBinary));
    socket.onClose((code, reason) => this.handleClose(connection, code, reason));
    socket.onError(() => this.handleError(connection));
  }

  private handleOpen(connection: AgentConnection): void {
    if (!this.isActive(connection) || connection.phase !== "connecting") {
      return;
    }

    try {
      const registration: RegisterPayload = Object.freeze({
        role: "egress-agent",
        peerId: this.config.agentId,
        nonce: Uint8Array.from(this.randomBytes(32))
      });
      this.send(connection, connectionFrame(FrameType.REGISTER, encodeRegisterPayload(registration)));
      connection.registration = registration;
      connection.phase = "awaiting-challenge";
      this.transition("authenticating");
    } catch {
      this.closeConnection(connection, { code: "AUTH_FAILED", terminal: true });
    }
  }

  private handleMessage(connection: AgentConnection, data: Uint8Array | undefined, isBinary: boolean): void {
    if (!this.isActive(connection)) {
      return;
    }

    if (!isBinary || data === undefined) {
      this.closeConnection(connection, { code: "PROTOCOL_VIOLATION", terminal: false });
      return;
    }

    try {
      const frame = decodeFrame(data);
      const payload = decodeFramePayload(frame);

      if (frame.type === FrameType.CHALLENGE && connection.phase === "awaiting-challenge") {
        const challengePayload = decodeChallengePayload(frame.payload);
        if (challengePayload.issuedAtMs > this.now() || challengePayload.expiresAtMs <= this.now()) {
          throw new EgressAgentRuntimeError("AUTH_EXPIRED");
        }

        const registration = connection.registration;
        if (registration === undefined) {
          throw new EgressAgentRuntimeError("AUTH_FAILED");
        }

        const response = signAuthenticationChallenge({
          identity: this.authenticationIdentity,
          signingKey: this.authenticationKey,
          registration,
          challenge: { issuedAtMs: challengePayload.issuedAtMs, payload: challengePayload }
        });
        this.send(
          connection,
          connectionFrame(FrameType.AUTHENTICATE, encodeAuthenticatePayload(response))
        );
        connection.phase = "awaiting-confirmation";
        return;
      }

      if (frame.type === FrameType.HEARTBEAT && connection.phase === "awaiting-confirmation") {
        if (payload === undefined || !("sequence" in payload)) {
          throw new EgressAgentRuntimeError("PROTOCOL_VIOLATION");
        }

        connection.phase = "online";
        this.heartbeatSequence = payload.sequence;
        this.transition("online");
        this.startHeartbeatTimer(connection);
        return;
      }

      if (frame.type === FrameType.HEARTBEAT && connection.phase === "online") {
        if (payload === undefined || !("sequence" in payload)) {
          throw new EgressAgentRuntimeError("PROTOCOL_VIOLATION");
        }

        return;
      }

      // 拨号和 stream 帧处理属于后续阶段；当前会话绝不因此读取或打开目标连接。
      throw new EgressAgentRuntimeError("PROTOCOL_VIOLATION");
    } catch (error: unknown) {
      const code = error instanceof EgressAgentRuntimeError ? error.code : "PROTOCOL_VIOLATION";
      this.closeConnection(connection, { code, terminal: closeCodeIsAuthenticationFailure(code) });
    }
  }

  private handleError(connection: AgentConnection): void {
    if (!this.isActive(connection)) {
      return;
    }

    this.closeConnection(connection, { code: "WSS_CONNECTION_FAILED", terminal: false });
  }

  private handleClose(connection: AgentConnection, _closeCode: number, reason: string): void {
    if (!this.isActive(connection)) {
      return;
    }

    const failure = connection.failure ?? {
      code: closeCodeIsAuthenticationFailure(reason) ? reason : "WSS_DISCONNECTED",
      terminal: closeCodeIsAuthenticationFailure(reason)
    };
    this.finalizeConnection(connection, failure);
  }

  private closeConnection(connection: AgentConnection, failure: ConnectionFailure): void {
    if (!this.isActive(connection)) {
      return;
    }

    connection.failure = failure;
    try {
      connection.socket.close(WEBSOCKET_CLOSE_CODE_PROTOCOL, failure.code);
    } catch {
      this.finalizeConnection(connection, failure);
    }
  }

  private finalizeConnection(connection: AgentConnection, failure: ConnectionFailure): void {
    if (!this.isActive(connection)) {
      return;
    }

    connection.finalized = true;
    this.activeConnection = undefined;
    this.clearHeartbeatTimer();
    const cleanupSucceeded = this.closeAllStreams();

    if (this.stopped) {
      this.transition("stopped", cleanupSucceeded ? undefined : "AGENT_STREAM_CLEANUP_FAILED");
      return;
    }

    if (!cleanupSucceeded) {
      this.transition("offline", "AGENT_STREAM_CLEANUP_FAILED");
      return;
    }

    this.scheduleReconnect(cleanupSucceeded ? failure : { code: "AGENT_STREAM_CLEANUP_FAILED", terminal: true });
  }

  private scheduleReconnect(failure: ConnectionFailure): void {
    if (this.stopped || failure.terminal) {
      this.transition("offline", failure.code);
      return;
    }

    if (this.reconnectAttempts >= this.config.limits.maxReconnectAttempts) {
      this.transition("offline", "RECONNECT_LIMIT_EXCEEDED");
      return;
    }

    this.reconnectAttempts += 1;
    const delayMs = calculateReconnectDelayMs(this.reconnectAttempts, this.config.limits, this.random);
    this.transition("backoff", failure.code);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect();
    }, delayMs);
    timerUnref(this.reconnectTimer);
  }

  private startHeartbeatTimer(connection: AgentConnection): void {
    this.clearHeartbeatTimer();
    this.heartbeatTimer = setInterval(() => {
      if (!this.isActive(connection) || connection.phase !== "online") {
        return;
      }

      try {
        this.heartbeatSequence = (this.heartbeatSequence + 1) >>> 0;
        this.send(
          connection,
          connectionFrame(FrameType.HEARTBEAT, encodeHeartbeatPayload({ sequence: this.heartbeatSequence }))
        );
      } catch {
        this.closeConnection(connection, { code: "WSS_CONNECTION_FAILED", terminal: false });
      }
    }, this.config.limits.heartbeatIntervalMs);
    timerUnref(this.heartbeatTimer);
  }

  private send(connection: AgentConnection, frame: ReturnType<typeof connectionFrame>): void {
    if (!this.isActive(connection)) {
      return;
    }

    connection.socket.send(encodeFrame(frame));
  }

  private closeAllStreams(): boolean {
    try {
      this.streamResources.closeAll();
      return true;
    } catch {
      return false;
    }
  }

  private clearHeartbeatTimer(): void {
    if (this.heartbeatTimer !== undefined) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== undefined) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
  }

  private isActive(connection: AgentConnection): boolean {
    return !connection.finalized && this.activeConnection === connection;
  }

  private transition(state: EgressAgentState, lastErrorCode?: string): void {
    this.state = state;
    this.lastErrorCode = lastErrorCode;
    const status = this.getStatus();

    for (const listener of this.statusListeners) {
      try {
        listener(status);
      } catch {
        // 状态订阅者不能影响受认证连接或重连状态机。
      }
    }
  }
}
