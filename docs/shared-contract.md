# Shared 共享契约

本文是 `@remote-codex/shared` 的稳定消费契约。`server`、`egress-agent` 和
`edge-client` 只能通过包根入口 `@remote-codex/shared` 导入；不得引用
`@remote-codex/shared/dist/*`、源文件路径或任一组件的私有实现。

该库不建立网络连接、不保存真实凭据，也不依赖 `remote-client` 或任一运行组件。
运行组件不能被 `shared` 反向依赖。

## 公开范围

包根入口只公开以下领域的类型、常量、错误和函数：

| 领域 | 消费者 | 公开能力 |
| --- | --- | --- |
| 配置和限额 | 三个组件 | `parse*Config`、`parseResourceLimits`、默认值与 TLS 校验 |
| 目标验证 | server、egress-agent、edge-client | `normalizeHostname`、`validateDestination` |
| 二进制协议 | 三个组件 | 帧常量、payload 编解码、envelope 编解码、错误码 |
| 流状态和背压 | 三个组件 | `StreamLifecycle`、`StreamBufferBudget`、credit 默认值 |
| 身份和能力凭据 | server、egress-agent、edge-client | 角色化 Ed25519 密钥、挑战认证、capability 签发和验证 |

未在根入口导出的模块成员属于内部实现，不能成为运行组件的依赖。组件只能在各自
`package.json` 中声明 `@remote-codex/shared: workspace:*` 的共享库依赖；不得依赖
其他运行组件。

## 帧 Envelope

每条 WebSocket message 恰好携带一帧。首部固定为 24 字节，依次为：

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 1 | `PROTOCOL_VERSION`，当前为 `2` |
| 1 | 1 | 帧类型 |
| 2 | 2 | flags；当前必须为 `0` |
| 4 | 16 | 128 位 `streamId` |
| 20 | 4 | 无符号大端 payload 长度 |
| 24 | N | payload |

连接级帧必须使用全零 `streamId`；stream 帧必须使用非零 ID。控制帧 payload 最大
`4096` 字节，`stream.data` 最大 `16384` 字节，整体最大 `16408` 字节。解码器先校验
这些界限，再复制外部数据。

## 帧类型

| 值 | 常量 | 级别 | payload |
| --- | --- | --- | --- |
| 1 | `REGISTER` | 连接 | peer 角色、ID、注册随机数 |
| 2 | `CHALLENGE` | 连接 | 挑战随机数、`issuedAtMs`、`expiresAtMs` |
| 3 | `AUTHENTICATE` | 连接 | 挑战随机数、Ed25519 签名 |
| 4 | `HEARTBEAT` | 连接 | sequence |
| 16 | `STREAM_OPEN` | stream | hostname、`443`、capability |
| 17 | `STREAM_OPENED` | stream | 空 |
| 18 | `STREAM_REJECTED` | stream | `TunnelErrorCode` |
| 19 | `STREAM_ERROR` | stream | `TunnelErrorCode` |
| 20 | `STREAM_DATA` | stream | 不透明 TCP 字节 |
| 21 | `STREAM_CREDIT` | stream | 可接收字节数 |
| 22 | `STREAM_CLOSE` | stream | `StreamCloseCode` |

`STREAM_DATA` 的 payload 是 HTTPS/TCP 字节，日志不得记录其内容。未知类型、错误版本、
非零 flags、长度不符、错误 stream ID 或格式错误 payload 都必须作为协议错误拒绝。

## 稳定错误码

| 分类 | 错误码 |
| --- | --- |
| 认证 | `AUTH_FAILED`、`AUTH_EXPIRED`、`AUTH_REPLAYED`、`AUTH_UNAUTHORIZED` |
| 授权与目标 | `CAPABILITY_INVALID`、`DESTINATION_REJECTED`、`STREAM_LIMIT_EXCEEDED` |
| 连接与超时 | `CONNECT_FAILED`、`OPEN_TIMEOUT`、`IDLE_TIMEOUT`、`PEER_DISCONNECTED` |
| 协议与资源 | `FLOW_CONTROL_VIOLATION`、`PROTOCOL_VIOLATION`、`INTERNAL_ERROR` |

`StreamCloseCode` 为 `NORMAL`、`PEER_DISCONNECTED`、`OPEN_TIMEOUT`、`IDLE_TIMEOUT`、
`PROTOCOL_ERROR`、`RESOURCE_LIMIT`、`DESTINATION_REJECTED`、`CONNECT_FAILED`。对外错误
不得携带目标 TLS 内容、请求 payload、cookie、token 或密钥细节。

## 状态和背压

```text
requested -> authorized -> connecting -> open -> closing -> closed
                         \-> rejected
                         \-> failed
```

`STREAM_OPEN` 仅可使 `requested` 流等待授权；通过 capability 后显式进入
`authorized`，开始 TCP 拨号时进入 `connecting`，收到 `STREAM_OPENED` 才进入 `open`。
乱序帧只关闭其所属 stream。`close` 幂等；WSS session 断开立即进入 `closed`，不支持
在新 session 恢复旧 TCP stream。

每端以 `STREAM_CREDIT` 授予对方读取上限。credit 用尽、单流缓冲满或 session 聚合缓冲
满时，调用方必须暂停生产端读取。`StreamBufferBudget` 必须由同一 WSS session 的各流共享。

## 默认限额

所有部署覆盖只能收紧以下默认值，不能放宽：

| 字段 | 默认值 |
| --- | ---: |
| `maxConcurrentStreams` | 32 |
| `maxBufferedBytesPerStream` | 262144 |
| `maxAggregateBufferedBytes` | 8388608 |
| `maxFramePayloadBytes` | 16384 |
| `maxIdleMs` | 120000 |
| `connectTimeoutMs` | 10000 |
| `openTimeoutMs` | 15000 |
| `heartbeatIntervalMs` | 15000 |
| `heartbeatTimeoutMs` | 45000 |
| `reconnectInitialMs` | 1000 |
| `reconnectMaxMs` | 30000 |
| `maxReconnectAttempts` | 12 |
| `DEFAULT_INITIAL_RECEIVE_CREDIT_BYTES` | 65536 |

关系约束：frame 不得大于单流缓冲，单流缓冲不得大于聚合缓冲，连接超时不得大于打开
超时，打开超时不得大于空闲超时，心跳间隔必须小于心跳超时，重连初始值不得大于最大值。

## 配置字段

配置解析拒绝未知字段、空字符串、错误类型和超出默认值的限额。三个组件均要求
`component`、其身份字段、`allowedDestination` 和可选的 `limits`；`serverUrl` 只接受
不含凭据、查询或 fragment 的 `wss:` URL。认证私钥不属于 JSON 配置，必须由运行时的
独立受保护输入提供。

| 组件 | 必填字段 | 可选字段 |
| --- | --- | --- |
| `server` | `component`、`serverId`、`allowedDestination` | `limits` |
| `egress-agent` | `component`、`agentId`、`serverUrl`、`allowedDestination` | `limits` |
| `edge-client` | `component`、`edgeUserId`、`edgeDeviceId`、`serverUrl`、`allowedDestination` | `listenHost`、`listenPort`、`limits` |

默认 `allowedDestination` 为 `ai-coding-bj-pub.singularity-ai.com:443`。目标验证会将 hostname
规范化为 ASCII 小写后精确比较，拒绝 IP literal、通配符、尾点、userinfo、路径、查询、
fragment 和所有非 `443` 端口。`edge-client.listenHost` 只允许 `127.0.0.1`；IPv6 `::1`、
局域网与公网监听地址均被拒绝。

## 身份和 Capability

edge 设备、egress agent、server capability 签名各自使用不同 `IdentityKeyRole` 的 Ed25519
密钥。认证挑战默认最长有效期为 60 秒，`CHALLENGE` wire payload 中的 `nonce`、
`issuedAtMs` 和 `expiresAtMs` 都是认证签名输入；peer 不得猜测签发时间。验证签名成功后才
消耗 nonce。server 签发的 capability 同样最长有效 60 秒，并精确绑定 `edgeUserId`、
`edgeDeviceId`、`agentId`、`streamId`、hostname 和端口。egress-agent 在 TCP 拨号前必须
验证 capability 并再次调用 `validateDestination`；capability 只能消费一次。
