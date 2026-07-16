# Remote Codex

Remote Codex 是供 Codex 使用的受限 HTTPS 出站隧道。它让 edge 机器上的 Codex
经由公司网络中的 `egress-agent` 访问唯一明确批准的模型网关，同时不把公司机器变成
公共入站服务。

本项目与 `remote-client` 完全独立：不得共享地址、域名、部署、用户身份、密钥、凭据、
数据库或运行时依赖。

## 当前实现状态

`shared` 已提供二进制帧、目标验证、身份认证、capability 和流控的共享契约；`server`
已实现受控 HTTPS/WSS 入口、peer 认证、授权注册表、stream 授权中继、四维资源限额和
进程内指标。`edge-client` 与 `egress-agent` 的实际代理、拨号和端到端集成仍属于后续
阶段，当前不应将本仓库视为可直接部署的完整隧道。

目标拓扑如下。两类 peer 均主动连接公共 `server`；公司机器不接受来自互联网的入站
连接。

```text
edge 机器上的 Codex CLI
  -> edge-client 的 127.0.0.1 本地代理
  -> server 的 WSS /tunnel
  -> egress-agent 发起的 WSS 连接
  -> 已批准模型网关的 HTTPS:443
```

## Server 职责

`server` 是认证和授权后的二进制 WebSocket 帧 broker。它：

- 只提供 HTTPS 上的 `GET /health` 和受严格 `Origin` 策略保护的 WSS `/tunnel`。
- 对 edge device 与 egress agent 执行挑战签名认证，并维护短生命周期 peer session。
- 依据显式 `edgeUserId`、`edgeDeviceId` 到 `agentId` 的授权记录决定路由；多个已授权
  的用户和设备可以共享同一 agent。
- 为每条获准 stream 分配内部 stream ID、签发短期 capability，并按 stream 所有权中继
  `open`、`data`、`credit` 和 `close` 帧。
- 在授权、用户、设备、共享 agent 和全局五个层次限制并发流和缓冲字节，并限制开流频率。
- 输出字段白名单审计记录，以及仅供宿主进程读取的聚合指标快照。

`server` 不建立模型网关或其他目标的 TCP 连接，不终止或解密目标 HTTPS，也不暴露
SOCKS、HTTP CONNECT、通用 TCP 转发、指标 HTTP 接口、管理 API 或管理 shell。

## 必要配置类别

当前 `server` 是由宿主程序调用 `createTunnelServer` 创建的运行时库，并未提供命令行
部署入口。部署集成必须通过受控的进程配置注入下列类别；不得从 WSS 请求、日志或其他
项目读取它们。

| 类别 | 用途与要求 |
| --- | --- |
| TLS 服务端材料 | 提供 HTTPS 证书和私钥；可使用 `loadTlsCredentials` 从明确路径加载。TLS 最低版本为 1.3，且不能设置 `NODE_TLS_REJECT_UNAUTHORIZED=0`。 |
| Origin 与传输限额 | 指定精确 HTTPS Origin 白名单，以及握手、头部、消息大小和连接速率上限。空白 Origin 策略会使启动失败。 |
| 可信 peer 身份 | 在创建 server 时登记独立的 edge-device 与 egress-agent Ed25519 公钥身份，可按设备或 agent 设置过期时间。私钥只保留在各自 peer 的受保护存储中。 |
| 授权注册表 | 注入单调递增 `auditVersion` 的 `AuthorizationRegistryDocument`，保存 user/device 到 agent 的显式绑定、状态、配额和审计时间。 |
| capability 签名身份 | 注入 server 专用 Ed25519 签名私钥及相应公钥身份；该密钥不得复用为 peer 认证密钥。 |
| 目标与资源限额 | 注入唯一 `allowedDestination`（端口固定为 `443`）、生命周期限额，以及 user/device/agent/global 的 stream 配额。server 端验证是纵深防御，egress-agent 仍须在拨号前再次验证。 |
| 审计与监控适配器 | 可接收 server 已序列化的白名单审计 JSON，或在受控宿主内调用 `getMetrics()`；不得将原始 WebSocket frame 交给日志系统。 |

配置中的身份、授权、TLS 与签名材料必须分开保存、最小权限读取并独立轮换。配置示例和
日志示例不得包含 token、私钥、证书正文、capability、授权头、cookie、请求 payload，或
任何可连接到 `remote-client` 的信息。

除授权注册表外，当前运行时没有 TLS、peer 身份或 capability 签名身份的热替换接口；这些
材料变更必须经受控的宿主重建/重启完成。重启会关闭现有 stream，且不会在新会话恢复旧流。

## 多用户共享 Agent

共享 agent 不是共享身份或共享 stream。每条有效授权以
`(edgeUserId, edgeDeviceId, agentId)` 为边界；同一 edge user/device 同时只能有一条
`active` agent 路由，而不同已授权 user/device 可以指向同一个在线 agent。

server 为每条 stream 分配与 edge 原始 ID 不同的内部 ID，capability 精确绑定 user、
device、agent、内部 ID、批准目标和过期时间。它分别追踪授权、用户、设备、agent 和全局
的计数、字节和开流速率；错误 peer、错误 ID 或未打开的流都会被拒绝。审计条目也保留各
自的身份和 stream 元数据，不记录任何流内容。

## 运维边界

授权登记、撤销、agent 下线和密钥轮换必须走受控变更流程，不存在可通过公网调用的管理
接口。授权热更新通过宿主进程持有的 `AuthorizationRegistry` 完成；只有完整候选文档通过
校验、`auditVersion` 单调递增后才会原子替换。受影响的活跃 stream 会关闭。

受控操作的详细顺序、capability 字段、审计允许字段和验收项见
[架构文档](docs/architecture.md)。共享契约和线协议见
[共享契约](docs/shared-contract.md)。

## 开发检查

仓库要求 Node.js `>=22 <23` 与 pnpm `>=10 <11`。可使用以下检查验证当前已实现的
共享库和 server：

```powershell
corepack pnpm lint
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
```

这些检查不代表 edge-client 到 egress-agent 的端到端能力已经完成。完整网络验收必须在
后续端实现后验证：只可到达批准网关、非批准 hostname/IP/端口被 egress-agent 拒绝、edge
监听器严格只绑定 `127.0.0.1`，以及 WSS 断线后不会恢复陈旧 stream。
