# Remote Codex

Remote Codex 是供 Codex 使用的受限 HTTPS 出站隧道。它让 edge 机器上的 Codex
经由公司网络中的 `egress-agent` 访问唯一已批准的模型网关，同时不把公司机器变成
公共入站服务。

本项目不是远程桌面、远程 shell、终端中继、文件管理器、VPN 或通用代理。它与
`remote-client` 完全独立：不得共享地址、域名、部署、用户身份、密钥、凭据、数据库或
运行时依赖。

## 组件与边界

```text
edge 机器上的 Codex CLI
  -> edge-client 的 HTTP CONNECT：127.0.0.1:<port>
  -> server 的 WSS /tunnel
  -> egress-agent 的受认证 WSS 会话
  -> 已批准模型网关的 HTTPS:443
```

- `edge-client` 是本地 HTTP CONNECT 前端和受认证 WSS 客户端。它只监听 IPv4
  loopback `127.0.0.1`，只接受 `CONNECT <hostname>:443 HTTP/1.1`。
- `server` 认证 peer，依据授权注册表将 edge user/device 路由到一个已授权的 agent，
  签发仅供 agent 使用的短期 capability，并中继二进制 WSS stream。它不建立目标 TCP
  连接。
- `egress-agent` 只建立到 server 的出站 WSS 和到精确批准 `hostname:443` 的出站 TCP
  连接。它没有 TCP、HTTP 或管理监听器。

一个 agent 可服务多个 edge 用户或设备，但不共享身份或 stream。唯一的路由来源是
server 授权注册表中的 active `(edgeUserId, edgeDeviceId) -> agentId` 记录；每条 stream
仍单独认证、授权、限额和清理。

生产进程由 `server-host`、`egress-agent-host`、`edge-client-host` 分别组合运行库与受保护配置。
`ops` 只执行离线身份、授权、bundle 和 release 操作。Public Server 的 TLS/WSS 是唯一公开入口；
Agent 没有入站面；Edge 只有 `127.0.0.1:<8000-9000>` CONNECT listener。Public Server 和两端
WSS 使用显式 `8000-9000` 端口，模型网关仍只允许精确 hostname 的出站 `443`。

## 协议与身份

当前 `protocolVersion` 为 `2`。每条 WebSocket message 是一帧小型二进制 envelope：首部包含版本、
类型、flags、128 位 stream ID 和 payload 长度；连接帧使用全零 stream ID，数据帧使用非零 ID。
不同版本、未知类型/flags、超长或格式错误帧会直接拒绝，没有协议降级协商。

Edge device 与 Egress Agent 各自用独立 Ed25519 身份响应 Server challenge。Server 认证 peer 后按
active user/device -> agent ACL 授权每条 stream，再用独立 signing key 签发短期、一次消费且精确
绑定 user、device、agent、stream ID、hostname:443 的 capability。Agent 在 TCP 拨号前验证签名、
有效期、绑定与本地 allowlist，因而 Server 端验证不是最终执行点。

## 启动前置条件

本仓库提供运行时库、不建立网络连接的离线运维 CLI，以及 server、agent、edge 的受控生产
启动器。各 host 只加载所属配置和独立受保护身份材料；Windows agent/edge 使用当前普通用户的
登录任务。生产按下列顺序管理：

1. 启动 `server-host`，登记 edge device、Egress Agent 公钥身份和授权注册表。
2. 启动 `egress-agent-host`，等待其完成 WSS 认证并在线。
3. 启动 `edge-client-host`。host 先创建固定 `127.0.0.1` 的受限 CONNECT listener，再启动 Edge
   WSS runtime；离线、认证中或重连期间的 CONNECT 只返回固定失败，不排队、不直连模型网关，
   也不放宽或改选 Agent。
4. 状态脚本确认 Edge WSS 在线、唯一 loopback listener 存在且没有额外连接后，才让 Codex 当前
   shell 使用 `HTTPS_PROXY`。

公开入口包括 `loadEdgeClientConfig`、`EdgeClientRuntime`、`LoopbackConnectProxy`、
`loadEgressAgentConfig`、`EgressAgentRuntime` 和 `EgressAgentDialer`。认证私钥通过这些
runtime 的独立受控输入提供，不能写入 JSON 配置、环境展示文本或 URL。安全配置结构见
[配置示例](docs/configuration-example.md)。

`@remote-codex/ops` 可生成分角色 Ed25519 材料、校验三组件生产 manifest、原子变更共享
agent 授权并复核连续审计版本；它不会启动监听器、建立网络连接或输出密钥正文。位置、权限、
轮换、撤销和灾难替换流程见[生产配置、身份与授权操作](docs/operations/identity-and-authorization.md)，
无秘密样例位于 `deployment/examples/`。

Public Server 使用直接 TLS，唯一公开 WSS URL 为
`wss://<publicHostname>:<8000-9000 内端口>/tunnel`，同一 listener 只额外提供无凭据
`GET /health`。样例端口为 `8443`，不开放 `80`、`443`、管理或 metrics endpoint。Linux
`systemd` 单元、证书 DNS-01/预置续期与安全 reload、外网手工检查和回滚流程见
[Public Server 部署与加固](docs/operations/public-server-deployment.md)。

Windows Edge Client 的独立设备材料、最低权限登录任务、会话级 `HTTPS_PROXY`、loopback 手工
验收和安全错误收集见 [Windows Edge Client 用户接入](docs/operations/windows-edge-client-deployment.md)。
所有运维入口见[运维文档索引](docs/operations/README.md)；版本化 production allowlist、逐文件
SHA-256 inventory、升级顺序和安全回滚见[发布、升级与回滚](docs/operations/release-and-rollback.md)。

## 源码联调启动

为三台机器从同一受控 Git commit 进行前台联调，根 `package.json` 提供以下快捷命令：

```powershell
$env:REMOTE_CODEX_CONFIG_ROOT = "C:\RemoteCodex\server-test"
corepack pnpm start:server

$env:REMOTE_CODEX_CONFIG_ROOT = "$env:LOCALAPPDATA\RemoteCodex\egress-agent-test"
corepack pnpm start:agent

$env:REMOTE_CODEX_CONFIG_ROOT = "$env:LOCALAPPDATA\RemoteCodex\edge-client-test"
corepack pnpm start:edge
```

Linux 上使用相同的 `REMOTE_CODEX_CONFIG_ROOT` 和 `corepack pnpm start:server` 命令。每个 `start:*`
都会先构建 workspace，再以前台子进程启动对应的 host CLI；`Ctrl+C` 会转发给该进程。可选的
`REMOTE_CODEX_MANIFEST` 只用于指定配置根内的 manifest 文件名，默认是 `manifest.json`。

配置根必须位于仓库外，且在启动前已通过 `ops deployment validate`；其中包含该角色的 manifest、
配置、独立身份材料和必要公钥。Server 还需要 TLS 材料、peer registry 与授权注册表。快捷命令不
创建身份、不生成配置、不放宽 TLS、目标验证或 listener 约束，也不替代正式 release、systemd 或
Windows 当前用户任务部署。

## Codex 接入

在启动 edge runtime 和本地代理后，将当前 PowerShell 会话的 `HTTPS_PROXY` 指向实际
监听端口。例如本地代理监听 `127.0.0.1:8787` 时：

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:8787"
codex
```

代理 URL 必须是 `http://127.0.0.1:<port>`：不得使用局域网或公网地址、`::1`、用户名、
密码、token、查询参数或 fragment。`HTTPS_PROXY` 只在需要本隧道的 shell 会话中设置；
使用结束后可清除它：

```powershell
Remove-Item Env:HTTPS_PROXY
```

该 CONNECT 代理只为批准的模型网关服务。若 edge runtime 未在线、本地代理未监听、目标
不等于已配置的 hostname:443，或 server/agent 拒绝 stream，连接会失败而不会回退到其他
路由。

## 明确不支持的能力

- SOCKS5、普通 HTTP 转发、absolute URL、HTTP/HTTPS proxy auth、`Upgrade`、请求 body 或
  CONNECT 请求后的额外字节。
- IPv6、局域网或公网 edge listener；edge 只可绑定 `127.0.0.1`。
- DNS 放宽、IP literal、通配符主机、重定向、非 `443` 端口和任意 TCP 目标。
- remote desktop、shell、VPN、文件管理、管理 API 或公网控制面。

TLS 应用内容从 Codex 到已批准模型网关端到端保持不透明。server 和 egress-agent 不终止、
检查、修改或记录 TLS plaintext；日志只允许记录经白名单筛选的 stream 元数据。

## 开发检查

仓库要求 Node.js `>=22 <23` 与 pnpm `>=10 <11`。在受控开发环境中运行：

```powershell
corepack pnpm lint
corepack pnpm typecheck
corepack pnpm test:without-e2e
corepack pnpm build
```

也可运行 `corepack pnpm verify:repository-without-e2e` 执行以上四项。该入口明确排除
`server/src/end-to-end.test.ts`，只适用于真实联调暂缓时的仓库验证，不能归档为完整 E2E 或发布
验收。完整 `corepack pnpm test`、真实 WSS/公司网关路径、非 loopback 负向访问以及预生产发布与
回滚必须由部署负责人在隔离环境手工完成。

网络验收还必须确认：请求只到达已批准网关；不同 hostname、IP literal 和非 `443` 端口在
egress-agent 的最终验证处失败；非 loopback 无法访问 edge 代理；WSS 断开会关闭旧 stream
并仅在重新认证后允许新流；日志不含 payload 或凭据。协议与资源契约见
[共享契约](docs/shared-contract.md)，详细信任边界见[架构文档](docs/architecture.md)。

自动测试已覆盖协议版本拒绝、认证/capability、目标验证、授权、stream 清理、背压、重连状态机、
loopback 配置、host bundle、安全日志与 release fail-closed 规则；它不证明实际 DNS/TLS、公司出口、
网关侧来源、主机防火墙、任务计划/systemd 状态或真实 Codex 请求已验收。
