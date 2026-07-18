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

## 启动前置条件

本仓库提供运行时库和不建立网络连接的离线运维 CLI，暂不提供运行时部署启动器。受控宿主
负责加载配置、TLS 材料和独立的受保护私钥，并按下列顺序管理运行时：

1. 创建并运行 server，登记 edge 设备、egress agent 的公钥身份以及授权注册表。
2. 用 `EgressAgentRuntime` 启动 agent，等待其完成 WSS 认证并在线。
3. 用 `EdgeClientRuntime` 启动 edge runtime，等待其状态为 `online`。
4. 以该 runtime 作为 `LoopbackConnectProxy` 的 `streamGateway` 创建本地代理，并调用
   `start()`。`LoopbackConnectProxy` 固定监听 `127.0.0.1`；生产端口应取
   `EdgeClientConfig.listenPort`。
5. 仅在 edge runtime 在线且本地代理已成功监听后，才让 Codex 使用 `HTTPS_PROXY`。

公开入口包括 `loadEdgeClientConfig`、`EdgeClientRuntime`、`LoopbackConnectProxy`、
`loadEgressAgentConfig`、`EgressAgentRuntime` 和 `EgressAgentDialer`。认证私钥通过这些
runtime 的独立受控输入提供，不能写入 JSON 配置、环境展示文本或 URL。安全配置结构见
[配置示例](docs/configuration-example.md)。

`@remote-codex/ops` 可生成分角色 Ed25519 材料、校验三组件生产 manifest、原子变更共享
agent 授权并复核连续审计版本；它不会启动监听器、建立网络连接或输出密钥正文。位置、权限、
轮换、撤销和灾难替换流程见[生产配置、身份与授权操作](docs/operations/identity-and-authorization.md)，
无秘密样例位于 `deployment/examples/`。

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
corepack pnpm test
corepack pnpm build
```

网络验收还必须确认：请求只到达已批准网关；不同 hostname、IP literal 和非 `443` 端口在
egress-agent 的最终验证处失败；非 loopback 无法访问 edge 代理；WSS 断开会关闭旧 stream
并仅在重新认证后允许新流；日志不含 payload 或凭据。协议与资源契约见
[共享契约](docs/shared-contract.md)，详细信任边界见[架构文档](docs/architecture.md)。
