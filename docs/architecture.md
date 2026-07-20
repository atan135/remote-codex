# Remote Codex 架构

## 范围与拓扑

Remote Codex 是受限 HTTPS 出站隧道，不是远程桌面、远程 shell、终端中继、文件管理器、
VPN 或通用代理。唯一允许的出站目标是部署配置中精确指定的模型网关 hostname 的 `443`
端口。新增目标、协议、监听器或命令执行能力都属于范围变更，必须单独批准。

```text
edge 机器                         公共互联网                         公司网络
+----------------+              +--------------------+            +-----------------+
| Codex CLI      |              | server-host :8443  |            | egress-agent    |
| edge-client    | -- WSS --->  | /health, /tunnel   | <--- WSS -- | 出站 WSS / TCP   |
| 127.0.0.1 only |              | TLS / WSS broker   |            |                 |
+----------------+              +--------------------+            +--------+--------+
                                                                          |
                                                                          | HTTPS:443
                                                                          v
                                                                   已批准模型网关
```

`edge-client` 和 `egress-agent` 都主动连接 server。公司网络不接受来自 edge 或互联网的
入站连接；server 的 HTTPS/WSS endpoint 是唯一可公开暴露的网络面。本项目与
`remote-client` 完全独立，不使用其地址、凭据、数据库、WebSocket endpoint、部署环境或
运行时依赖。

三个生产 host 为 `server-host`、`egress-agent-host`、`edge-client-host`；离线 `ops` 是第四个
production workspace。它们依赖 `shared` 以及各自运行库，但三个运行组件不互相建立运行时依赖。
`server-host` 是唯一公网 listener，固定绑定 `0.0.0.0:8443` 并直接终止 TLS/WSS。Edge 的本地应用
listener 仍固定在 `8000-9000`。网关 `443` 是 Agent 的受限
出站目标，不是应用 listener。

## 二进制协议与身份链

当前 `PROTOCOL_VERSION` 为 `2`。每个 WebSocket message 恰好携带一个二进制帧，固定 24 字节首部
依次为版本、frame type、flags、128 位 stream ID 和 payload 长度。连接级
`REGISTER/CHALLENGE/AUTHENTICATE/HEARTBEAT` 使用全零 stream ID；开流、数据、credit、错误和关闭
帧使用非零 ID。不同版本以 `PROTOCOL_VERSION_UNSUPPORTED` 拒绝，未知 flags/type、错误 ID、长度
或 payload 同样 fail closed；协议没有协商降级或恢复旧 session 的机制。

Edge device、Egress Agent、Server capability signing 使用三个分离的 Ed25519 key role。peer 先
发送角色、ID 与注册 nonce，Server 返回带签发/过期时间的 challenge；peer 对完整签名输入响应，
Agent 只容忍最多 5 秒的本机时钟偏差，Server 校验公钥注册、challenge 有效期和 replay 后才认证
session。Server 根据 active
`(edgeUserId, edgeDeviceId) -> agentId` ACL 选择 Agent，并为每条 stream 签发短期、一次消费且
绑定 user/device/agent/stream/destination 的 capability。Agent 是最终执行点：先验 capability，
再按自身 allowlist 验证 hostname:443，最后才拨号。
Agent 只容忍 capability 的签发时间最多快于本机 5 秒，且仍严格拒绝过期、签名或绑定无效的
capability。

## Server 与共享授权

server 由 `createTunnelServer` 创建，公共面仅包括 `GET /health` 与受 TLS、Origin、头部、
消息大小和速率约束的 WSS `/tunnel`。它认证 edge-device 和 egress-agent，管理 peer
session，按授权注册表中 active `(edgeUserId, edgeDeviceId) -> agentId` 记录选择在线
agent，并为每条获准 stream 创建内部 stream ID 和短期 capability。

多个 edge user/device 可以指向同一个 agent；这只共享 agent 的有限资源，不共享用户身份、
capability 或 stream。server 分别对授权三元组、edge user、edge device、agent 与全局强制
stream 数、缓冲字节和开流速率限制。server 不建立目标 TCP 连接，也不公开 SOCKS、HTTP
CONNECT、通用 TCP 转发、管理 API、指标 HTTP endpoint 或 shell。

生产由独立 `server-host` 进程直接在 `0.0.0.0:8443` 组合 `ops` 受保护 bundle 与
`createTunnelServer` 并终止 TLS。唯一公开 URL 是 `wss://<publicHostname>:8443/tunnel`；仅
`/health` 和 `/tunnel` 可访问，其他路径均为 `404`。Node 以 TCP socket 的对端地址实施连接限流，
不信任 `X-Forwarded-For`。证书通过预置流程或 DNS-01 续期并在 `SIGHUP` 后安全 reload；host 配置、
Origin、TLS 下限、代理地址来源或资源限制变化必须重启。

peer 认证密钥、server capability 签名密钥、TLS 材料、部署配置和授权注册表必须分离。私钥
只放在所属组件的受保护存储中；授权注册表是共享 agent 路由的唯一来源，不能由 CONNECT
请求、WSS frame、edge 配置或 agent 配置改变。

## Edge HTTP CONNECT 边界

edge-client 的 `LoopbackConnectProxy` 固定监听 IPv4 loopback `127.0.0.1`。它只接受精确的
`CONNECT <hostname>:443 HTTP/1.1`，并在本地 allowlist 验证 hostname:443 后才请求 WSS
stream。代理在收到 server/agent 端的 `STREAM_OPENED` 前暂停本地 socket；只有成功打开后
才返回 `HTTP/1.1 200 Connection Established` 并开始转发不透明 TLS 字节。

生产 `edge-client-host` 在创建任何 WSS 或 listener 前加载严格 edge bundle，固定校验
`wss://<非 IP hostname>/tunnel`（或显式非标准端口）、`127.0.0.1:<8000-9000>` 和唯一目标
`hostname:443`。非浏览器 WSS 客户端发送与 server URL 对应的 HTTPS Origin，以满足 server 的
来源白名单；Origin 公开可构造且不参与身份授权，设备仍必须完成 Ed25519 challenge 认证。

host 加载成功后先启动这个受限 loopback proxy，再启动 WSS runtime，以便 listener 绑定失败时整体
原子退出。proxy 只在 runtime 已在线时请求 stream；离线、认证中、backoff 或撤销状态下的 CONNECT
立即固定失败，不排队到未来 session、不回退直连、不改变授权路由。运维状态检查通过后才设置
Codex 当前 shell 的 `HTTPS_PROXY`。

下列输入或能力一律拒绝：SOCKS5、普通 HTTP、absolute URL、非 `CONNECT` 方法、非
HTTP/1.1、认证头（含 `Authorization` 与 `Proxy-Authorization`）、`Upgrade`、请求 body、
`CONNECT` 头部后的额外字节、IP literal、非 `443`、IPv6 `::1`、局域网/公网 listener、
DNS 放宽、redirect 和任意 TCP 目标。edge 不保存或向本地前端暴露 capability。
代理接受不含凭据的 `Proxy-Connection` 兼容头，但不使用它参与认证、目标选择或路由。

本地 socket、edge stream 与当前 WSS session 一一绑定。edge WSS、server 会话或 agent
会话断开时，edge 会关闭所有 pending 与 open 的本地 socket，释放 credit、队列和预算；旧
stream、内部 ID 与 capability 都不可在重连后复用。只有 WSS 重新连接、完成认证并在线后，
本地 CONNECT 才能创建新的 stream。

## Agent 最终拨号边界

egress-agent 没有入站监听器、HTTP 转发客户端或代理链；它只创建到 server 的受认证出站
WSS，以及到最终批准 hostname:443 的出站 TCP。收到经 server 授权的开流请求后，它必须按
如下顺序执行，任一步失败都不得调用 TCP connector：

1. 验证 capability 的 Ed25519 签名、有效期、一次消费属性，以及与本地 `agentId`、当前
   stream ID、edge user/device 和 destination 的精确绑定。
2. 用自身静态 allowlist 再次验证精确 hostname:443，拒绝 IP literal、通配符和所有非
   `443` 端口。
3. 仅在以上验证通过、并发限额未超出后，调用 connector 建立到该 hostname:443 的 TCP
   连接。

TCP 连接成功后才发送 `STREAM_OPENED` 和初始 credit。agent 与 edge 都以每流 credit、流
缓冲、会话聚合缓冲、WSS 发送水位和 TCP `drain` 建立背压。连接、空闲、关闭或 WSS 断开
都会清理对应 socket、队列、计数和 capability 消费状态。

## TLS、数据与审计

Codex 与已批准模型网关之间的 TLS 应用内容端到端不透明。server 与 egress-agent 只传递
TCP 字节，不能终止、解密、检查、修改或记录 TLS plaintext。日志与审计只能记录经白名单
筛选的 stream 元数据，如时间、内部 stream ID、身份 ID、状态、字节计数、持续时间、错误
码和关闭码；不得记录请求 payload、destination、authorization header、cookie、token、
capability、私钥或证书正文。

## 部署与验收

配置解析只接受 `wss:` server URL，拒绝 URL 中的凭据、查询和 fragment，且 TLS 校验不能
被 `NODE_TLS_REJECT_UNAUTHORIZED=0` 禁用。配置样例见
[configuration-example.md](configuration-example.md)。`@remote-codex/ops` 只提供离线生产文件、
身份、授权和 release 操作，不是网络运行时。三个 host 在创建网络资源前分别严格加载所属 bundle；
Edge host 按上文顺序先绑定受限 proxy 再启动 runtime，未在线时 CONNECT 固定失败。

release 以机器可读 allowlist 只暂存实际运行 `.js`、package metadata、部署脚本和必要文档，排除
测试、测试 helper、source map、类型声明、构建缓存、coverage 和身份/TLS/配置根。逐文件 SHA-256
inventory 与兼容、升级、回滚流程见[发布 runbook](operations/release-and-rollback.md)。当前协议不
接受版本混跑；升级/回滚造成的 WSS 断开必须关闭旧 stream/TCP，不能恢复或迁移。

网络功能验收必须证明：

1. edge Codex 请求只能经已授权的在线 agent 到达已批准网关。
2. 不同 hostname、IP literal 和非 `443` 端口在 agent 最终验证处失败。
3. edge listener 无法从非 `127.0.0.1` 接口访问。
4. WSS 断开会释放旧资源；重连不恢复旧 stream 或扩大路由。
5. 日志不含 payload、凭据或 TLS 明文。

仓库自动测试覆盖二进制帧版本、认证/capability、ACL、目标、流状态/背压/重连、loopback 和 host
配置及 release fail-closed 规则。真实 DNS/TLS、系统 listener、防火墙、Windows task/systemd、
公司出口与网关路径、完整 E2E 以及预生产发布/回滚仍必须手工验收，不能由单元测试结论替代。
