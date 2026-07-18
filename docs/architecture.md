# Remote Codex 架构

## 范围与拓扑

Remote Codex 是受限 HTTPS 出站隧道，不是远程桌面、远程 shell、终端中继、文件管理器、
VPN 或通用代理。唯一允许的出站目标是部署配置中精确指定的模型网关 hostname 的 `443`
端口。新增目标、协议、监听器或命令执行能力都属于范围变更，必须单独批准。

```text
edge 机器                         公共互联网                         公司网络
+----------------+              +--------------------+            +-----------------+
| Codex CLI      |              | server             |            | egress-agent    |
| edge-client    | -- WSS --->  | HTTPS / WSS broker | <--- WSS -- | 出站 WSS / TCP   |
| 127.0.0.1 only |              | /health, /tunnel   |            +--------+--------+
+----------------+              +--------------------+                     |
                                                                          | HTTPS:443
                                                                          v
                                                                   已批准模型网关
```

`edge-client` 和 `egress-agent` 都主动连接 server。公司网络不接受来自 edge 或互联网的
入站连接；server 的 HTTPS/WSS endpoint 是唯一可公开暴露的网络面。本项目与
`remote-client` 完全独立，不使用其地址、凭据、数据库、WebSocket endpoint、部署环境或
运行时依赖。

## Server 与共享授权

server 由 `createTunnelServer` 创建，公共面仅包括 `GET /health` 与受 TLS、Origin、头部、
消息大小和速率约束的 WSS `/tunnel`。它认证 edge-device 和 egress-agent，管理 peer
session，按授权注册表中 active `(edgeUserId, edgeDeviceId) -> agentId` 记录选择在线
agent，并为每条获准 stream 创建内部 stream ID 和短期 capability。

多个 edge user/device 可以指向同一个 agent；这只共享 agent 的有限资源，不共享用户身份、
capability 或 stream。server 分别对授权三元组、edge user、edge device、agent 与全局强制
stream 数、缓冲字节和开流速率限制。server 不建立目标 TCP 连接，也不公开 SOCKS、HTTP
CONNECT、通用 TCP 转发、管理 API、指标 HTTP endpoint 或 shell。

生产由独立 `server-host` 进程组合 `ops` 受保护 bundle 与 `createTunnelServer`，直接终止入口
TLS。唯一公开 URL 是 `wss://<publicHostname>:<8000-9000 内端口>/tunnel`；样例为 `8443`。
证书通过预置流程或 DNS-01 续期并在 `SIGHUP` 后安全 reload，不为 ACME 或管理功能新增
listener。host 配置、Origin 或资源限制变化必须重启，不能借 reload 放宽运行边界。

peer 认证密钥、server capability 签名密钥、TLS 材料、部署配置和授权注册表必须分离。私钥
只放在所属组件的受保护存储中；授权注册表是共享 agent 路由的唯一来源，不能由 CONNECT
请求、WSS frame、edge 配置或 agent 配置改变。

## Edge HTTP CONNECT 边界

edge-client 的 `LoopbackConnectProxy` 固定监听 IPv4 loopback `127.0.0.1`。它只接受精确的
`CONNECT <hostname>:443 HTTP/1.1`，并在本地 allowlist 验证 hostname:443 后才请求 WSS
stream。代理在收到 server/agent 端的 `STREAM_OPENED` 前暂停本地 socket；只有成功打开后
才返回 `HTTP/1.1 200 Connection Established` 并开始转发不透明 TLS 字节。

下列输入或能力一律拒绝：SOCKS5、普通 HTTP、absolute URL、非 `CONNECT` 方法、非
HTTP/1.1、认证头（含 `Authorization` 与 `Proxy-Authorization`）、`Upgrade`、请求 body、
`CONNECT` 头部后的额外字节、IP literal、非 `443`、IPv6 `::1`、局域网/公网 listener、
DNS 放宽、redirect 和任意 TCP 目标。edge 不保存或向本地前端暴露 capability。

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
身份和授权操作，不是运行时启动器；受控宿主仍必须分别创建 server、agent runtime、edge
runtime 和 `LoopbackConnectProxy`，并先使 edge runtime 在线，再监听本地 CONNECT 端口。

网络功能验收必须证明：

1. edge Codex 请求只能经已授权的在线 agent 到达已批准网关。
2. 不同 hostname、IP literal 和非 `443` 端口在 agent 最终验证处失败。
3. edge listener 无法从非 `127.0.0.1` 接口访问。
4. WSS 断开会释放旧资源；重连不恢复旧 stream 或扩大路由。
5. 日志不含 payload、凭据或 TLS 明文。
