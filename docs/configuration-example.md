# 受限隧道配置示例

本文件只说明可解析的非敏感配置形状。所有 hostname、身份 ID 与端口组合都是示例，不能
直接用于生产。认证私钥、TLS 私钥、证书正文、token、cookie、authorization header 和
capability 都不能写入这些 JSON 文件、`serverUrl` 或日志；它们必须由各组件独立的受保护
存储和受控运行时输入提供。

生产部署还必须用严格 manifest 指定每个组件可读取的身份材料。无秘密样例见
`deployment/examples/`，离线校验与权限要求见
[生产配置、身份与授权操作](operations/identity-and-authorization.md)。

以下 `limits` 均只会收紧共享库默认上限。实际部署还必须分别向 server 注入 TLS、peer
公钥身份、capability 签名身份和授权注册表。

## Egress Agent

```json
{
  "component": "egress-agent",
  "agentId": "agent-example-01",
  "serverUrl": "wss://tunnel.example.invalid:8443/tunnel",
  "allowedDestination": {
    "hostname": "gateway.example.invalid",
    "port": 443
  },
  "limits": {
    "maxConcurrentStreams": 16,
    "maxBufferedBytesPerStream": 131072,
    "maxAggregateBufferedBytes": 1048576,
    "maxFramePayloadBytes": 16384,
    "maxIdleMs": 60000,
    "connectTimeoutMs": 5000,
    "openTimeoutMs": 10000,
    "heartbeatIntervalMs": 10000,
    "heartbeatTimeoutMs": 30000,
    "reconnectInitialMs": 1000,
    "reconnectMaxMs": 10000,
    "maxReconnectAttempts": 8
  }
}
```

`agentId` 是 agent 身份字段，不是密钥。`EgressAgentRuntime` 需要单独提供与该 ID 匹配的
agent 认证身份和私钥，以及 server capability 验证公钥。它只会在 capability 和本地
`allowedDestination` 都精确匹配后拨号 `gateway.example.invalid:443`。

## Edge Client

```json
{
  "component": "edge-client",
  "edgeUserId": "edge-user-example-01",
  "edgeDeviceId": "edge-device-example-01",
  "serverUrl": "wss://tunnel.example.invalid:8443/tunnel",
  "listenHost": "127.0.0.1",
  "listenPort": 8787,
  "allowedDestination": {
    "hostname": "gateway.example.invalid",
    "port": 443
  },
  "limits": {
    "maxConcurrentStreams": 16,
    "maxBufferedBytesPerStream": 131072,
    "maxAggregateBufferedBytes": 1048576,
    "maxFramePayloadBytes": 16384,
    "maxIdleMs": 60000,
    "connectTimeoutMs": 5000,
    "openTimeoutMs": 10000,
    "heartbeatIntervalMs": 10000,
    "heartbeatTimeoutMs": 30000,
    "reconnectInitialMs": 1000,
    "reconnectMaxMs": 10000,
    "maxReconnectAttempts": 8
  }
}
```

`edgeUserId` 与 `edgeDeviceId` 是 edge 身份字段，不是密钥。`EdgeClientRuntime` 的认证私钥
必须独立注入；配置解析仅接受 `listenHost: "127.0.0.1"`，不接受 `::1`、局域网或公网地址。
生产 host 将 runtime 对象传给 `LoopbackConnectProxy` 作为 `streamGateway`，以 `listenPort`
先绑定固定 loopback listener，再启动 WSS runtime。runtime 未在线、认证中或重连时，CONNECT 只会
固定失败，不排队、不直连模型网关。只有状态检查确认 runtime 在线后，用户才设置 `HTTPS_PROXY`。

## 共享 Agent 授权

多个 user/device 可以绑定同一个 `agentId`，但该绑定只能由 server 授权注册表控制。示意：

```text
(edge-user-example-01, edge-device-example-01) -> agent-example-01
(edge-user-example-02, edge-device-example-02) -> agent-example-01
```

以上是两个独立的 active 授权记录，不是共享 edge 私钥、WSS session、stream 或 capability。
每个 `(edgeUserId, edgeDeviceId)` 同时只能有一条 active agent 路由。不能通过 edge/agent
JSON、CONNECT 请求或代理环境变量选择、替换或扩大该路由。

## 禁止配置与用法

- 不配置 SOCKS5、普通 HTTP 转发、absolute URL、HTTP/HTTPS proxy auth、公共 listener、
  IPv6 listener、DNS 放宽、redirect 或任意 TCP destination。
- `serverUrl` 使用固定 `/tunnel` 且不含凭据、查询和 fragment 的 `wss:` URL。当前 Public Server
  固定使用 `8443`，写作 `wss://<hostname>:8443/tunnel`。非浏览器 agent/edge 客户端发送对应的
  HTTPS Origin；Origin 不是身份凭据。
- `allowedDestination` 必须是精确 hostname 与 `443`，不能是 IP literal、通配符或其他端口。
- Codex 的 `HTTPS_PROXY` 只使用 `http://127.0.0.1:<listenPort>`，不携带用户名、密码或 token。
