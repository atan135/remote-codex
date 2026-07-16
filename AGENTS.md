# Remote Codex 仓库规范

## 范围

本仓库构建供 Codex 使用的受限 HTTPS 出站隧道。它不是远程桌面、远程 shell、
终端中继、文件管理器、VPN 或通用代理产品。

唯一允许的出站目标是配置的模型网关主机名的 `443` 端口。任何新目标、协议、
监听器或命令执行能力都视为范围变更，必须获得明确批准。

## 架构边界

- `server` 负责经认证的多路复用 WSS 流中继，不建立目标 TCP 连接。
- `egress-agent` 运行在公司机器上，向已批准的目标发起连接；它只创建出站 WSS
  和已批准的出站 TCP 连接。
- `edge-client` 运行在家庭电脑或在线服务器上，只暴露绑定到 `127.0.0.1` 的本地
  HTTP CONNECT 监听器；SOCKS5 不在当前范围内。
- `shared` 负责协议 schema、认证原语、流生命周期、流量控制和验证辅助函数。
- 不得添加对 `remote-client` 的运行时依赖，也不得使用其凭据、数据库、WebSocket
  endpoint 或部署资源。

## 安全要求

- 拒绝 IP literal 目标、非 `443` 端口、通配符主机、跳转到其他主机的重定向，以及
  创建通用 TCP 代理的尝试。
- 在转发字节前认证每个 peer 并授权每条 stream。
- 服务身份、用户身份、加密密钥和部署配置必须与其他项目分离。
- 不得将请求 payload、授权头、cookie、token 或 TLS 明文写入日志。
- 所有 edge 代理监听器必须绑定到 loopback；仅 server 的 HTTPS/WSS endpoint 可公开暴露。
- 必须保留背压，并为并发 stream、缓冲字节、空闲时长和重连重试设置显式限制。

## 实现规则

- 优先采用带显式 stream ID 的小型二进制 WebSocket 帧协议。
- egress agent 中的目标验证是最终执行点；server 端验证仅作为纵深防御。
- 保持 Codex 与已批准模型网关之间的 HTTPS 端到端传输。
- 为认证、目标验证、stream 清理、流量控制、重连行为和仅 loopback 绑定添加聚焦测试。
- 协议、安全边界或部署拓扑变更时，更新 `README.md` 和 `docs/architecture.md`。

## 文档规范

- 项目文档必须使用中文编写；代码标识、路径、协议名、环境变量、配置键、错误码和
  精确配置值可保留原文，以避免技术含义歧义。

## 验证

在声明网络功能完成前，验证以下内容：

1. edge 端 Codex 请求只能通过公司 egress agent 到达已批准网关。
2. 尝试访问不同 hostname、IP 地址或端口时，会在 egress agent 处失败。
3. edge 代理无法从非 loopback 接口访问。
4. WSS 连接断开会清理 stream，并在不暴露陈旧或放宽路由的前提下重连。
5. 日志只含 stream 元数据，不含请求 payload 或凭据。
