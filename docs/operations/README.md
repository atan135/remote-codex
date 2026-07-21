# Remote Codex 运维入口

本目录只覆盖 Remote Codex 受限 HTTPS 隧道。所有操作都必须保持唯一公开 Server TLS/WSS、
Agent 无入站、Edge 只监听 `127.0.0.1`、`server-host` 是唯一公网 `8443` listener，模型网关只允许精确 hostname 的出站 `443`。不得借故障处理增加代理目标、listener、远程命令或 `remote-client`
依赖。

## 文档索引

| 场景 | 文档 | 责任边界 |
| --- | --- | --- |
| 身份供应、密钥轮换、授权与用户/设备撤销 | [生产配置、身份与授权操作](identity-and-authorization.md) | 离线文件与 server 注册表 |
| Public Server 安装、TLS 续期、健康检查 | [Public Server 部署与加固](public-server-deployment.md) | Linux、唯一公网入口 |
| 公司 Egress Agent 安装与网络核对 | [Windows Egress Agent 部署与演练](windows-egress-agent-deployment.md) | 普通用户任务、只出站 |
| Edge 设备接入、`HTTPS_PROXY` 与 loopback 验收 | [Windows Edge Client 用户接入](windows-edge-client-deployment.md) | 独立设备身份、本地 CONNECT |
| Windows Edge 实测安装、密钥轮换与排障 | [Windows边缘客户端实测部署与排障](Windows边缘客户端实测部署与排障.md) | 本次环境路径与已验证问题定位 |
| 版本化产物、升级顺序、兼容与安全回滚 | [发布、升级与回滚](release-and-rollback.md) | 四个生产 workspace 与运行依赖 |
| 故障定位、容量告警、脱敏取证和事件响应 | [故障定位与事件响应](incident-response.md) | 拒绝新流或关闭关联流，不拓宽路由 |

协议与状态机以[共享契约](../shared-contract.md)为准，信任边界以[架构文档](../architecture.md)为准。
文档中的自动测试结果不能替代真实 WSS、模型网关、公司出口、非 loopback 访问和预生产发布/回滚
演练。

## 变更分类

- 配置、文档或实现变化但 `protocolVersion`、manifest schema 和身份角色不变：按常规兼容发布，
  仍要重新生成清单并完成相应手工检查。
- `protocolVersion`、二进制帧、认证签名输入、capability 绑定、manifest schema、身份角色或部署
  拓扑变化：属于不兼容发布，必须安排维护窗口和全组件切换，不能滚动混跑。
- 新目标、协议、公开 endpoint、listener、命令执行、文件访问、SOCKS/VPN 或 `remote-client` 集成：
  属于范围变更，当前 runbook 不授权实施。
