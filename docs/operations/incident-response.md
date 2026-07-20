# 故障定位与事件响应

## 安全优先级

故障处理只能恢复既有受限路径。可用动作是拒绝新流、关闭关联 stream、停止相关 Edge/Agent/Server、
撤销授权或轮换凭据；不得临时增加目标、端口、listener、代理链，关闭 TLS/认证/证书校验，或把流
转发到未授权 Agent。无法确认边界时优先停止受影响组件。

## 快速定位

1. 记录 UTC/本地时间、release aggregate SHA-256、组件、脱敏稳定错误码和计数，不记录异常对象。
2. 对配置根运行 `deployment validate`，确认 schema、owner-only ACL、key 角色和引用仍有效。
3. Server 检查经 Nginx 的 `/health`、唯一公网 `443` listener、仅 loopback 的 Node listener、TLS 有效期和 journald；Agent 运行
   `Test-EgressAgentNetwork.ps1`；Edge 运行 `Test-EdgeClientStatus.ps1`。
4. 按 `edge -> server authorization/session -> agent -> gateway` 定位。Edge 离线时本地 CONNECT
   固定失败；没有“暂存请求后改走直连”的恢复路径。
5. 只在隔离预生产复现。生产中需要抓 payload、TLS 明文、Authorization、cookie、token 或
   capability 才能继续定位时，应停止并升级为安全事件，不收集这些内容。

| 现象 | 首查项 | 安全动作 |
| --- | --- | --- |
| Edge listener 不存在 | task、bundle 校验、Edge 状态日志、WSS 认证状态 | 保持代理失败，修复配置或身份后重启 |
| Agent 离线或反复 backoff | server TLS/Origin、Agent key、撤销状态、重连上限 | 停止重复任务，禁止更换为未审批 URL |
| `AUTH_*` / `CAPABILITY_INVALID` | key ID、peer registry、时间、撤销与 session | 关闭关联 peer/stream，按身份 runbook 轮换 |
| `DESTINATION_REJECTED` | 三端精确 hostname:443 配置 | 视为可疑输入；不增加 allowlist |
| `STREAM_LIMIT_EXCEEDED` / 缓冲高水位 | user/device/agent/global 配额和 active stream | 拒绝新流，定位异常客户端，不提高配额救火 |
| `IDLE_TIMEOUT` / `OPEN_TIMEOUT` | WSS 状态、公司出口、网关可达性 | 关闭超时流；不得延长到无界 |
| 意外 listener 或远端连接 | PID、任务 owner、release hash、主机连接表 | 立即隔离主机并停止相关进程 |

## 容量阈值与告警

以实际配置的上限为分母，不能把告警处理变成自动放宽：

- active stream 或 aggregate buffered bytes 持续 5 分钟达到 `70%`：warning，检查租户/设备分布和
  长流；达到 `85%`：critical，暂停新增授权或发布，并准备拒绝新流。
- 单 user/device/agent 配额达到 `80%`，或连续出现 `STREAM_LIMIT_EXCEEDED`：warning；达到配置
  上限时由运行时拒绝新流，不能自动提升 quota。
- WSS 重连连续失败、心跳超时或任务重启在 15 分钟内达到 3 次：critical。达到
  `maxReconnectAttempts` 后保持失败状态，由人员查证 TLS/身份/网络。
- 任一 `DESTINATION_REJECTED`、`FLOW_CONTROL_VIOLATION`、认证 replay、未知 frame/version、额外
  listener、非批准远端或日志秘密命中：立即安全告警；重复发生时隔离受影响身份或主机。
- Server TLS 剩余 30 天 warning、7 天 critical；续期仍只使用预置流程或 DNS-01，不开放 HTTP-01
  端口。

安全降级顺序为：拒绝新 stream，关闭违规或超限 stream，撤销对应 user/device/agent，必要时停止
组件。现有流不能跨 WSS/进程恢复，也不能改路由到其他 Agent。容量扩展必须另行评审显式上限、
主机资源和授权影响。

## 脱敏日志与证据

允许收集：release/inventory aggregate hash、时间、组件状态、稳定错误码、内部 stream ID、身份 ID、
状态、字节计数、持续时间、关闭码、active/buffer/reconnect 计数、任务结果。提交前搜索并拒绝：
URL/hostname/IP（状态脚本已做分类隐藏）、CONNECT authority、payload、原始 frame、TLS plaintext、
headers、Authorization、Proxy-Authorization、cookie、token、capability、私钥、证书正文、完整配置、
完整命令行和异常堆栈。

Server 使用 journald 的有界日志；Agent/Edge 各只收集最多四个 owner-only 轮转状态文件。日志写入失败
本身应告警，但不能阻止 WSS/stream/socket 清理。事件工单记录文件 hash 和保管人，不在即时消息中
粘贴原始日志正文。

## 安全事件处置

### 凭据泄露

立即停止受影响组件。Edge 设备 key 泄露时按 device 撤销授权并移除 peer 公钥；Agent key 泄露时
撤销该 Agent 的所有授权、停止任务并换新身份；Server signing key 泄露时停止 Server，灾难替换
signing key，向全部 Agent/Edge 更新验签公钥并移除旧 key。TLS 私钥泄露还要吊销/换证。恢复前确认
旧身份、旧 capability 和旧 stream 均不能使用。

### 可疑目标或绕过尝试

出现 IP literal、非 `443`、通配符、不同 hostname、redirect、SOCKS/普通 HTTP 或任意 TCP 请求时，
保留脱敏错误码和身份/stream 元数据，关闭关联流；重复行为撤销设备。核对三端配置和 agent 最终
验证仍一致。不得为“诊断”临时加入目标。

### 额外 listener 或非批准连接

立即从网络隔离主机，停止对应 PID/任务并保留进程、release hash、任务 owner 和分类计数。确认它
是否来自被篡改 release、错误任务或无关软件；重新部署前从已验证 inventory 创建全新激活目录，
轮换可能暴露的 key，并重复 listener/连接表检查。不要在原目录原位修补后直接恢复。

## 关闭与复盘

恢复后确认授权、peer registry、配置、release hash 和 listener 均为预期；WSS 全部重新认证，旧
stream/TCP 为零，日志无秘密。复盘必须区分仓库自动证据和真实网络证据，记录根因、影响身份、
撤销/轮换时间、修复 release、手工验收人以及仍待完成的 E2E/预生产演练。
