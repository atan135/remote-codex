# Windows Egress Agent 部署与演练

## 固定边界

Egress Agent 只在指定的公司 Windows 普通用户上下文中运行。进程只创建两类出站连接：

- 到唯一 Public Server `wss://<hostname>:8443/tunnel` 的 WSS。
- 经 capability 与本地 allowlist 双重验证后，到唯一模型网关 hostname 的 TCP `443`。

Agent 不创建 TCP、HTTP、SOCKS、调试、管理或 named-pipe listener，不设置 Windows 系统代理，
也不要求入站防火墙规则。Windows 临时源端口由系统选择，不属于应用监听端口。TCP 连接表只能
核对解析后的远端地址和端口，不能证明 TLS SNI；真实 hostname、证书和公司出口仍须由部署负责人
结合 Public Server、模型网关和公司网络证据手工确认。

## 安装准备

使用 Node.js 22 和已经通过完整构建的只读 release。配置目录建议放在当前用户专用位置，例如
`%LOCALAPPDATA%\RemoteCodex\egress-agent`，并先使用 `remote-codex-ops` 生成或分发材料。目录、
manifest、config、agent 私钥和 server 验签公钥必须通过 Windows owner-only ACL 检查。私钥不放入
release、命令参数、环境变量、任务描述或日志。配置中的 Public Server URL 必须使用非 IP hostname、
固定 `/tunnel`，并显式使用 `8443`；模型网关必须是非 IP 的精确 hostname 和 `443`。

在目标普通用户的非提升 PowerShell 中运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File `
  deployment\windows\egress-agent\Install-EgressAgentTask.ps1 `
  -ReleaseRoot C:\RemoteCodex\current `
  -ConfigRoot "$env:LOCALAPPDATA\RemoteCodex\egress-agent"
```

安装器先离线运行严格 bundle 与 ACL 校验，再注册固定名称 `RemoteCodex-EgressAgent`。任务只在当前
用户登录时触发，使用 `Interactive` 和 `Limited`、单实例、三次一分钟失败重启，并且不自动启动。
`ExecutionTimeLimit` 使用 Task Scheduler 的 `PT0S`（`[TimeSpan]::Zero`）无限时长语义，不会按日历
期限终止长期运行的 agent。安装器拒绝 LocalSystem、管理员令牌、UNC 路径和不完整 release；若固定
名称任务已属于其他用户，也会以 `AGENT_TASK_OWNER_MISMATCH` 失败，不使用 `-Force` 覆盖他人任务。
同一当前用户可幂等更新。需要跨用户部署时，应让每个指定普通用户登录后分别安装，不能用管理员
任务替代服务身份隔离。

启动、强制停止与卸载：

```powershell
.\deployment\windows\egress-agent\Start-EgressAgentTask.ps1
.\deployment\windows\egress-agent\Stop-EgressAgentTask.ps1
.\deployment\windows\egress-agent\Uninstall-EgressAgentTask.ps1
```

`SIGINT`/`SIGTERM` 可用时 host 会幂等停止 WSS、重连计时器和所有目标 TCP，但 Windows
`Stop-ScheduledTask` 不保证向 Node 传递这些信号。当前停止脚本明确执行任务计划强制终止，等待最多
15 秒并确认任务不再为 `Running`；它依赖 Windows 回收进程 WSS/TCP，以及 server 的 peer-disconnect
清理 stream，不声称执行了 host graceful shutdown。进程重启不会恢复旧 stream 或 stale route。
脚本超时会以 `AGENT_TASK_STOP_TIMEOUT` 失败，运维人员此时必须先检查任务和进程状态，不能直接启动
第二实例。本版本没有为优雅停止增加 named pipe、listener 或远程管理控制面。

## 持久状态日志

生产 host 默认把白名单状态事件写入配置根的 `logs\agent-status.ndjson`。日志目录和文件沿用配置根
owner-only ACL；host 拒绝符号链接、reparse link、硬链接、多 owner 或目录逃逸。当前文件达到
`1 MiB` 前轮转，固定保留 `agent-status.ndjson.1` 到 `.3` 三个备份。每条写入后同步文件数据；写入或
轮转故障不会中断认证、WSS 重连或 stream 清理状态机，也不会把路径或异常正文写到其他输出。

状态日志只含 `event`、`occurredAtMs`、`state`、`reconnectAttempts` 和稳定 `code`。不要把 manifest、
config、私钥、完整任务命令行或 Windows 事件详情混入日志。支持人员收集证据前先重新运行离线
`deployment validate`，然后只提交上述最多四个 `agent-status.ndjson*` 文件；仍应搜索并拒绝任何
意外出现的 URL、hostname、IP、header、token、capability、payload 或密钥正文。

## 状态与网络检查

在 agent 启动后运行只读检查：

```powershell
.\deployment\windows\egress-agent\Test-EgressAgentNetwork.ps1 `
  -ReleaseRoot C:\RemoteCodex\current `
  -ConfigRoot "$env:LOCALAPPDATA\RemoteCodex\egress-agent"
```

脚本重新执行离线 bundle/ACL 校验，按 DNS 当前结果核对 agent PID 的 TCP 表，只输出任务状态、
进程数量和分类计数，不输出 URL、hostname、IP、命令行、payload 或凭据。成功必须同时满足：任务
存在且属于当前用户、任务状态为 `Running`、目标 host 进程恰好一个、到 Public Server 的
`Established` WSS TCP 恰好一条，以及 `listeningSocketCount` 和 `unexpectedConnectionCount` 均为
`0`，`staleConnectionCount` 也必须为 `0`。所有 `RemotePort != 0` 的 agent TCP 都会先按批准的
server/gateway 地址和端口分类；任何状态的非批准远端都计入 unexpected。批准端点的 `SynSent` /
`SynReceived` 计入 pending，`CloseWait`、`FinWait1/2`、`LastAck`、`TimeWait` 等计入 stale，不会静默
忽略。未安装、离线、backoff、仅 pending、stale/closed socket 或零进程都会退出 `1`；模型网关连接
在无活跃 stream 时可以为零。主机防火墙预期规则是：
agent 用户可出站访问 Public Server 固定端口（通常为 `443`）和模型网关 `443`，没有 Remote Codex
入站 allow 规则。生产防火墙变更由公司网络管理员实施，本仓库脚本不会自动修改防火墙或系统代理。

## 安全故障演练

所有演练均在隔离预生产环境进行，不使用 `NODE_TLS_REJECT_UNAUTHORIZED=0`，不临时放宽目标、
身份或端口。日志只记录 `agent.state_changed`、重连次数和稳定错误码。

1. **Server 暂时不可用**：先确认无活跃业务流，停止预生产 server。agent 应记录
   `WSS_CONNECTION_FAILED` 与有界指数退避，达到配置上限后记录 `RECONNECT_LIMIT_EXCEEDED` 并以
   失败状态退出，由任务计划最多重启三次。恢复 server 后手工启动任务，旧 stream 不恢复。
2. **证书错误**：只在预生产 server 换用不受信或 hostname 不匹配证书。agent 行为与连接失败相同，
   不能输出证书正文或错误对象。恢复可信证书后再启动任务。
3. **Agent 凭据撤销**：从 server peer registry/授权中撤销 agent，按 server 受控重启流程生效。
   agent 应收到稳定认证错误、停止重连并失败退出；任务计划重试仍不能绕过撤销。恢复时供应新 key ID
   和私钥，不能重新启用已撤销私钥。
4. **进程重启**：建立受控测试流后停止任务，确认 server stream 数、agent 目标 TCP 和本机句柄归零，
   再启动任务。新 WSS 必须重新认证，任何旧 stream ID、capability 和 TCP 都不能恢复。

每次演练保留脱敏的状态事件、计数、时间点和任务结果。最终在公司网络由管理员核对模型网关侧的
源 egress 属于公司机器路径，并确认 edge 机器没有到模型网关 `443` 的直连；这项结果不能由本地
单元测试或 TCP 表推断。
