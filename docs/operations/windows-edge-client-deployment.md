# Windows Edge Client 用户接入

## 固定边界与材料

每台 edge 设备使用独立的 `(edgeUserId, edgeDeviceId)` 和 `edge-device-authentication` 密钥，
只接收本设备私钥、对应公钥和 server capability 验签公钥。不得向 edge 用户分发其他设备私钥、
agent 私钥、server 签名私钥、peer registry 或授权文件。管理员只在 server 端把这个 user/device
授权给所需的共享 agent，并为设备设置必要配额。

Edge Client 只创建到唯一 Public Server 的出站 WSS，并只监听
`127.0.0.1:<8000-9000>` 的 HTTP CONNECT。样例使用 Nginx Public Server `443`、本地 listener
`8787`。它不提供 SOCKS、普通 HTTP 转发、文件、命令、调试或管理接口，不修改 Windows 系统
代理、防火墙或全局环境变量，也不直连模型网关。WSS 客户端从唯一
`wss://<hostname>/tunnel`（或显式非标准端口）固定派生并发送对应 HTTPS Origin；Origin
只是 server 的握手来源检查，真正身份仍由设备私钥完成 challenge 签名，不能用 Origin 绕过认证。

配置根建议为 `%LOCALAPPDATA%\RemoteCodex\edge-client`。目录、manifest、config、本设备私钥和
server 公钥必须通过 owner-only ACL 检查。配置必须明确写出非 IP 的 server hostname、
固定 `/tunnel`、`127.0.0.1` listener、`8000-9000` 内本地端口，以及唯一
模型网关 hostname 的 `443`。先在离线状态运行：

```powershell
node C:\RemoteCodex\current\ops\dist\cli-main.js deployment validate `
  --root "$env:LOCALAPPDATA\RemoteCodex\edge-client" --manifest manifest.json
```

任何校验失败都应阻止启动。不得通过关闭 TLS 校验、换用 IP、放宽 hostname/port 或复用其他身份
来恢复连接。

## 当前用户任务安装

使用 Node.js 22 和已经完整构建的只读 release。在设备所属普通用户的非提升 PowerShell 中运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File `
  deployment\windows\edge-client\Install-EdgeClientTask.ps1 `
  -ReleaseRoot C:\RemoteCodex\current `
  -ConfigRoot "$env:LOCALAPPDATA\RemoteCodex\edge-client"
```

安装器先执行严格离线校验，再注册固定名称 `RemoteCodex-EdgeClient`。任务使用当前用户
`AtLogOn`、`Interactive`、`Limited`、单实例、三次一分钟失败重启和 `PT0S` 无限执行时长；不会
自动启动，不存储密码，不以管理员或 SYSTEM 身份运行。若同名任务属于其他用户则失败，不覆盖。
启动、强制停止和卸载命令为：

```powershell
.\deployment\windows\edge-client\Start-EdgeClientTask.ps1
.\deployment\windows\edge-client\Stop-EdgeClientTask.ps1
.\deployment\windows\edge-client\Uninstall-EdgeClientTask.ps1
```

`Stop-ScheduledTask` 不保证向 Node 发送 `SIGINT`/`SIGTERM`。停止脚本执行任务计划的强制终止，
等待最多 15 秒确认不再为 `Running`；它不声称调用了 host graceful shutdown。Windows 会回收本机
listener/WSS，server 的 peer-disconnect 会清理 stream。脚本超时并返回 `EDGE_TASK_STOP_TIMEOUT`
时，先确认现有进程和 listener 已消失，不能直接启动第二实例。正常终端信号或 runtime 的认证终止、
撤销、replay 和重试耗尽会由 host 幂等关闭 listener、WSS 与全部 stream。

## Codex 会话接入

任务在线后，只对需要使用隧道的当前终端进程设置 `HTTPS_PROXY`。端口必须与受保护配置完全一致：

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:8787"
codex
```

关闭该 PowerShell 窗口后变量自然消失；也可以在当前会话执行
`Remove-Item Env:HTTPS_PROXY`。不要使用 `setx`、Windows 系统代理、用户名、密码、token、局域网
地址、`::1`、查询参数或 fragment。本仓库不提供接受任意命令的 Codex launcher。

## 状态检查与手工验收

启动后运行只读状态检查：

```powershell
.\deployment\windows\edge-client\Test-EdgeClientStatus.ps1 `
  -ReleaseRoot C:\RemoteCodex\current `
  -ConfigRoot "$env:LOCALAPPDATA\RemoteCodex\edge-client"
```

成功必须同时满足：任务属于当前用户并为 `Running`、host 进程恰好一个、到 Public Server 的
`Established` WSS 恰好一条、批准的 `127.0.0.1` listener 恰好一个、没有额外 listener、陈旧或
非批准远端连接，并且没有额外的 pending Server TCP。仅本机 CONNECT 的 pending 连接只记录计数，
不单独判失败。输出只包含状态和分类计数，不显示 URL、hostname、IP、命令行或凭据。

真实网络验收由用户在隔离环境手工完成：

1. 先用 `Test-NetConnection -ComputerName 127.0.0.1 -Port 8787` 确认本机可达，并运行一次受控
   Codex 请求确认 CONNECT 能打开。
2. 从同一局域网另一台机器访问 edge 设备地址的 `8787`，结果必须失败；本机访问 `127.0.0.2`
   和 `::1` 的同一端口也必须失败。不要为测试新增防火墙 allow 规则。
3. 用已授权设备确认业务可用；使用未授权用户、已从 server 撤销的设备以及错误 user/device、
   server URL、目标 hostname 配置分别确认无法开流。预期只出现稳定认证、授权或配置错误，不能
   临时放宽规则。
4. 退出 Codex、停止任务后，确认 listener、WSS、stream 与 socket 在规定超时内归零；重新启动
   必须重新认证，不能恢复旧 stream。

上述步骤涉及真实 WSS、server 授权、共享 agent 和公司网络，仓库单元测试不声称已经完成这些验收。

## 安全错误收集

生产 host 默认写入配置根的 `logs\edge-status.ndjson`，达到 `1 MiB` 前轮转，固定保留
`edge-status.ndjson.1` 到 `.3`。日志目录和文件继承 owner-only ACL；host 拒绝符号链接、reparse
link、硬链接、多 owner 和目录逃逸。日志写入或轮转失败不会阻止 listener、WSS 和 stream 清理。

支持请求只收集以下材料：离线 `deployment validate` 的稳定错误码、状态检查输出、任务状态结果，
以及最多四个 `edge-status.ndjson*` 文件。提交前搜索并拒绝任何意外出现的 URL、hostname、IP、
CONNECT authority、request/response payload、headers、cookie、Authorization、token、私钥、
capability、TLS 明文或完整命令行。不要抓包、复制 Codex 请求内容或要求用户提交凭据。
