# Windows边缘客户端实测部署与排障

本文记录一次完成的 Windows Edge Client 部署。它补充
[Windows Edge Client 用户接入](windows-edge-client-deployment.md) 的通用约束；以该文为安全边界的
权威来源。本次使用的目录如下，可按实际环境替换：

```text
Windows release: E:\project\remote-codex
Windows 配置根: E:\project\config\remote-codex
Server 配置根: /opt/config/remote-codex/runtime/server
Server release: /opt/remote-codex/releases/0.1.0
```

配置根位于 Git 工作树外是预期行为。`runtime/` 不应提交 Git；它包含运行配置和身份材料。

## 目标状态

本次 Windows 设备使用：

```text
edgeUserId: edge-user-01
edgeDeviceId: edge-device-win-01
edge key ID: edge-device-win-01-2026-07-21
Server: wss://remote-codex.zergzerg.cn:8443/tunnel
本地 CONNECT: 127.0.0.1:8787
```

Server 上保留原有 `(edge-user-01, edge-device-win-01) -> company-agent-01` 授权。密钥轮换只替换
该设备的认证公钥和 key ID，不修改 `authorizations.json`，也不新增重复的 user/device 条目。

## Windows 配置与身份生成

以下操作必须在运行 Codex 的普通 Windows 用户、非提升 PowerShell 中完成：

```powershell
$ReleaseRoot = 'E:\project\remote-codex'
$ConfigRoot = 'E:\project\config\remote-codex'
$KeyId = 'edge-device-win-01-2026-07-21'

New-Item -ItemType Directory -Force $ConfigRoot | Out-Null
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$currentGrant = "*$($currentSid):(OI)(CI)F"
$systemGrant = '*S-1-5-18:(OI)(CI)F'
icacls $ConfigRoot /inheritance:r /grant:r $currentGrant $systemGrant

node "$ReleaseRoot\ops\dist\cli-main.js" identity generate `
  --root $ConfigRoot `
  --output-directory 'keys/authentication' `
  --role 'edge-device-authentication' `
  --key-id $KeyId
```

不要使用 `whoami /user /fo csv /nh | ConvertFrom-Csv` 获取 SID：`/nh` 删除了 CSV 表头，导致
`ConvertFrom-Csv` 无法生成 `SID` 属性，最终会向 `icacls` 传入无效 SID。应使用上例的
`WindowsIdentity` API。

生成后，Windows 配置根必须具备下列结构：

```text
E:\project\config\remote-codex\
  manifest.json
  config.json
  keys\authentication\identity.json
  keys\authentication\private.pem
  keys\authentication\public.pem
  server-keys\capability\public.pem
```

`private.pem` 永远留在此 Windows 配置根。只向 Server 传输
`keys\authentication\public.pem`。Server capability 公钥可从 Server 的
`keys/server-signing/public.pem` 经受控渠道复制到 Windows 的
`server-keys\capability\public.pem`；不得复制 Server signing 私钥。

`config.json`：

```json
{
  "component": "edge-client",
  "edgeUserId": "edge-user-01",
  "edgeDeviceId": "edge-device-win-01",
  "serverUrl": "wss://remote-codex.zergzerg.cn:8443/tunnel",
  "listenHost": "127.0.0.1",
  "listenPort": 8787,
  "allowedDestination": {
    "hostname": "ai-coding-bj-pub.singularity-ai.com",
    "port": 443
  }
}
```

`manifest.json` 中的 `authenticationKey.keyId` 必须与新生成的 `identity.json` 一致；其公私钥路径为
`keys/authentication/public.pem` 和 `keys/authentication/private.pem`。`serverCapabilityVerificationKey`
使用 `server-signing-2026-01` 及 `server-keys/capability/public.pem`。

完整 `manifest.json` 如下：

```json
{
  "schemaVersion": 2,
  "component": "edge-client",
  "serverId": "public-server-01",
  "configPath": "config.json",
  "authenticationKey": {
    "role": "edge-device-authentication",
    "keyId": "edge-device-win-01-2026-07-21",
    "publicKeyPath": "keys/authentication/public.pem",
    "privateKeyPath": "keys/authentication/private.pem"
  },
  "serverCapabilityVerificationKey": {
    "role": "server-capability-signing",
    "keyId": "server-signing-2026-01",
    "publicKeyPath": "server-keys/capability/public.pem"
  }
}
```

配置完成后，先执行离线校验。`OPS_FILE_NOT_FOUND` 表示上述结构中至少一个文件尚未供应，不能跳过：

```powershell
node "$ReleaseRoot\ops\dist\cli-main.js" deployment validate `
  --root $ConfigRoot --manifest manifest.json
```

## Server 公钥登记与重启

将 Windows 新公钥保存为新的、不可覆盖的 Server 路径，例如：

```text
/opt/config/remote-codex/runtime/server/peer-keys/
  edge-device-win-01-2026-07-21/public.pem
```

该目录和文件应仅由 `remote-codex` 与必要的系统主体访问。修改
`peer-identities.json` 中现有的 `edge-device-win-01` 条目：

```json
"authenticationKey": {
  "role": "edge-device-authentication",
  "keyId": "edge-device-win-01-2026-07-21",
  "publicKeyPath": "peer-keys/edge-device-win-01-2026-07-21/public.pem"
}
```

先校验 Server bundle 和授权审计：

```bash
node /opt/remote-codex/releases/0.1.0/ops/dist/cli-main.js deployment validate \
  --root /opt/config/remote-codex/runtime/server --manifest manifest.json

node /opt/remote-codex/releases/0.1.0/ops/dist/cli-main.js authorization validate \
  --root /opt/config/remote-codex/runtime/server \
  --authorizations authorizations.json --peers peer-identities.json \
  --history authorization-history
```

本次 Server 由 `remote-codex` 用户的 PM2 管理，而非 systemd。认证 peer registry 的改动必须重启，
不能使用 TLS reload：

```bash
runuser -u remote-codex -- env \
  HOME=/var/lib/remote-codex \
  PM2_HOME=/var/lib/remote-codex/.pm2 \
  PATH=/usr/local/bin:/usr/bin:/bin \
  /usr/local/bin/pm2 restart remote-codex-server
```

确认 PM2 状态为 `online`、Server 监听 `0.0.0.0:8443`。重启期间出现短暂 `PEER_DISCONNECTED` 是预期的；
agent 重新认证后应恢复。健康检查必须禁用当前 shell 的代理环境变量，否则请求可能被外部代理返回 `403`：

```bash
env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy \
  curl --silent --show-error --fail --max-time 10 --noproxy '*' --insecure \
  --resolve remote-codex.zergzerg.cn:8443:127.0.0.1 \
  https://remote-codex.zergzerg.cn:8443/health
```

预期返回 `{"status":"ok"}`。

## 安装、启动和验收

确认 Windows release 已包含 `ops\dist\cli-main.js` 与 `edge-client-host\dist\cli-main.js` 后，安装任务：

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File `
  "$ReleaseRoot\deployment\windows\edge-client\Install-EdgeClientTask.ps1" `
  -ReleaseRoot $ReleaseRoot `
  -ConfigRoot $ConfigRoot
```

安装器必须以普通用户运行。若出现 `EDGE_TASK_OWNER_MISMATCH`，先查看任务所有者：

```powershell
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$task = Get-ScheduledTask -TaskName 'RemoteCodex-EdgeClient'
[pscustomobject]@{
  CurrentName = $identity.Name
  CurrentSid = $identity.User.Value
  TaskUserId = $task.Principal.UserId
  TaskState = $task.State
} | Format-List
```

对于本地账户，任务计划程序可能将完整身份 `COMPUTER\\user` 规范化为短用户名 `user`。脚本已在提交
`94cd59c` 中修复此兼容性；Windows 工作树需要先执行 `git pull`，再启动和检查，不需要重新生成密钥或
重新安装任务。

```powershell
cd E:\project\remote-codex
git pull

& "$ReleaseRoot\deployment\windows\edge-client\Start-EdgeClientTask.ps1"
Start-Sleep -Seconds 5

& "$ReleaseRoot\deployment\windows\edge-client\Test-EdgeClientStatus.ps1" `
  -ReleaseRoot $ReleaseRoot `
  -ConfigRoot $ConfigRoot
```

成功状态必须包含：

```text
ok: true
taskOwned: true
taskRunning: true
processCount: 1
approvedListenerCount: 1
wssConnectionCount: 1
unexpectedListenerCount: 0
unexpectedConnectionCount: 0
```

任务使用交互式 Node 进程，可能显示一个 Node 控制台窗口。不要直接关闭该窗口，否则 Edge listener 和
WSS 会停止。需要停止时使用 `Stop-EdgeClientTask.ps1`。

## Codex 会话与常见错误

只在当前 PowerShell 会话设置代理，并将赋值和启动命令分开执行：

```powershell
$env:HTTPS_PROXY = 'http://127.0.0.1:8787'
codex
```

PowerShell 中写成 `$env:HTTPS_PROXY = 'http://127.0.0.1:8787' codex` 会产生
`Unexpected token 'codex'`，因为赋值语句与命令之间缺少换行或分号。

关闭该 PowerShell 后代理变量自动消失；也可执行：

```powershell
Remove-Item Env:HTTPS_PROXY
```

不得使用 `setx`、系统代理、局域网地址、IPv6 listener、用户名密码或 token。状态检查失败时，只收集
稳定错误码、状态 JSON 和受控日志；不要提交私钥、请求内容、完整命令行或 TLS 明文。
