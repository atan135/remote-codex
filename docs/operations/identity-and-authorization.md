# 生产配置、身份与授权操作

本文只描述离线文件供应，不引入管理 endpoint、额外监听器或远程命令能力。所有命令应在受控
部署目录中执行；输出只包含状态、角色、key ID、文件路径和授权审计版本，不输出 PEM、token
或凭据正文。

## 目录与权限

推荐位置如下：

| 组件 | Windows | Linux |
| --- | --- | --- |
| server | 不建议部署 | `/etc/remote-codex/server` |
| egress-agent | `%ProgramData%\RemoteCodex\egress-agent` | `/etc/remote-codex/egress-agent` |
| edge-client | `%LOCALAPPDATA%\RemoteCodex\edge-client` | `$HOME/.config/remote-codex/edge-client` |

每个部署根目录、全部中间目录和身份子目录都必须为 owner-only，并拥有独立
`manifest.json`、`config.json`。server 额外持有
`peer-identities.json`、`authorizations.json` 与 `authorization-history/`。私钥、manifest、
config、peer registry 和 authorization registry 在 POSIX 上必须为 owner-only；Windows 上
不得向 `Everyone`、`Authenticated Users`、`Users`、`Interactive` 或 `Guests` 授予访问权限。
公钥在 POSIX 上允许其他用户读取，但不得由组或其他用户写入；Windows 当前策略对全部部署
文件和目录仅授权运行用户与 `SYSTEM`。路径必须相对部署根目录，不能包含 `..`、反斜杠、
盘符、alternate data stream 或符号链接。

production manifest 当前 schema 为 `schemaVersion: 2`；v1 会以
`OPS_MANIFEST_VERSION_MISMATCH` 明确拒绝，不能按旧 shape 猜测或降级加载。server 新增的
`host.json` 使用独立的 `schemaVersion: 1`，两者不是同一个 schema。

加载顺序固定为：

1. 读取并严格解析组件 `manifest.json`，拒绝未知字段和错误组件。
2. 检查路径包含关系、文件类型与权限，然后严格解析 runtime config。
3. 按 manifest 的固定角色加载公私钥，校验 Ed25519 类型和公私钥匹配。
4. server 加载 peer 公钥目录，再加载授权文件并核对 user/device/agent 引用。
5. 全部检查成功后才向运行时返回材料；失败不产生网络连接或监听器。

edge 生产端口只允许 `8000-9000`，样例使用 `8787`。目标网关仍只能是精确 hostname 的出站
`443`，该端口不是应用监听端口。

## 身份生成与分发

构建后使用 `remote-codex-ops identity generate` 分别生成三种角色。输出目录必须预先有受限的
父目录，工具不会覆盖已有文件。

```powershell
remote-codex-ops identity generate --root C:\RemoteCodex\staging --output-directory server-signing-2026-01 --role server-capability-signing --key-id server-signing-2026-01
remote-codex-ops identity generate --root C:\RemoteCodex\staging --output-directory agent-01-2026-01 --role egress-agent-authentication --key-id agent-01-2026-01
remote-codex-ops identity generate --root C:\RemoteCodex\staging --output-directory edge-device-01-2026-01 --role edge-device-authentication --key-id edge-device-01-2026-01
```

分发矩阵：

| 材料 | server | agent | edge |
| --- | --- | --- | --- |
| server capability 私钥 | 读取 | 禁止 | 禁止 |
| server capability 公钥 | 读取 | 读取 | 读取 |
| agent 认证私钥 | 禁止 | 读取 | 禁止 |
| agent 认证公钥 | 读取 | 读取 | 禁止 |
| edge 设备认证私钥 | 禁止 | 禁止 | 读取 |
| edge 设备认证公钥 | 读取 | 禁止 | 读取 |
| peer identity registry、授权文件 | 读取 | 禁止 | 禁止 |

私钥经受控文件传输落到最终目录，不放入命令参数、工单正文、聊天、shell 变量或版本库。仅把
对应公钥加入 server 的 peer registry。server 公钥可分发给 agent 和 edge；agent 不接收任何
edge 公钥，edge 不接收任何 agent 私钥或其他用户材料。

## 轮换、吊销与灾难替换

常规轮换使用新 key ID 和新目录生成材料，绝不原位覆盖：

1. 先把新公钥加入依赖方并设置明确生效/到期窗口，运行 `deployment validate`。
2. 将新私钥 manifest 只切换到所属组件；重启会关闭旧 WSS 和 stream，不恢复旧路由。
3. 确认新身份上线后，从 peer registry 移除旧公钥并提升授权审计版本。
4. 离线销毁旧私钥；审计记录只保留 key ID、时间、操作者和变更原因。

edge 设备丢失时，先按设备撤销授权并从 peer registry 移除公钥；agent 泄露时按 agent 撤销其
全部授权并更换 agent key；server capability 私钥泄露时属于灾难替换：立即停止 server，生成
新的 server key，向所有 agent/edge 重新分发公钥，撤销旧 key ID 后再恢复服务。不得为了恢复
连接临时复用其他角色私钥或关闭签名验证。

## 授权变更与审计

授权工具以 lock 文件串行化变更，用现有 `AuthorizationRegistry` 完整校验候选文档，将当前版
和新版本写入不可覆盖的 `authorization-history/authorization-vNNNNNNNNNNNN.json`，最后原子
替换当前文件。失败时当前授权不变。

新增 user/device 前先供应独立 edge 公钥并写入 peer registry，再执行 `authorization grant`。
同一 user/device 已存在 active route 时，工具拒绝静默换 agent；必须先撤销，再显式 grant。
`tighten-quota` 只允许降低 `maxConcurrentStreams` 或 `maxBufferedBytes`，提高配额需独立审批并
以受审配置变更处理。

```powershell
remote-codex-ops authorization grant --root C:\RemoteCodex\server --authorizations authorizations.json --peers peer-identities.json --history authorization-history --edge-user-id edge-user-01 --edge-device-id edge-device-01 --agent-id company-agent-01 --max-concurrent-streams 4 --max-buffered-bytes 1048576 --now-ms 1784332800000
remote-codex-ops authorization revoke --root C:\RemoteCodex\server --authorizations authorizations.json --peers peer-identities.json --history authorization-history --selector edge-device --id edge-device-01 --now-ms 1784336400000
remote-codex-ops authorization validate --root C:\RemoteCodex\server --authorizations authorizations.json --peers peer-identities.json --history authorization-history
```

审计复核至少比较：当前 audit version 与最后归档版本一致、归档版本连续、peer 引用有效、同一
设备只有一条 active route、配额未超过全局上限、撤销记录包含时间。日志和工单不得附带私钥、
capability、请求 payload、Authorization、cookie 或 TLS 明文。

## 离线预检

在启动任何组件前执行：

```powershell
remote-codex-ops deployment validate --root C:\RemoteCodex\edge-client --manifest manifest.json
```

该命令验证配置、路径、权限、角色、公私钥匹配和 server 授权引用，不启动网络。任何
`OPS_*` 错误都应阻止启动；错误仅含稳定错误码，不回显文件内容、JSON 值或密钥正文。
