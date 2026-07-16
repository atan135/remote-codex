# Remote Codex 架构

## 范围与实现状态

Remote Codex 构建的是受限 HTTPS 出站隧道，不是远程桌面、远程 shell、终端中继、文件
管理器、VPN 或通用代理。唯一允许的出站目标是部署配置指定的模型网关 hostname 的
`443` 端口。新增任何目标、协议、监听器或命令执行能力都需要单独批准。

目前已实现 `shared` 共享协议与 `server` 的认证、授权和受限中继层。`edge-client` 的
loopback 代理和 `egress-agent` 的目标 TCP 拨号属于后续阶段；本文件同时记录已实现的
server 安全边界和后续组件必须遵守的契约，不能据此将未完成的 peer 当作可部署能力。

本项目完全独立于 `remote-client`。它不使用对方的地址、凭据、数据库、WebSocket endpoint、
部署环境或运行时依赖。

## 目标拓扑

```text
edge 机器                         公共互联网                         公司网络
+----------------+              +--------------------+            +-----------------+
| Codex CLI      |              | server             |            | egress-agent    |
| edge-client    | -- WSS --->  | HTTPS / WSS broker | <--- WSS -- | 出站连接         |
| 仅 127.0.0.1   |              | /health, /tunnel   |            +--------+--------+
+----------------+              +--------------------+                     |
                                                                          | TLS:443
                                                                          v
                                                                   已批准模型网关
```

`edge-client` 与 `egress-agent` 都只能向 `server` 建立出站 WSS。edge 的本地代理必须严格
绑定 `127.0.0.1`；公司机器不需要入站连接。目标 HTTPS 位于隧道之内，server
和 egress-agent 只转发字节，不解密、检查、修改或记录 TLS plaintext。

## Server 公共面与职责

server 当前由 `createTunnelServer` 创建。它的公共 HTTPS 面严格限定为：

| 路径 | 方法/协议 | 行为 |
| --- | --- | --- |
| `/health` | `GET` | 返回固定可用性结果，不含身份、stream、配置或指标。 |
| `/tunnel` | WebSocket upgrade | 仅接受 TLS 1.3、精确 Origin 白名单、受限头部/消息大小和速率限制的 WSS 连接。 |
| 其他 | 任意 | 拒绝。 |

`/tunnel` 先认证 peer，再处理协议帧。server 不建立目标 TCP 连接，不公开 SOCKS、HTTP
CONNECT、TCP 转发、指标 HTTP endpoint、管理 API 或 shell。`getMetrics()` 只返回受控
宿主进程可读取的聚合快照，不能映射为新的公共 HTTP 路由。

server 的职责是：

- 用独立 Ed25519 身份完成 edge-device 与 egress-agent 的挑战认证，维护心跳与会话有效期。
- 根据显式授权决定 edge user/device 能否使用某个 agent，并拒绝未授权、撤销、离线或
  配额超限的请求。
- 为获准 stream 分配 server 内部 ID，签发短期 capability，并按所有权中继二进制帧。
- 为身份、stream、agent、流控、关闭和审计建立边界；不保存或解释请求 payload。

## 身份、授权与共享 Agent

peer 认证身份与授权记录分开维护：

- edge-device 身份包含 `edgeUserId`、`edgeDeviceId` 和该设备专用认证公钥。
- egress-agent 身份包含 `agentId` 和该 agent 专用认证公钥。
- server capability 签名身份使用第三套密钥角色，不得复用任一 peer 的认证密钥。

peer 身份目录、TLS 材料和 capability 签名身份只在 `createTunnelServer` 时注入；当前没有
它们的热替换 API。相对地，授权注册表可在进程内替换完整候选文档。身份或密钥变更必须以
受控宿主重建/重启发布，且现有 stream 会关闭而不在新 session 恢复。

授权注册表的每条记录由 `edgeUserId`、`edgeDeviceId`、`agentId`、`status`、每授权配额、
创建/撤销时间和审计版本组成。引用的 device 与 agent 必须已存在于可信 peer 身份目录中。

规则如下：

- 每个 active `(edgeUserId, edgeDeviceId)` 只能指向一个 `agentId`。
- 不同的 active edge user/device 可以同时指向同一 `agentId`，这是唯一允许的共享 agent
  形式。
- 同一三元组不能重复登记；历史撤销记录保留，用于审计。
- `active` 以外的授权不产生路由；未授权或撤销的 edge stream 被拒绝。

共享 agent 时，server 不会共享任一用户的 stream 或安全上下文。它为每条接受的 stream
维护 edge 原始 ID 与 server 内部 ID 的单一映射，并分别按下列维度强制计数和缓冲限制：

| 隔离维度 | 受限资源 |
| --- | --- |
| 授权三元组 | 每授权的并发 stream 与缓冲字节。 |
| edge user | 并发 stream、缓冲字节、开流频率和拒绝计数。 |
| edge device | 并发 stream、缓冲字节和开流频率。 |
| egress agent | 并发 stream、缓冲字节和开流频率。 |
| server 全局 | 并发 stream、缓冲字节和开流频率。 |

任一 peer 只能操作自己拥有且处于正确状态的 stream。伪造 stream ID、跨 peer 发送帧、
在 `open` 前发送数据或违反 credit 都会拒绝或关闭相应流；一个慢消费者的队列按流和方向
公平恢复，不能把共享 agent 的其他用户挤出内存预算。

## Capability

server 在接收已授权的 `STREAM_OPEN` 后，先验证目标与配额，再创建新的内部 stream ID。
它把 capability 只发送给被授权的 agent；edge 端不会得到可复用于另一个 agent 的授权。

capability 为带 Ed25519 签名的二进制令牌，最长有效期为 60 秒。其受签名字段如下：

| 字段 | 约束与用途 |
| --- | --- |
| `capabilityVersion`、`signingKeyId` | 标识格式和验证所需的 server 签名公钥。 |
| `edgeUserId`、`edgeDeviceId`、`agentId` | 精确绑定发起者、设备与被选 agent。 |
| `streamId` | server 分配的 128 位内部 ID；不是 edge 原始 ID。 |
| `destination.hostname`、`destination.port` | 绑定规范化 hostname 与固定 `443`。 |
| `issuedAtMs`、`expiresAtMs` | 受限的签发和过期窗口。 |
| `capabilityId` | 单次消费的随机标识，用于重放保护。 |
| `signature` | server capability 专用私钥的 Ed25519 签名。 |

egress-agent 必须在任何 DNS 解析或 TCP 拨号前，用 server 公钥验证签名、时间、完整绑定和
单次消费；随后仍必须以自身固定 allowlist 重新调用目标验证。capability、签名、私钥和
原始 `STREAM_OPEN` payload 都不能进入日志。

## 协议、生命周期与资源控制

每条 WSS message 恰好是一帧受版本和长度约束的二进制协议帧，包含显式 128 位 stream ID。
连接级认证帧使用零 stream ID；stream 帧使用非零 ID。相关帧包括 `REGISTER`、`CHALLENGE`、
`AUTHENTICATE`、`HEARTBEAT`、`STREAM_OPEN`、`STREAM_OPENED`、`STREAM_REJECTED`、
`STREAM_ERROR`、`STREAM_DATA`、`STREAM_CREDIT` 与 `STREAM_CLOSE`。

stream 生命周期为：

```text
requested -> authorized -> connecting -> open -> closing -> closed
                         \-> rejected
                         \-> failed
```

只有 agent 的 `STREAM_OPENED` 后，server 才允许双向 `STREAM_DATA`。`STREAM_CREDIT`、
每流缓冲上限、会话聚合缓冲和 WebSocket 发送水位共同形成背压。能力过期、打开/空闲超时、
会话断开、agent 替换、授权撤销和协议错误都会清理 stream 映射、队列、字节预算和所有
维度的计数；不支持在重连后恢复旧 TCP stream。

共享库的默认资源上限只能在部署时收紧，不能放宽。详细帧格式、错误码和默认值见
[共享契约](shared-contract.md)。

## 受控运维操作

当前 server 没有管理 HTTP API。以下操作只能通过经审批的部署配置发布或由受控宿主进程
调用 `AuthorizationRegistry` 的 API 完成；不得把这些方法暴露为 `/tunnel` 以外的公网接口。
操作记录只应保存变更单号、操作者、时间、受影响身份 ID、授权文档版本、结果与关闭原因，
不能保存私钥、token、capability、cookie、授权头或请求内容。

### 登记授权

1. 为 edge device 和 egress agent 分别生成各自认证密钥；私钥仅交给对应 peer 的受保护
   存储，变更材料中只登记公钥身份和不敏感 key ID。
2. 将新 peer 身份写入下一次 server 创建所用的可信身份目录，核对 `edgeDeviceId` 所属的
   `edgeUserId` 和 `agentId` 的运维归属；确认无设备 ID 重复或过期身份。
3. 基于当前完整授权文档创建候选版本。新增记录必须引用已登记身份，写入所需的配额、
   `createdAtMs` 和新的 `auditVersion`；一个 active user/device 不得有第二个 agent 路由。
4. 若只变更授权，在隔离环境校验候选文档后，以高于当前值的顶层 `auditVersion` 原子调用
   `replaceDocument` 或 `replaceJson` 发布。文档解析、交叉引用、配额或版本任一失败时保持
   旧路由不变。若同时加入 peer 身份，则把同一候选授权文档和身份目录一并写入下一次 server
   创建的受控启动配置，再重建/重启宿主；不要让重启加载旧授权文档。
5. 在变更生效后观察 peer 认证、授权拒绝计数和 agent 活跃 stream 指标。身份变更的重启会
   关闭旧 stream；用无请求内容的测试开流确认新设备只路由到指定 agent，不要将 capability
   或 TLS 字节用于验收证据。

### 撤销用户或设备

1. 确认撤销范围是整个 `edgeUserId` 还是单个 `edgeDeviceId`，并记录批准依据与当前
   `auditVersion`。
2. 在受控宿主中调用 `revokeByEdgeUser` 或 `revokeByEdgeDevice`，或者发布将匹配 active
   记录改为 `revoked`、含 `revokedAtMs` 的完整新文档。不得删除历史记录或降低版本。
3. 确认更新结果列出相应撤销；server 的 stream 协调器会收到回调，关闭精确匹配的既有
   stream，并拒绝后续开流。
4. 检查审计中的身份、关闭原因和字节计数，以及聚合指标归零情况；不得检查或导出流内容。

### Agent 下线与替换

1. 对计划维护，先停止为该 agent 新增授权并观察其活动流；对安全事件，直接进入撤销。
2. 在受控宿主中调用 `revokeByAgent`，或发布将所有指向该 `agentId` 的 active 授权撤销的
   单调递增文档。受影响流会关闭，后续开流返回不可用或未授权错误。
3. 关闭或隔离 agent 的 WSS 连接。会话断开也会触发对应存量 stream 清理；同一 `agentId`
   的新认证会话会替换旧会话，旧会话被撤销。
4. 要把用户迁移到替代 agent，先登记替代 agent 身份，再在同一受控文档更新中撤销旧路由、
   新增指向替代 agent 的 active 记录；核对每个 user/device 最终只有一条 active 路由。若
   替代 agent 是新 peer，必须将身份目录和该文档一起放入启动配置后重启 server。

### 密钥轮换

1. 分别规划 TLS 服务端、edge-device 认证、egress-agent 认证和 server capability 签名
   四类密钥；它们不能交叉复用。确定窗口、回退条件和受影响身份。
2. 生成新密钥并把私钥放入其所属组件的受保护存储；配置、文档、工单和日志中不写私钥或
   可用秘密。准备包含新公钥、新 key ID、TLS 材料或 server 签名身份的下一版受控启动配置。
3. 在维护窗口协调更新 peer 与 egress-agent 配置后，重建/重启 server 以载入新材料。当前
   接口每个身份角色只接受一个活动认证或验证键，未实现多 key 的在线重叠验证；不得把文档
   设想的兼容期当作既有能力，也不得接受未知 key ID。重启会关闭现有 stream。
4. 在新材料连接认证成功且旧 stream 已清理后，从下一版启动配置移除旧身份或旧签名公钥。
   新 server 不再签发旧 capability，旧 capability 最长只会在其短期有效窗口内存续。
5. 验证旧密钥认证和旧 capability 均失败，新密钥连接可用，并检查日志只出现 key ID 和
   白名单 stream 元数据，而没有密钥材料或 payload。

## 审计与监控

审计序列化采用字段白名单。允许记录的 stream 元数据为事件类型、时间、内部 stream ID、
peer ID、edge user/device ID、agent ID、状态、双向字节计数、持续时间、错误码和关闭码。
不得记录 destination、WebSocket frame、capability、认证 key、私钥、TLS plaintext、
Authorization、cookie、token 或请求 payload。

进程内指标仅包括已认证 edge/agent peer 数、按 agent 的活跃流、按用户的拒绝流、按原因
的关闭流和缓冲水位。它们不经 `/health` 或 WSS 对外提供。日志与配置样例只能使用字段名
和抽象占位说明，不能引用 `remote-client` 的地址、凭据、数据库或部署资源。

## 网络验收

在 edge-client 与 egress-agent 完成后，网络功能必须同时满足：

1. edge Codex 请求只能经过授权的在线 agent 到达批准模型网关。
2. 不同 hostname、IP literal、通配符 hostname、重定向到其他 hostname 和所有非 `443`
   端口都在 egress-agent 的最终验证处失败。
3. edge 代理严格绑定 `127.0.0.1`，无法从其他接口访问；server 是唯一允许公开的
   HTTPS/WSS endpoint。
4. WSS 断开、agent 替换和授权撤销都会清理旧 stream，不会恢复或扩大陈旧路由。
5. 审计与日志只包含白名单元数据，且多用户共享 agent 时其 stream ID、capability、配额、
   credit、字节和审计记录保持隔离。
