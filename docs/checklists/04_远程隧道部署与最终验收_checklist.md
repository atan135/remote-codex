# 04：远程隧道部署与最终验收 Checklist

## 目标

将已实现的 server、egress-agent、edge-client 和 shared 交付为可由多个
edge 用户共享同一 company egress agent 的完整第一版。覆盖独立配置与密钥
供应、部署、Windows 自动启动、真实网络验证、故障演练、运维资料和最终验收。

## 基础原则

- [ ] 部署资源、账号、证书、域名、数据库（如使用）和密钥均独立于 `remote-client`。
- [ ] 生产环境中不以日志、示例、shell 历史或版本库暴露用户凭据、服务私钥、TLS 私钥或请求内容。
- [ ] 生产验证不会临时放宽固定目标、loopback 绑定、认证、配额或 payload 不透明性。
- [ ] 每个阶段完成后运行对应验证，记录结果，并作为独立提交边界。

## 阶段 1：生产配置、身份供应与撤销流程

- 开始时间：2026-07-18 13:57:08 +08:00
- 结束时间：2026-07-18 15:18:19 +08:00
- 开发总结：新增独立 `ops` workspace，交付三组件严格生产 manifest、受限文件与目录权限校验、分角色 Ed25519 身份生成、最小身份材料加载、共享 agent 授权原子变更与连续审计，以及不建立网络连接的脱敏 CLI 和中文操作说明。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/ops test`（10/10）、`corepack pnpm lint`、`corepack pnpm typecheck`、`corepack pnpm build` 均通过；构建后 CLI 缺参返回稳定错误 JSON 和退出码 1，8 个部署样例 JSON 均可解析，`git diff --check` 通过。按约定未运行 `server/src/end-to-end.test.ts` 或真实联调。

- [x] 定义 server、agent、edge 的生产配置位置、最小文件权限、加载顺序、配置校验和不含秘密的样例。（验证：`ops/src/schema.ts`、`ops/src/secure-files.ts`、`ops/src/production-loader.ts` 实现严格 manifest、owner-only 目录链和固定加载顺序；`deployment/examples/` 的 8 个无秘密 JSON 均通过解析）
- [x] 为 server 签名密钥、agent 服务身份、edge 用户/设备身份制定独立生成、分发、轮换、吊销与灾难替换流程。（验证：`ops/src/identity-files.ts` 生成不可覆盖的分角色 Ed25519 材料；`docs/operations/identity-and-authorization.md` 记录分发矩阵、轮换、吊销与 server 私钥灾难替换）
- [x] 建立多 edge 用户共享 agent 的授权变更流程：新增用户/设备、授予 agent、收紧配额、撤销及审计复核。（验证：`ops/src/authorization-files.ts` 实现文件锁、grant、仅收紧配额、按 user/device/agent 撤销、连续版本归档和原子替换；ops 授权测试通过）
- [x] 验证任何用户身份不能替代 agent 身份，任何 agent 凭据不能签发用户会话或 stream capability。（验证：manifest 与 peer registry 严格绑定三种 `IdentityKeyRole`，SPKI/PKCS#8 Ed25519 容器分离；ops 角色错配、私钥伪装公钥及 agent 私钥冒充 server 签名密钥负向测试通过）
- [x] 执行离线配置校验与权限检查，确认运行进程只读取其必需的身份材料。（验证：`remote-codex-ops deployment validate` 只返回组件元数据；部署根、中间目录、文件 ACL、符号链接、目标 hostname、端口和最小密钥集合均 fail closed，Windows ACL 与失败清理回归通过）

## 阶段 2：Public Server 部署与加固

- 开始时间：2026-07-18 15:21:14 +08:00
- 结束时间：
- 开发总结：
- 验证记录：仓库开发验证已完成：`ops` 12/12、`server-host` 6/6、connection rate tracker 4/4，通过全仓 lint、typecheck、build、部署 JSON 解析、CLI 缺参 smoke test 和 `git diff --check`；未运行 `server/src/end-to-end.test.ts`，未执行公网、生产 listener、systemd 生效或真实日志验收。

- [x] 选择并实现独立的 server 部署单元、HTTPS 证书续期、反向代理或直接 TLS 终止策略，明确唯一公开 WSS URL。（验证：`server-host` 组合严格生产 bundle 与 `createTunnelServer`，仅在 `8443` 直接终止 TLS；`deployment/linux/server/` 提供加固 systemd 单元、DNS-01/预置证书 path reload，`server-host` 测试覆盖 TLS-only reload 与所有非 TLS 变更强制重启）
- [ ] 配置网络入口仅暴露 HTTPS/WSS 和必要健康检查，禁止部署平台默认的调试、管理或额外端口外露。
- [ ] 设置进程身份、资源限制、自动重启、日志轮转、时间同步和升级回滚流程。
- [ ] 从外部网络验证有效 WSS 连接和无凭据健康检查；验证其他 endpoint、非 TLS 和超限握手被拒绝。
- [ ] 审查 server 运行日志和指标导出，确认没有请求 payload、认证头、cookie、token 或密钥。

## 阶段 3：Company Windows Egress Agent 部署

- 开始时间：2026-07-18 16:35:17 +08:00
- 结束时间：
- 开发总结：
- 验证记录：仓库开发验证已完成：主流程运行 `egress-agent-host` 20/20、`egress-agent` 30/30、`ops` 12/12，PowerShell AST 5/5，并通过全仓 lint、typecheck、build 和 `git diff --check`；验证覆盖退避期间进程保活、owner-only 有界轮转状态日志、同名任务所有权保护、无限执行时长、强制停止确认与严格在线网络检查。未运行 `server/src/end-to-end.test.ts`，未安装真实任务、未建立网络连接或执行公司出口验收。

- [ ] 在拥有模型网关访问条件和 agent 身份材料的指定 Windows 用户上下文中安装 agent 运行文件与受限配置。
- [x] 使用 Windows 任务计划在用户登录后自动启动 agent，设置失败重启和受控停止；不创建任何入站端口或系统级通用代理。（验证：`deployment/windows/egress-agent/` 实现当前普通用户 `AtLogOn`/`Interactive`/`Limited` 任务、单实例、3 次失败重启、`PT0S` 无限运行和 15 秒强制停止确认；`egress-agent-host` 静态边界测试确认无 listener、系统代理、防火墙放宽或远程控制面，20/20 通过）
- [ ] 验证 agent 仅创建到 public server 的 WSS 和到精确模型网关 `:443` 的出站 TCP；记录其预期网络规则。
- [ ] 模拟 server 临时不可用、证书错误、agent 凭据撤销和进程重启，确认退避、告警和流清理符合设计。
- [ ] 在公司网络观察实际模型网关连接的源 egress，确认流量经公司机器路径而非 edge 机器直连。

## 阶段 4：Edge 用户设备接入与 Loopback 验证

- 开始时间：2026-07-18 17:42:54 +08:00
- 结束时间：
- 开发总结：
- 验证记录：仓库开发验证已完成：主流程运行 `edge-client-host` 26/26、`edge-client` 35/35、`ops` 12/12，server 除 E2E 外 6 个测试文件 51/51，PowerShell AST 5/5，并通过全仓 lint、typecheck、build 和 `git diff --check`；验证覆盖默认 WSS Origin、`8000-9000` 原子测试端口、仅 `127.0.0.1` CONNECT listener、terminal/信号并发清理、owner-only 有界日志和最低权限当前用户任务脚本。未运行 `server/src/end-to-end.test.ts`，未安装真实任务、未建立真实 WSS/网关连接或执行用户授权联调。

- [ ] 为每个 edge 用户/设备供应其独立身份和仅必要的 server/agent 授权，不分发其他用户或 agent 私钥。
- [ ] 安装 edge-client 并配置本机启动方式；将 Codex 的 `HTTPS_PROXY` 指向 `127.0.0.1` 的指定端口。
- [ ] 从本机验证 HTTP CONNECT 可建立，从局域网和非 loopback 地址验证该代理不可访问。
- [ ] 验证一个已授权用户可以使用共享 agent，未授权用户、已撤销设备和错误配置用户均无法打开流。
- [x] 编写用户支持步骤，包含状态检查和安全的错误收集方式，不要求用户提交 payload、headers 或凭据。（验证：`docs/operations/windows-edge-client-deployment.md` 记录离线配置校验、任务状态与脱敏连接计数、会话级 `HTTPS_PROXY`、loopback/局域网手工验收及最多 4 个有界日志文件的安全收集流程，明确禁止 payload、headers、cookie、Authorization、token、私钥与 TLS 明文）

## 阶段 5：真实端到端业务验证

- 开始时间：
- 结束时间：
- 开发总结：
- 验证记录：

- [ ] 在至少两名已授权 edge 用户同时运行 Codex，并确认两者均通过同一在线 egress agent 抵达固定模型网关。
- [ ] 观察 server 与 agent 元数据，确认每名用户的 stream 身份、连接数、字节计数和关闭状态独立且可追溯。
- [ ] 验证模型网关 TLS 仍由 Codex 端到端协商，中间节点无证书替换、TLS 解密或请求内容记录。
- [ ] 记录真实环境的成功标准、前置条件与不包含秘密的诊断证据，作为发布验收附件。
- [ ] 检查 Codex 退出、代理退出和 agent 退出后，所有对应 stream 与 socket 在规定超时内清理。

## 阶段 6：强制安全负向验证

- 开始时间：2026-07-18 18:36:31 +08:00
- 结束时间：
- 开发总结：
- 验证记录：仓库级强制负向验证已完成：主流程运行 `shared` 36/36、`server` 52/52（显式排除 `src/end-to-end.test.ts`）、`egress-agent` 31/31、`edge-client` 36/36、`server-host` 12/12、`egress-agent-host` 21/21、`edge-client-host` 27/27，并通过全仓 lint、typecheck、build 和 `git diff --check`。新增完整目标绕过矩阵、server/agent 独立 fail-closed 证据、capability 过期/伪造/replay 零新增拨号、跨 host 生产表面审计和恶意日志输入回归；修复 server 启动日志暴露地址/URL、host 异常码过宽及 server 日志 writer 故障影响运行时清理的问题。未执行真实 WSS、模型网关、Task Scheduler、公司网络或外部端口扫描。

- [x] 从 edge-client 测试其他 hostname、相似子域、IP literal、IPv6 literal、端口 `80` 与其他非 `443` 端口，确认均被拒绝。（验证：`edge-client/src/connect-proxy.test.ts` 覆盖不同/前后缀/子域/尾点 hostname、IPv4 多形态、IPv6 和 `80/444/8443`，所有拒绝输入均不调用 gateway 且不创建 stream；大小写等价精确 hostname 按规范化策略接受）
- [x] 直接构造越过 edge 预检的 WSS `stream.open`，确认 server 早拒绝且 agent 最终拒绝并且没有产生 TCP 拨号。（验证：`server/src/stream-open.test.ts` 直接构造 raw `STREAM_OPEN` 证明非批准目标/端口/错误 agent 均不转发；`egress-agent/src/dialer.test.ts` 独立对同矩阵最终复验且 `FakeConnector.calls` 保持为 0）
- [x] 测试伪造/过期/replay capability、错误 agent ID、跨用户 stream ID、超额并发和 credit 违规。（验证：agent 新增过期/签名篡改/replay 零新增拨号回归；现有 `shared` capability 绑定、`server` 跨用户/跨 peer 所有权与配额、server/agent buffer-credit 违规用例全部通过）
- [ ] 验证 server、edge 和 agent 均不存在可发现的公共 SOCKS、HTTP CONNECT、TCP、命令执行、文件访问或调试监听器。
- [x] 审查所有组件测试与生产日志，验证没有 payload、cookie、Authorization、token、密钥或 TLS 明文。（验证：三个 host 行为测试向 CLI/logger 注入 URL、CONNECT authority/header、身份/key ID、token、capability、TLS 字节和恶意异常码，输出只保留白名单事件/稳定码；server audit allowlist 由共享协议常量派生，writer 故障不影响 listener/reload/shutdown）

## 阶段 7：故障演练、容量与恢复

- 开始时间：
- 结束时间：
- 开发总结：
- 验证记录：仓库级容量阈值与安全降级规则已完成：运行时保持显式 stream、buffer、timeout 和 reconnect 上限，`docs/operations/incident-response.md` 定义 70%/85%、单主体 80%、重连/心跳/TLS 等告警条件及拒绝新流、关闭关联流、撤销身份、停止组件的降级顺序；未执行真实故障与容量演练。

- [ ] 在活跃流期间分别断开 edge WSS、agent WSS 和 server，确认旧流关闭、无 stale route，并按有界退避重连。
- [ ] 演练 agent 重启、server 滚动重启、网络抖动、目标 TCP 超时和慢消费者，验证内存、句柄和流计数回落至稳定水位。
- [ ] 使用多个授权 edge 用户共享一个 agent 的并发场景验证全局与每用户配额，确认单用户超额不会阻塞其他用户。
- [ ] 验证身份撤销和授权取消在目标时限内阻止新流，并按设计关闭受影响存量流。
- [x] 定义容量阈值、告警条件和安全降级行为；达到限制时仅拒绝新流或关闭关联流，不拓宽路由。（验证：`docs/operations/incident-response.md` 的“容量阈值与告警”定义 warning/critical 条件及 fail-closed 降级顺序；各组件现有 `ResourceLimits`、stream/buffer credit、timeout 和 bounded reconnect 测试证明达到上限不会拓宽目标或路由）

## 阶段 8：运维资料、发布与回滚演练

- 开始时间：2026-07-18 19:21:39 +08:00
- 结束时间：2026-07-18 20:20:59 +08:00
- 开发总结：完成最终架构与运维资料，交付协议/配置 schema 兼容策略、安全升级回滚流程，以及基于精确 runtime allowlist 的 release stage、逐文件与聚合 SHA-256 inventory、目标侧复验和凭据/范围边界扫描；生产候选明确排除测试、helper、source map、类型声明、构建缓存、coverage 与部署配置/身份/TLS 材料。
- 验证记录：主流程从 `corepack pnpm clean` 状态运行 `corepack pnpm verify:repository-without-e2e`，全仓 lint、build、typecheck 与 24 个测试文件 237/237 均通过，Server 测试显式排除 `src/end-to-end.test.ts`；`ops` release 聚焦测试 22/22 通过。主 agent 另在临时目录实际执行 stage -> inventory -> validate，三次结果均为 v0.1.0、protocol 2、87 files、617210 bytes、SHA-256 `e812589e3873bef72f6b6fb8a36213b0a86c55d003b18f3bea6cb38a5248cb6d`，候选中 test/map/d.ts/cache/coverage 为 0；`pnpm install --prod --offline --frozen-lockfile --ignore-scripts` 后四个 production workspace import 成功且 listener 为 0。未运行完整 `pnpm test`、真实 WSS/网关、task/systemd、公司网络或预生产发布回滚演练。

- [x] 更新 `README.md` 与 `docs/architecture.md`，反映最终协议、共享 agent 授权模型、部署拓扑、端口边界和已验证的限制。（验证：两份文档记录 `protocolVersion=2` 二进制帧、三角色 Ed25519 身份链、共享 Agent ACL/capability、三 host 拓扑、`8000-9000` listener、精确网关 `hostname:443`、Edge 先绑定受限 proxy 后启动 runtime，以及自动验证与真实网络验收边界）
- [x] 编写部署、升级、密钥轮换、授权变更、用户撤销、故障定位、日志脱敏和事件响应 runbook。（验证：`docs/operations/README.md` 汇总既有三组件部署与身份授权文档，并新增 `release-and-rollback.md`、`incident-response.md` 覆盖版本产物、升级/回滚、容量阈值、安全降级、脱敏取证和事件处置）
- [x] 记录版本兼容策略：协议版本不匹配时拒绝连接，升级期间不恢复旧流，并提供安全回滚步骤。（验证：`docs/operations/release-and-rollback.md` 明确 v2 无降级协商、兼容/不兼容升级顺序、旧 stream/TCP 不恢复、独立审批 hash 目标侧复验和只读 candidate 回滚；release 测试覆盖 protocol/manifest/host schema 漂移拒绝）
- [ ] 在预生产或等价隔离环境完成一次发布和回滚演练，验证不会遗留公开监听器、过期配置或活跃陈旧流。
- [ ] 执行完整 `pnpm lint`、`pnpm typecheck`、`pnpm test`、`pnpm build`，归档不含秘密的输出与验收记录。

## 阶段 9：第一版发布门禁

- 开始时间：
- 结束时间：
- 开发总结：
- 验证记录：

- [ ] 对照所有 checklist 的未完成项，确认没有通过未实现的认证、授权、最终目标验证、背压或清理要求。
- [ ] 独立复核共享 agent 的多用户隔离：身份、device、agent ACL、capability、stream 所有权、配额、日志和撤销。
- [ ] 完成安全审查，确认不存在向其他 host/port、命令执行、远程桌面、文件管理、VPN 或通用代理扩展的路径。
- [ ] 批准生产发布版本、回滚版本和联系人；部署后复测健康、agent 在线和 edge CONNECT 行为。

## 最终完成定义

以下项目作为 Remote Codex 第一版整体完成标准，必须在三个实现 checklist 与本清单完成后统一验收。

- 开始时间：
- 结束时间：
- 验收总结：

- [ ] 任一已授权 edge 用户运行 Codex 时，流量只可经本机 loopback edge-client、public server 和被授权 company agent 到达精确配置的模型网关 `:443`。
- [ ] 至少两名 edge 用户可同时绑定同一个 agent，且无法读取、控制、占用或审计对方的流量与资源。
- [ ] agent 拒绝任何不同 hostname、IP literal、非 `443` 端口、过期/伪造 capability 与通用 TCP 代理企图，并且不建立相关出站连接。
- [ ] edge proxy 从非 loopback 接口不可用；agent 不需要也不暴露任何入站连接；server 是唯一公网 HTTPS/WSS 暴露面。
- [ ] WSS 中断会关闭关联 stream，重连使用有界退避且不恢复旧 TCP 路由；所有资源计数、socket 和队列可验证地清理。
- [ ] 可观测性只包含 stream 元数据，所有日志、测试报告和运维资料均不含 payload、TLS 明文或凭据。
