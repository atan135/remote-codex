# 03：远程隧道代理端与端到端集成 Checklist

## 目标

在共享库和 server 完成后交付 company 侧 `egress-agent` 与 edge 侧
`edge-client`。edge-client 提供仅 loopback 的 HTTP CONNECT，egress-agent
只会在 capability、静态 allowlist 与资源控制均通过后拨号固定模型网关。两端
共同保证多个 edge 用户可安全共用一个 agent。

## 基础原则

- [x] TCP 数据全程不透明转发；不得解密、检查、修改、缓存或记录 HTTPS payload。（验收：`server/src/end-to-end.test.ts` 以 TLSv1.3 经过 CONNECT 回显两条应用 payload，并断言 edge/agent WSS 捕获不到其明文；阶段 7 零日志回归及本次 152 项全仓测试通过）
- [x] egress-agent 是最终安全边界，即使 server 或 edge-client 出现缺陷也不能打开其他目标。（验收：`egress-agent/src/dialer.test.ts` 覆盖 capability、精确 hostname、443 端口与 agent 配额的最终准入；IP、别名、其他 hostname/端口及篡改 capability 均在拨号前拒绝，connector 调用数为 0）
- [x] edge-client 没有公共监听器，agent 没有入站监听器；两者只向 server 发起 WSS 连接。（验收：`edge-client/src/connect-proxy.test.ts` 确认仅 `127.0.0.1` 可连接且 `127.0.0.2`、`::1` 被拒绝；阶段 7 静态检查确认 agent 无 `createServer` 或 `.listen`）
- [x] 所有 socket 与 WebSocket 生命周期都必须受状态机、超时、配额和背压约束。（验收：runtime、proxy、dialer 的断线、重复 close、空闲/连接超时、WSS 水位、credit、配额与陈旧回调回归通过；端到端测试覆盖四类中断后清理旧流并新建流）

## 阶段 1：Egress Agent 运行时与持久 WSS 会话

- 开始时间：2026-07-16 17:43:59 +08:00
- 结束时间：2026-07-16 18:11:33 +08:00
- 开发总结：已实现受限 egress-agent WSS runtime、v2 challenge 认证、心跳、有限抖动退避与断线资源清理挂钩；协议 v2 将签名所需的 `issuedAtMs` 纳入 CHALLENGE wire payload，旧 v1 peer 被确定性拒绝。本阶段未创建任何目标 TCP socket 或 listener。
- 验证记录：主流程运行 shared 35 项、server 46 项、egress-agent 10 项测试及 `corepack pnpm test:coverage`（全工作区 92 项，85.34%）通过；egress-agent lint/typecheck/build 通过。

- [x] 实现 agent 配置加载、独立服务身份、WSS 建连、注册、认证心跳和明确的在线/离线状态。（审核：`EgressAgentRuntime` 严格加载本地 config，绑定 agent Ed25519 身份并实施 REGISTER/CHALLENGE/AUTHENTICATE/HEARTBEAT 状态机）
- [x] 采用带抖动的指数退避、重连次数与等待上限；认证失败和配置错误不可无限重试。（验证：`calculateReconnectDelayMs` 与 runtime 测试覆盖 50%-100% 抖动、上限、失败终止和重试耗尽）
- [x] 将 agent ID、最大并发流和固定允许目标视为本地部署配置，拒绝从 `stream.open` 覆盖。（审核：runtime 只从解析后的 `EgressAgentConfig` 生成不可变 local policy；本阶段任何 stream 帧均拒绝而不改变 policy）
- [x] 断开 WSS 时关闭全部关联 TCP socket、停止数据读取并清空本地映射；重连后只接受新流。（审核：断线和停止都调用注入的 `streamResources.closeAll()`；旧 `AgentConnection` 通过 finalized/active identity 隔离。本阶段尚无 TCP socket，阶段 2 将接入该清理边界）
- [x] 为首次连接、认证失败、心跳失效、退避边界和多次断线清理添加测试。（验证：`egress-agent/src/runtime.test.ts` 10 项覆盖首次认证、认证失败、心跳、退避、重复清理、异常帧、停止与 TLS 禁用）

## 阶段 2：Agent 最终授权与受限 TCP 拨号

- 开始时间：2026-07-16 18:13:18 +08:00
- 结束时间：2026-07-16 18:36:55 +08:00
- 开发总结：已实现 agent 最终 capability 验证与受限 TCP dialer；仅在线 WSS 会话、签名/时效/完整 binding、静态 hostname:443、未占用 stream 与 agent 配额同时满足后才调用 connector。连接、空闲、EOF、错误、远端 close 与 WSS 断开均走幂等清理；成功连接后的 opened/data/credit 留给阶段 3。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/egress-agent test`（16 项）与 `corepack pnpm test:coverage`（全工作区 99 项，85.08%）通过，egress-agent lint/typecheck/build 与 diff 检查通过。

- [x] 在收到 `stream.open` 时依次验证 agent 会话归属、capability 签名/时效/绑定字段、流状态、静态目标和 agent 并发配额。（审核：runtime 只向当前 online WSS session 创建 dialer session；`EgressAgentDialer` 按 capability、stream、目标、状态、配额顺序准入）
- [x] 在 DNS 之前运行严格目标验证器，并仅用 agent 配置内的精确 hostname 和 `443` 创建 TCP 连接。（验证：connector 只接收 `validateDestination` 返回的本地配置 hostname:443；非法测试断言 connector calls 为空）
- [x] 设定 TCP 连接超时、socket 错误映射、每流空闲计时和安全的半关闭/完整关闭处理。（验证：dialer 覆盖 connect timeout、独立 idle timeout、error、EOF、两阶段 close 与 closeAll；多 timeout callback 回归通过）
- [x] 严禁实现任意 host/port 连接、代理链、HTTP 请求转发、DNS 查询接口或入站 TCP listener。（审核：生产 agent 仅使用 `node:net` 的受限 `connect({host: allowedHostname, port:443})`；无 HTTP/DNS/listener API）
- [x] 用注入式 connector 验证合法目标可连接，所有 IP、近似域名、其他端口、篡改 capability 与无 capability 均在拨号前失败。（验证：`dialer.test.ts` 对合法 connector 参数与 IP/近似 host/444/篡改/缺失/错 agent/错 stream 的零拨号断言通过）

## 阶段 3：Agent 数据转发、背压与多用户公平性

- 开始时间：2026-07-16 18:38:32 +08:00
- 结束时间：2026-07-16 19:15:07 +08:00
- 开发总结：已在 TCP connect 成功后发送 opened 与初始 credit，实现不透明 TCP/WSS data 转发、TCP drain 后 credit 回补、per-stream FIFO、公平 WSS 恢复与 pause/resume。组合 lifecycle/local queue 预算与 payload 感知 WSS 高水位共同约束 agent 内存；EOF、错误、credit 违规、超时、WSS 断开均幂等清理。
- 验证记录：主流程运行 egress-agent lint/typecheck/build 和 `corepack pnpm test:coverage`，全工作区 111 项通过，statements/lines 为 85.13%。

- [x] 仅在收到 `opened` 所需的连接成功条件后发送 `stream.opened`，并按协议将 TCP 字节包装为 data 帧。（验证：dialer 仅在 TCP `connect` 后发送 `STREAM_OPENED` 与初始 credit；透明 data 与字节顺序测试通过）
- [x] 将 TCP `pause`/`resume`、WebSocket 高水位和 per-stream credit 结合，确保慢 edge 不造成无界 agent 内存增长。（审核：payload 感知 WSS 水位、TCP drain credit、组合 lifecycle/queue per-stream+aggregate 准入；近阈值与两流预算回归通过）
- [x] 以 stream 为隔离单位维护队列和计数，确保同一 agent 上一个用户的慢连接、关闭或配额超出不污染另一用户流。（验证：两个 capability 中不同 edge user/device 的流分别 FIFO 调度；慢 TCP、超额 credit 和关闭只影响所属流）
- [x] 在 TCP EOF、错误、agent 限额、credit 违规、空闲超时和 WSS 断开时发送或本地执行幂等 close。（验证：dialer 测试覆盖 connect/idle timeout、EOF、write/error、远端 close、closeAll、异常 WSS send 与重复清理）
- [x] 用两个不同 edge 用户的模拟流、慢 TCP 读取端和慢 WSS 接收端验证吞吐、公平性、顺序和缓冲上限。（验证：`egress-agent/src/dialer.test.ts` 覆盖双用户、慢 write/drain、慢 WSS、payload 顺序和组合上限；全工作区 111 项通过）

## 阶段 4：Loopback HTTP CONNECT 代理

- 开始时间：2026-07-16 19:16:49 +08:00
- 结束时间：2026-07-16 19:34:58 +08:00
- 开发总结：新增严格的 `LoopbackConnectProxy`，固定仅监听 `127.0.0.1`；它在本地完成 CONNECT 语法与精确目标 allowlist 校验，等待 gateway `opened` 后才建立透明转发，并在超时、拒绝、关闭和背压情况下清理本地映射。
- 验证记录：主流程运行 `corepack pnpm lint`、`corepack pnpm typecheck`、`corepack pnpm build` 和 `corepack pnpm test:coverage`；123 项测试通过，全局 statements/lines 均为 85.18%。

- [x] 只在配置的 IPv4/IPv6 loopback 地址绑定 HTTP server，默认 `127.0.0.1`，并拒绝非 loopback remote address。（审核：`edge-client/src/connect-proxy.ts` 固定 `server.listen({ host: "127.0.0.1" })` 并校验 remote address；`shared/src/config.ts` 进一步拒绝 `::1`；网络测试确认 `127.0.0.2` 无法连接）
- [x] 仅支持语法严格的 `CONNECT host:port HTTP/1.1`；拒绝普通 HTTP 请求、绝对 URL、认证转发、升级、请求体与多余字节。（审核：`parseConnectDestination` 仅接受 hostname`:443` 与 HTTP/1.1，禁止头字段和 `head`；网络测试覆盖 GET、绝对 URL、认证、body、upgrade 和额外字节）
- [x] 在创建 stream 前执行目标规范化和精确 allowlist 检查；将非允许目标返回固定 CONNECT 错误而不通知 server。（审核：`validateDestination` 在 `streamGateway.open` 前执行；错误 host、端口、IP literal 和认证请求均断言 gateway 未收到 open）
- [x] 本地连接在 server/agent 返回 `opened` 前保持暂停；成功后返回规范的 `200 Connection Established` 并开始透明双向转发。（审核：建立后立即 `socket.pause()`，仅处理 `opened` 时回复 200/resume；测试覆盖双向字节转发、opened 前独立字节拒绝和双向背压恢复）
- [x] 为 loopback 成功、非 loopback 访问、错误方法、错误 host/port、畸形 authority、agent 拒绝和打开超时添加网络测试。（验证：`edge-client/src/connect-proxy.test.ts` 12 项网络与生命周期测试覆盖上述情形；`corepack pnpm test:coverage` 123 项全通过）

## 阶段 5：Edge WSS 会话与本地连接映射

- 开始时间：2026-07-16 19:36:13 +08:00
- 结束时间：2026-07-16 20:14:52 +08:00
- 开发总结：实现 `EdgeClientRuntime` 作为 CONNECT gateway 的唯一 WSS 会话与 stream 所有者，完成 edge 身份 challenge、心跳、有界重连、流控、严格 stream 所有权与断线清理。close 发起即进入 `closing`，立即撤销本地流可用性，直到异步 WSS close 后才重连。
- 验证记录：主流程运行 `corepack pnpm lint`、`corepack pnpm typecheck`、`corepack pnpm build` 和 `corepack pnpm test:coverage`；142 项测试通过，全局 statements/lines 均为 85.35%。覆盖率连续运行两次均为 85.35%。

- [x] 实现 edge 用户/设备身份的 WSS 注册、心跳、会话失效处理和有界重连；认证材料不进入代理日志或 URL。（审核：`EdgeClientRuntime` 使用本地 user/device 身份签名 challenge、仅连接已解析 `wss:` URL、心跳与认证超时/退避均受 limits 约束；私钥仅由 runtime options 注入，未暴露给 CONNECT 或日志）
- [x] 将每个已接受 CONNECT 映射到一个待开 stream，校验返回帧的 stream ID 和状态归属，禁止跨连接写入。（审核：每流以随机 stream ID、生命周期和 connection 引用建映射；未知、重复、非法方向和旧会话帧均使所属会话失败，测试确认不会写入新会话 listener）
- [x] 只转发 server 授权的 data/credit/close；本地 socket 关闭、客户端中止和代理停止时及时发送幂等 close。（审核：online 状态仅处理允许的 stream frame 与 lifecycle 迁移，data/credit 均经预算和 WSS 水位约束；local close、错误与 stop 均幂等释放映射，close 发送失败会使整会话失效）
- [x] WSS 断开时关闭所有本地已建立与待建立连接，不保留可在新会话重用的 TCP 流或 capability。（审核：`closing` 状态立即 `closeAllStreams`、取消心跳和发送调度；异步 close 回调后才 backoff/reconnect；edge open 使用固定不可验证哨兵，server 才签发绑定新 session 的 capability）
- [x] 为 edge 重连、错误 stream ID、局部流关闭、客户端抢先关闭和无 server 可用时的确定性失败添加测试。（验证：`edge-client/src/runtime.test.ts` 19 项覆盖握手、重连、TLS、未知 ID、旧会话、局部 close、WSS 发送失败、延迟 close 和离线拒绝；全工作区 142 项通过）

## 阶段 6：三方端到端测试夹具

- 开始时间：2026-07-16 20:16:05 +08:00
- 结束时间：2026-07-16 20:41:39 +08:00
- 开发总结：新增真实三方端到端夹具，使用临时 TLS 证书、一个 agent、两个独立 edge 和 loopback CONNECT。测试 connector 仅在断言配置 hostname`:443` 后桥接动态本地网关；双用户配额、流 ID、关闭和审计字节计数均独立，四类中断后只允许新流重连。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/server test`（51 项通过）、`corepack pnpm lint`、`corepack pnpm typecheck`、`corepack pnpm build` 和 `corepack pnpm test:coverage`；全工作区 147 项通过，statements/lines 为 85.54%。

- [x] 建立临时证书、受控 server、一个受控 agent、两个独立 edge 用户/设备和固定测试网关的端到端夹具。（验证：`server/src/end-to-end.test.ts` 为每例生成短期 tunnel/gateway TLS 证书，真实启动 server、agent、edge A/B 和两个 loopback CONNECT proxy）
- [x] 让测试网关以配置的 hostname 解析到本地测试地址，确保测试仍经过 hostname 验证而不放宽为 IP literal。（审核：配置与 capability 绑定始终使用 `gateway.integration.test:443`；测试 connector 仅接受该精确值再拨号 `127.0.0.1`，TLS 使用该 hostname SNI、临时 CA 和 `rejectUnauthorized: true`）
- [x] 通过 edge-client 的 CONNECT 建立 TLS 客户端到测试网关的会话，并验证 application bytes 原样到达且中间组件无法读取其内容。（验证：CONNECT 返回 200 后建立 TLSv1.3 客户端并回显；edge/agent WSS 仅捕获 `STREAM_DATA` 密文字节，断言不含两条应用 payload）
- [x] 同时运行两名用户的请求，验证它们共享一个 agent 但没有流、配额、关闭或字节计数串扰。（验证：两个授权各限 1 条流、共享 agent/global 上限为 2，双流并发成功；A 关闭后 B 可继续；metadata-only closed audit 分别断言 user/device、stream ID 及双向字节计数）
- [x] 在中途断开 server、edge WSS、agent WSS 与目标 TCP，验证流均清理且后续重连只能创建新流。（验证：5 项端到端测试逐类注入上述断开，等待 edge/agent/server 流清零、重新认证在线后断言新 server stream ID 不等于旧值）

## 阶段 7：端侧安全回归与诊断

- 开始时间：2026-07-16 20:42:57 +08:00
- 结束时间：2026-07-16 20:55:51 +08:00
- 开发总结：补充 edge/agent 安全回归，覆盖 IPv4-only listener、最终目标拒绝零拨号、认证与 CONNECT 零日志、以及 proxy/dialer 在停止、重复 close 和陈旧回调后的确定性资源回收；未改变生产代码。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/edge-client test`（35 项通过）、`corepack pnpm --filter @remote-codex/egress-agent test`（30 项通过）、`corepack pnpm lint`、`corepack pnpm typecheck`、`corepack pnpm build` 和 `corepack pnpm test:coverage`；全工作区 152 项通过，statements/lines 为 85.69%。

- [x] 验证 edge 不会在 `0.0.0.0`、局域网地址或公网地址监听，且 agent 没有 TCP 入站监听器。（验证：proxy 网络测试确认固定 `127.0.0.1` 且 `127.0.0.2`、`::1` 无法连接；edge 源码禁止其他 listen 值；agent runtime/dialer 静态检查无 `createServer`/`.listen`）
- [x] 验证 agent 对其他 hostname、相同 IP 的其他名称、IP literal 和非 `443` 端口均不产生网络拨号。（验证：signed `STREAM_OPEN` 经 agent runtime/dialer 的记录 connector 测试覆盖 IPv4/IPv6 literal、同 IP 别名、其他 hostname、篡改 capability 与非443 payload，所有拒绝分支 connector 调用数为 0）
- [x] 审查 edge 和 agent 日志，确保仅含组件状态、stream ID、字节计数和错误码，不含 CONNECT headers、payload 或凭据。（验证：edge proxy/runtime 和 agent runtime/dialer 静态拒绝 console/logger/stdout/stderr 写出；CONNECT header 与 REGISTER→CHALLENGE→AUTHENTICATE 路径的 console/stdout/stderr spies 均为 0）
- [x] 为崩溃、进程退出、重复 close、异常帧和资源耗尽执行泄漏检查与句柄清理测试。（验证：proxy stop 关闭 pending socket 和 stream；dialer `closeAll()` 两次销毁 pending/connected TCP，陈旧 connect/data 无效；既有 runtime 测试覆盖异常帧、WSS 错误、超时、限额和幂等 stop）
- [x] 执行 `pnpm --filter @remote-codex/egress-agent test`、`pnpm --filter @remote-codex/edge-client test` 及全工作区质量检查。（验证：edge 35 项、agent 30 项、全工作区 152 项测试以及 lint/typecheck/build 全部通过）

## 阶段 8：代理端文档与 Codex 接入说明

- 开始时间：2026-07-16 21:01:04 +08:00
- 结束时间：2026-07-16 21:11:46 +08:00
- 开发总结：README、架构、共享契约和无密钥配置示例已同步至 HTTP CONNECT-only 实现；说明 edge runtime/loopback proxy 前置顺序、Codex `HTTPS_PROXY` 接入、共享 agent 的 server 注册表授权、断线清理和 agent 最终验证。仓库规范同步明确 SOCKS5 不在范围内。
- 验证记录：主流程解析 `docs/configuration-example.md` 的 2 段 JSON，检查 README 链接、`git diff --check` 与陈旧/宽松表述搜索；全部通过，README/架构/配置示例未含凭据或生产网关值。

- [x] 更新 `README.md`，说明 edge-client 必须先启动，以及以 `HTTPS_PROXY` 指向 loopback CONNECT 端口的方式。（验证：README 记录 server→agent→edge runtime→`LoopbackConnectProxy` 顺序，并给出 PowerShell `HTTPS_PROXY=http://127.0.0.1:8787` 与清除方式；未虚构 CLI）
- [x] 更新 `docs/architecture.md`，记录 HTTP CONNECT 范围、端侧断线语义、TLS 不透明性与 agent 最终验证顺序。（验证：架构文档明确严格 CONNECT、opened 前暂停、断线关闭 pending/open、TLS 不透明，以及 capability binding→静态 hostname:443→connector 的最终顺序）
- [x] 编写不含真实密钥的 agent/edge 配置示例，明确共享 agent 的用户授权由 server 注册表控制。（验证：`docs/configuration-example.md` 的 2 段 JSON 均可解析，只含 `.invalid` hostname 和占位 ID；说明私钥独立注入与 server 注册表的唯一 user/device→agent 路由）
- [x] 明确记录不支持 SOCKS5、HTTP 非 CONNECT 转发、公共 edge listener、代理重定向和任意 TCP 目标。（验证：README、架构、配置示例及 `AGENTS.md` 均明确 HTTP CONNECT-only、SOCKS5 不在范围；陈旧/宽松表述搜索无命中）

## 最终完成定义

以下项目作为本清单的完成标准，不要求每个开发阶段都执行，由所有相关阶段完成后统一验收。

- 开始时间：2026-07-16 17:43:59 +08:00
- 结束时间：2026-07-16 21:15:05 +08:00
- 验收总结：阶段 1 至 8 已完成并分别提交为 5 个 edge/integration/security/docs 提交。最终复跑全仓覆盖率测试、lint、typecheck 与 build 均通过；实现支持多个已授权 edge 用户绑定并共享同一个 agent，同时维持 stream、配额、背压、关闭和审计隔离。`summary/` 仅保留本次进度记录，不随代码提交。

- [x] 任何合法 edge 用户均只能经 loopback CONNECT 到固定网关，并通过被授权的共享 agent 建立端到端 TLS。（验收：`server/src/end-to-end.test.ts` 的双用户共享 agent 测试经过严格 hostname 校验、edge loopback CONNECT 与 TLSv1.3 回显；152 项全仓测试通过）
- [x] 任何试图改变 hostname、port、agent 归属或复用旧流的行为均在正确边界被拒绝且不产生越权连接。（验收：shared/edge/agent 目标与 capability 回归覆盖 IP、近似域名、非443、错误 agent/stream、篡改/过期 capability 与旧会话；所有 agent 拒绝分支均零拨号）
- [x] 同一个 agent 可同时承载多名授权用户，但流、背压、配额、关闭与审计均彼此隔离。（验收：端到端夹具同时运行两个 user/device，各自上限 1、共享 agent 上限 2；关闭 A 后 B 持续可用，metadata-only 审计分别校验 user/device、stream ID 与双向字节计数）
