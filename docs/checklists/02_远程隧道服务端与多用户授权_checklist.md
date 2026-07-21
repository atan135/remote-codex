# 02：远程隧道服务端与多用户授权 Checklist

## 目标

在“远程隧道基础协议”完成后交付 public server：认证 WSS peer、维护可用
egress agent、将多个被授权的 edge 用户/设备绑定到同一个 agent，并只中继
已经授权的二进制 stream。服务端不解析 TLS、不拨号目标主机、不保存请求内容。

## 基础原则

- [x] 共享 agent 是显式授权关系，不是“知道 agent ID 即可使用”；每个 stream 仍保留 edge 用户和设备归属。（审核：`AuthorizationRegistry` 按 user/device 解析唯一 agent 路由，`StreamOwnership` 绑定 edge user/device/agent，双用户共享 agent 集成测试通过）
- [x] server 的授权存储、服务身份和审计数据与 `remote-client` 完全独立。（验证：server 仅接收进程内 identity/authorization/signing 配置；代码与文档扫描未出现对方地址、凭据、数据库或运行时依赖）
- [x] server 只暴露 HTTPS/WSS；不会暴露 SOCKS、CONNECT、TCP 转发或管理 shell 监听器。（验证：`server/src/runtime.ts` 仅定义 `/health` 与 `/tunnel`；入口集成测试和生产源码静态检查通过）
- [x] 所有日志仅含安全审计所需的元数据，绝不含 payload、cookie、token、Authorization 或密钥。（验证：`serializeStreamAuditEvent` 字段白名单与 Authorization/Cookie 伪造 payload 回归测试通过）

## 阶段 1：服务端进程与 WSS 防护基线

- 开始时间：2026-07-16 13:48:30 +08:00
- 结束时间：2026-07-16 14:01:28 +08:00
- 开发总结：已实现唯一 HTTPS/WSS `/tunnel` 入口与 `/health`，使用显式 TLS 凭据、TLS 1.3、严格 Origin、受限升级和 WebSocket 消息上限；server 不建立目标 TCP。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/server lint/typecheck/test/build`，9 个集成测试全部通过。

- [x] 建立 HTTPS server 与单一受控 WSS endpoint，配置证书加载、TLS 最低版本、origin 策略、最大消息长度和握手超时。（审核：`server/src/runtime.ts` 仅提供 `/tunnel`，TLSv1.3、Origin 白名单、`maxPayload` 与 timeout）
- [x] 将健康检查与 WSS 端点隔离；健康检查只返回服务状态，不泄露 agent、用户、流或配置详情。（验证：`/health` 固定返回 `{"status":"ok"}`，`/tunnel` 非 Upgrade 返回 426）
- [x] 限制 WebSocket 升级前的请求体、headers、并发握手和连接速率，拒绝非预期 endpoint 和方法。（审核：升级 handler 的 body/header/rate/concurrency 检查）
- [x] 为 TLS/证书缺失、错误 WebSocket 路径、超大握手、超大 message 和健康检查添加集成测试。（验证：`server/src/index.test.ts` 9 项集成测试通过）

## 阶段 2：Peer 注册、认证与会话管理

- 开始时间：2026-07-16 14:03:18 +08:00
- 结束时间：2026-07-16 14:18:29 +08:00
- 开发总结：已在 server 完成 edge/agent 的二进制注册、挑战认证、随机 peer session、心跳和 agent 成功重连替换；认证失败或连接终止会撤销会话状态。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/server lint/typecheck/test/build`，2 个测试文件、15 个测试通过。

- [x] 实现 edge 与 agent 的独立注册流程，基于共享认证契约完成挑战/响应、身份类型校验与会话建立。（审核：`PeerSessionManager` 消费 shared 认证契约并仅接收二进制 connection frame）
- [x] 将每个连接会话绑定不可伪造的 peer ID、认证身份、协议版本、建立时间和心跳状态。（审核：服务端 `randomUUID` peer ID 与 `SessionRecord` 元数据）
- [x] 拒绝重复 nonce、错误角色、过期身份、版本不兼容和同一 agent 的异常并发会话，并定义受控替换策略。（验证：`peer-session.test.ts` 覆盖 nonce/角色/过期/版本及 agent 替换）
- [x] 在断开、认证失败和心跳失效时立即撤销会话可用性，清除临时认证状态。（审核：`removeSocket`、`reject`、`expireInactivePeers` 清理映射）
- [x] 为所有注册成功与拒绝路径、nonce 重放、心跳超时和 agent 重连替换添加测试。（验证：server 15 个专项测试通过）

## 阶段 3：多用户到共享 Agent 的授权注册表

- 开始时间：2026-07-16 14:20:14 +08:00
- 结束时间：2026-07-16 14:37:46 +08:00
- 开发总结：已实现以已注册 peer 身份为引用源的原子授权注册表，支持 user/device 到唯一 agent 路由、多用户共享 agent、热更新和按 user/device/agent 撤销。
- 验证记录：主流程执行 `corepack pnpm --filter @remote-codex/server lint/typecheck/test/build`，3 个测试文件、22 个测试通过。

- [x] 定义独立的授权注册表：`edgeUserId`、允许的 `edgeDeviceId`、`agentId`、状态、配额、创建/撤销时间及审计版本。（审核：`AuthorizationRegistration` 与严格文档 schema）
- [x] 实现 server 启动时的严格加载与原子热更新，配置不合法、引用未知身份或产生重复/冲突授权时拒绝生效。（验证：候选 state 构建失败保留旧路由的测试通过）
- [x] 允许多个不同 edge 用户和多个设备关联同一个已注册 agent，同时禁止用户借由请求参数选择未授权 agent。（验证：双用户共享 agent 与 spoofed agent 字段忽略测试通过）
- [x] 支持逐用户、逐设备和逐 agent 撤销；撤销后拒绝新流，并按策略关闭受影响的存量流。（审核：撤销 API 发布 `closeExistingStreams: true` 回调供 stream 层消费）
- [x] 为共享 agent 的合法并发用户、未授权 agent、设备冒用、授权热更新和撤销添加集成测试。（验证：`authorization-registry.test.ts` 与 WSS 联动测试纳入 server 22/22 通过）

## 阶段 4：打开流授权与 Capability 签发

- 开始时间：2026-07-16 14:39:45 +08:00
- 结束时间：2026-07-16 15:03:38 +08:00
- 开发总结：已实现 server 侧 stream 授权协调器：由已认证 edge 身份解析 agent 路由、签发内部 stream ID capability、保存单一所有权映射，并在 agent opened 前拒绝数据。
- 验证记录：主流程运行 `corepack pnpm lint/typecheck/build/test:coverage`，66 个测试通过，覆盖率 85.32%。

- [x] 接收 `stream.open` 后验证 edge 会话归属、授权注册表、请求目标、用户/设备配额和 agent 在线状态。（审核：`StreamOpenCoordinator.handleEdgeFrame` 的身份、route、target、quota、agent 检查）
- [x] 为每个被接受的流分配唯一 stream ID，签发绑定用户、设备、共享 agent、固定目标和短过期时间的 capability。（审核：server 创建内部 ID，并以 `issueCapability` 绑定全部字段）
- [x] 将 `open` 及 capability 只转交给指定 agent，并将 edge 会话、agent 会话和 stream ID 建立单一所有权映射。（审核：edge ID 与 server-agent ID 双映射且 agent ID 来自授权表）
- [x] 在 agent `opened` 前禁止任何 data 转发；对于拒绝、连接失败和过期 capability 给 edge 返回稳定错误码。（验证：coordinator 拒绝 data/credit，超时/agent error 路径测试通过）
- [x] 为双用户同 agent 并行开流、能力绑定错配、配额耗尽、agent 离线和打开超时添加测试。（验证：`stream-open.test.ts` 及全工作区 66 个测试通过）

## 阶段 5：多路复用中继与背压传播

- 开始时间：2026-07-16 15:05:51 +08:00
- 结束时间：2026-07-16 16:10:42 +08:00
- 开发总结：已实现基于 stream 所有权的双向 data、credit、close 中继；按授权和 edge 用户分别计数及限制缓冲，并在 WSS 发送队列受压时有界排队、恢复后按流公平发送。edge 断线会关闭 agent 侧对应 stream，agent 断线仅通知对应 edge；协议错误、资源超限与空闲只清理关联 stream。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/server lint`、`typecheck`、`test`，41 项测试通过；`corepack pnpm test:coverage`（全工作区 78 项，85.34%）与 `corepack pnpm build` 通过。

- [x] 按 stream 所有权和状态转发 data、credit、close；拒绝来自错误 peer、未知流和未打开流的帧。（审核：`server/src/stream-open.ts` 以 edge/agent 双映射和 `StreamLifecycle` 验证每帧；`stream-open.test.ts` 覆盖伪造 stream ID 与未打开流）
- [x] 将接收端 credit 和 WebSocket 发送排队状态反馈到发送端，维护每流及服务端聚合内存上限。（审核：`StreamBufferBudget` 与 `getSendBufferedBytes` 实施 per-stream/aggregate 限制；慢 WSS consumer 测试验证 credit/data 延迟及恢复）
- [x] 为不同 edge 用户的流分别计数和限额，确保单一用户的慢流或超额流不会饿死同一 agent 上其他用户。（验证：`streamCountsByEdgeUser`、用户授权缓冲计数与双用户共享 agent 测试；Alice 超额后 Bob 流仍可转发）
- [x] 在任一端断开、帧协议错误、限额超出或空闲超时时只关闭关联流，除非 peer 会话已失效。（验证：edge 断开向 agent 发送 `STREAM_CLOSE`，agent 断开仅通知存活 edge；发送失败、畸形帧、闲置和 agent error 的隔离测试均通过）
- [x] 用受控慢消费者和至少两个 edge 身份的并发测试验证隔离、顺序、背压和内存上限。（验证：`server/src/stream-open.test.ts` 覆盖双 edge 身份、正反向慢消费者、顺序恢复、聚合限制及断线隔离；server 41/41 通过）

## 阶段 6：配额、清理、审计与可观测性

- 开始时间：2026-07-16 16:12:04 +08:00
- 结束时间：2026-07-16 16:40:08 +08:00
- 开发总结：已在 server 内实现 user、device、agent、全局四维并发、开流频率和缓冲限制；所有终结路径通过幂等清理回收映射、计数、预算与队列。审计采用字段白名单，指标仅经受控进程内快照提供，未增加公网 endpoint。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/server lint`、`typecheck`、`test`，45 项测试通过；此前本阶段改动后的 `corepack pnpm test:coverage` 81 项通过，覆盖率 85.84%，新增频率回归仅增加测试覆盖。

- [x] 执行用户、设备、agent 和全局维度的并发流、打开频率、缓冲字节和空闲时间限制。（审核：`StreamOpenCoordinator` 的四维计数与 admission maps；受控时钟测试覆盖频率拒绝和窗口恢复）
- [x] 在流关闭后原子清理所有配对、计数器、计时器和待发送队列；关闭必须可重复调用。（审核：唯一 `removeStream` 终结路径释放 lifecycle budget、四维计数和待发送队列；异常帧与断线循环测试无映射/缓冲泄漏）
- [x] 记录 peer 身份、stream ID、agent ID、状态转换、字节计数、错误码和耗时，不记录目标之外的 payload 或认证材料。（审核：`server/src/observability.ts` 重建白名单 JSON；`stream-open.ts` 记录连接、打开与关闭元数据）
- [x] 暴露可聚合的健康与指标：已认证 edge/agent 数、每 agent 活跃流、按用户拒绝数、关闭原因和缓冲水位。（验证：`getMetrics()` 返回受控内存快照，`stream-open.test.ts` 覆盖 peer、agent 活跃流、拒绝数与水位）
- [x] 对日志序列化做敏感字段回归测试，并通过断线/异常帧压力测试检查没有计数或流映射泄漏。（验证：`observability.test.ts` 排除 payload/Authorization/cookie/capability/privateKey；45 项 server 测试通过）

## 阶段 7：服务端安全与并发集成测试

- 开始时间：2026-07-16 16:41:57 +08:00
- 结束时间：2026-07-16 16:53:02 +08:00
- 开发总结：已新增共享 agent 多用户安全集成场景，覆盖授权隔离、stream/data/credit/close 越权、capability 错配、撤销、离线 agent、配额及审计脱敏；生产 server 静态检查未发现目标 TCP 拨号 API。
- 验证记录：主流程运行 `corepack pnpm --filter @remote-codex/server test`，46 项通过；`corepack pnpm test:coverage` 全工作区 83 项通过，覆盖率 86.14%。

- [x] 建立内存身份与授权注册表测试夹具，覆盖一个 agent 同时服务至少两个独立 edge 用户。（验证：`stream-open.test.ts` 的 Alice/Bob 通过同一 shared agent 开流并各自接收所属 frame）
- [x] 验证用户 A 不能观察、写入、关闭或消耗用户 B 的 stream credit，即使两者使用同一 agent。（验证：Bob 伪造 Alice credit/data/close 全部收到 `PROTOCOL_VIOLATION`，Alice stream 保持可用）
- [x] 验证未授权用户、已撤销设备、离线 agent、错误 capability、错误 peer 和超过配额均无法转发字节。（验证：集成用例断言 capability binding、错误 agent peer、未授权 edge、每用户配额、设备撤销和 agent 下线拒绝路径）
- [x] 验证 server 不产生任何目标 TCP 连接，并且测试日志中没有 payload 或凭据。（验证：生产 `server/src` 仅含 HTTPS/WSS listener、无 `node:net`/`node:tls` 目标拨号 API；审计断言排除伪造 Authorization/Cookie）
- [x] 执行 `pnpm --filter @remote-codex/server lint`、`typecheck`、`test`、`build` 与全工作区检查。（验证：server 46/46、全工作区 83/83 及 build 通过）

## 阶段 8：服务端接口与运维文档

- 开始时间：2026-07-16 16:54:30 +08:00
- 结束时间：2026-07-16 17:05:16 +08:00
- 开发总结：已以中文更新 README 与架构文档，准确区分已实现的 shared/server 和待实现的 edge/egress；补齐共享 agent 隔离、capability、受控授权登记/撤销、agent 下线和密钥轮换步骤，并统一 edge listener 为严格 `127.0.0.1`。
- 验证记录：主流程复查 Markdown、`git diff --check` 与敏感关键词；未发现可用秘密、URL、Bearer 或 `remote-client` 资源引用，后者仅作为隔离禁止说明出现。

- [x] 更新 `docs/architecture.md`，说明 edge-user/device-to-agent 授权关系、共享 agent 隔离和 capability 字段。（审核：架构文档定义授权三元组、五维隔离计数与完整 capability 受签名字段）
- [x] 更新 `README.md`，列出 server 的职责、必要配置类别和明确非目标。（审核：README 区分当前实现状态，列出 TLS、Origin、peer 身份、授权、签名、资源与审计配置类别）
- [x] 编写授权注册、用户/设备撤销、agent 下线和密钥轮换的受控操作步骤，不在示例中放置可用秘密。（审核：架构文档四组编号步骤只使用抽象身份与配置描述；无 token、私钥或证书正文）
- [x] 审查所有 server 配置和日志样例，确认未引用 `remote-client` 的地址、凭据、数据库或部署资源。（验证：关键词扫描仅保留隔离禁止说明；未发现 URL、Bearer、私钥块或可用秘密）

## 最终完成定义

以下项目作为本清单的完成标准，不要求每个开发阶段都执行，由所有相关阶段完成后统一验收。

- 开始时间：2026-07-16 13:48:30 +08:00
- 结束时间：2026-07-16 17:08:28 +08:00
- 验收总结：服务端认证、显式多用户授权、capability、中继、流控、配额、审计、指标、集成测试与中文运维文档均已完成并提交。验收范围为 server 授权/中继层；edge-client 实际代理和 egress-agent 目标拨号仍由后续清单实现，尚不能声明完整端到端网络隧道可部署。

- [x] 多个明确授权的 edge 用户可同时请求同一个在线 agent，且授权、配额、stream ID、字节与审计记录保持隔离。（验证：`server/src/stream-open.test.ts` 的共享 agent 集成场景覆盖 Alice/Bob 同时开流、伪造 credit/data/close 拒绝与审计元数据隔离）
- [x] 任何未认证、未授权、撤销或越权的 peer 都无法获得可用 stream 或转发 payload。（验证：peer 认证、未授权 edge、capability binding、错误 peer、设备撤销、agent 离线及配额拒绝测试纳入 server 46/46）
- [x] server 只中继经授权的二进制帧，从不建立模型网关或其他目标的 TCP 连接。（验证：`server/src` 静态检查仅含 HTTPS/WSS broker listener、无目标 TCP 拨号 API；全工作区 lint/typecheck/build 与 83 项测试通过）
