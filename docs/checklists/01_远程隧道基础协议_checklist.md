# 01：远程隧道基础协议 Checklist

## 目标

交付 Remote Codex 第一版的共享基础：Node.js 22 + TypeScript + pnpm
workspace、受限配置、二进制 WSS 帧、流状态机、流量控制、身份与能力凭据。
本清单不实现监听器、WSS broker 或 TCP 拨号；这些由后续清单消费。本版只
支持 HTTP CONNECT 作为 edge 本地代理协议，不提供 SOCKS5。

## 基础原则

- [x] 仅允许配置的精确模型网关主机名和 `443` 端口；不新增其他目标、协议或命令执行能力。（验证：`validateDestination`、严格配置与负向测试覆盖）
- [x] `shared` 不依赖 `remote-client`，也不包含用户、服务或部署环境的真实凭据。（验证：依赖扫描无 `remote-client`，测试密钥均为运行时生成）
- [x] 协议和解析器对版本、帧长、字段大小、状态转换及错误码执行显式限制。（验证：协议、状态机、身份 capability 单元测试覆盖畸形与越权输入）
- [x] 每个阶段完成后运行对应验证，记录结果，并作为独立提交边界。（验证：阶段 4-7 分别提交为 `623e2b2`、`d8742ec`、`2494d99`、`98e2c47`）

## 阶段 1：工作区与质量基线

- 开始时间：未记录
- 结束时间：2026-07-16 12:12:05 +08:00
- 开发总结：已建立 Node.js 22、pnpm 10、TypeScript 严格 ESM 工作区，包含四个独立 package、ESLint、Vitest 覆盖率、锁定依赖和敏感文件忽略规则。
- 验证记录：`corepack pnpm lint`、`corepack pnpm typecheck`、`corepack pnpm test`、`corepack pnpm build` 均通过。

- [x] 创建 `server`、`egress-agent`、`edge-client`、`shared` 四个 package 与根 `pnpm` workspace 配置。
- [x] 固定 Node.js 22 运行时、TypeScript 严格模式、ESM 模块约定及锁定依赖版本。
- [x] 建立根级 `lint`、`typecheck`、`test`、`build` 脚本，使每个 package 可单独执行对应脚本。
- [x] 配置单元测试框架、覆盖率输出和不提交构建产物、私钥、环境文件的忽略规则。
- [x] 执行 `pnpm lint`、`pnpm typecheck`、`pnpm test`、`pnpm build`，确认空工作区可重复通过。

## 阶段 2：受限配置与运行时限额

- 开始时间：2026-07-16 12:13:29 +08:00
- 结束时间：2026-07-16 12:17:15 +08:00
- 开发总结：已在 `shared` 提供 server、egress-agent、edge-client 的严格配置 parser、统一协议版本和仅可收紧的资源限额；agent 本地配置持有最终允许目标，edge 监听地址仅可为 loopback。
- 验证记录：`corepack pnpm --filter @remote-codex/shared lint`、`typecheck`、`test` 通过；`corepack pnpm lint`、`typecheck`、`test`、`build` 全工作区通过。

- [x] 定义各组件的严格配置 schema，未知字段、空值、错误类型和越界数值均在启动前失败。
- [x] 将允许目标定义为 agent 本地部署配置的精确 hostname 与端口，不允许 edge 请求或服务端覆盖。
- [x] 定义并校验并发流数、单流和聚合缓冲、帧大小、连接超时、空闲超时、心跳、重连退避与打开流超时。
- [x] 让边、服务端与 agent 使用一致的协议版本和资源上限默认值，并允许更严格的部署侧覆盖。
- [x] 确保配置错误、路径和来源可诊断，但错误输出不回显密钥、token、授权头或完整环境变量。
- [x] 为合法配置、缺失配置、未知字段、非法限额和试图放宽目标限制分别添加测试。

## 阶段 3：目标规范化与最终验证器

- 开始时间：2026-07-16 12:17:15 +08:00
- 结束时间：2026-07-16 12:19:48 +08:00
- 开发总结：已实现纯同步目标验证器，使用 Node 的 `domainToASCII` 与 `isIP` 规范化 hostname 并阻止各种 IP literal 和 authority 变体；验证器只返回固定错误码且不执行 DNS。
- 验证记录：`corepack pnpm --filter @remote-codex/shared lint`、`typecheck`、`test` 通过（13 个测试）；`corepack pnpm build` 通过。

- [x] 实现 hostname 的 Unicode/ASCII 规范化、小写化和精确匹配，禁止通配符、后缀匹配、尾点与空白变体。
- [x] 用结构化网络 API 识别并拒绝 IPv4、IPv6、方括号 IPv6 和混淆型 IP literal。
- [x] 拒绝缺失端口、非数值端口、所有非 `443` 端口、userinfo、路径、查询和 fragment。
- [x] 让验证器在任何 DNS 查询和 TCP 拨号之前完成；返回固定的受限错误码而非内部网络细节。
- [x] 为大小写、IDN、尾点、IP literal、错误端口、近似域名和精确允许目标添加表驱动测试。

## 阶段 4：二进制协议与有界编解码

- 开始时间：2026-07-16 12:19:48 +08:00
- 结束时间：2026-07-16 12:41:44 +08:00
- 开发总结：已实现版本化 24 字节二进制 envelope、类型专用控制载荷、稳定错误码、严格 stream ID/flags/长度约束，以及先限长后复制的有界解码。
- 验证记录：主流程独立执行 `corepack pnpm --filter @remote-codex/shared lint`、`typecheck`、`test`（20/20）和 `build`，全部通过。

- [x] 定义单个 WebSocket message 对应一个二进制 envelope 的规范：协议版本、帧类型、flags、128 位 stream ID、载荷长度和载荷。（审核：`shared/src/protocol.ts` 的 `FRAME_HEADER_BYTES`、`encodeFrame`、`decodeFrame`；24 字节头测试通过）
- [x] 定义注册、挑战/响应、心跳、`stream.open`、`opened`、`rejected`、`error`、`data`、`credit`、`close` 的字段和稳定错误码。（审核：`shared/src/protocol.ts` 定义全部 payload schema、`TunnelErrorCode` 和 `StreamCloseCode`；round-trip 测试覆盖全部帧类型）
- [x] 为连接级帧规定零 stream ID，为数据和控制帧分别设置最大载荷；拒绝未知类型、截断帧、长度不符和非当前版本。（审核：`validateFrame`、`decodeFrame` 与畸形帧测试覆盖该约束）
- [x] 提供无副作用的编码器与解码器，保证任何外部输入在限制内解析且不会分配无界内存。（审核：`decodeFrame` 先检查 `MAX_FRAME_BYTES` 与载荷长度，再复制受限字节）
- [x] 添加协议 round-trip、畸形输入、版本不兼容、最大边界和随机 fuzz 样本测试。（验证：`shared/src/protocol.test.ts`，`corepack pnpm --filter @remote-codex/shared test` 20/20 通过）

## 阶段 5：流生命周期与流量控制

- 开始时间：2026-07-16 12:43:56 +08:00
- 结束时间：2026-07-16 13:01:10 +08:00
- 开发总结：已实现每 stream 的显式生命周期、会话绑定、幂等关闭、超时终止、双向 credit 账务与共享缓冲预算；WSS 断开直接关闭 stream，不提供 resume。
- 验证记录：主流程执行 `corepack pnpm --filter @remote-codex/shared lint`、`typecheck`、`test`（5 个文件、28 个测试）和 `build`，全部通过。

- [x] 以显式状态机实现 `requested -> authorized -> connecting -> open -> closing -> closed` 及 `rejected`、`failed` 终态。（审核：`shared/src/stream.ts` 的 `StreamState` 与 `StreamLifecycle`）
- [x] 限制每个状态允许的入站与出站帧，所有非法转换必须关闭相应流且不得影响其他流。（验证：`stream.test.ts` 覆盖乱序帧和单流隔离）
- [x] 定义初始 receive credit、credit 增量、未确认字节数和每流/全局缓冲上限；credit 耗尽时暂停生产端读取。（审核：`StreamBufferBudget`、credit 账务与 `canReadFromProducer`；credit 测试通过）
- [x] 定义幂等 `close`、打开超时、空闲超时和连接丢失时的终态原因，禁止在新 WSS 会话恢复旧 TCP stream。（验证：`onSessionDisconnected` 无 rebind，关闭和注入时钟超时测试通过）
- [x] 为合法转换、重复 close、乱序帧、credit 耗尽/恢复、超时和连接断开进行确定性时钟测试。（验证：`shared/src/stream.test.ts` 8 项测试纳入共享库 28/28 通过）

## 阶段 6：身份材料与短期流能力

- 开始时间：2026-07-16 13:04:02 +08:00
- 结束时间：2026-07-16 13:24:13 +08:00
- 开发总结：已实现 Ed25519 角色化身份与密钥加载接口、单次挑战认证、短期版本化 capability、agent 侧精确绑定验证和两类重放保护；伪造响应不会消耗合法 challenge。
- 验证记录：主流程执行 `corepack pnpm --filter @remote-codex/shared lint`、`typecheck`、`test`（6 个文件、35 个测试）和 `build`，全部通过。

- [x] 定义分离的 edge 用户/设备身份、egress agent 服务身份和 server 签名身份的数据模型与密钥加载接口。（审核：`shared/src/identity.ts` 的角色化 `KeyObject` 模型、身份构造器与安全加载接口）
- [x] 实现挑战随机数、时间窗、签名验证和重放防护；认证凭据仅出现在 WSS 握手或二进制认证帧中，不得写入 URL。（验证：Ed25519 challenge 测试覆盖过期、篡改、重放与伪造响应不消耗 nonce）
- [x] 定义 server 签发、agent 用公钥验证的短期 capability，绑定 edge 用户、edge 设备、agent ID、stream ID、目标、签发时间和过期时间。（审核：`CapabilityBinding`、`issueCapability`、`verifyCapability` 绑定全部字段）
- [x] 为 capability 设置紧凑、版本化、可验证的二进制表示，并在验证失败时返回不泄露密钥细节的错误。（审核：二进制 `CAPABILITY_VERSION` 格式与统一 `CAPABILITY_INVALID` 拒绝结果）
- [x] 为签名篡改、过期、未来签发、绑定字段不符、重放及密钥角色混用添加测试。（验证：`shared/src/identity.test.ts` 纳入共享库 35/35 通过）

## 阶段 7：共享库发布边界与契约文档

- 开始时间：2026-07-16 13:25:14 +08:00
- 结束时间：2026-07-16 13:42:48 +08:00
- 开发总结：已将 shared 限制为显式根入口，三个 runtime package 仅声明其正向 workspace 依赖，并补充中文共享契约和跨工作区覆盖率门禁。
- 验证记录：主流程执行 `corepack pnpm lint`、`typecheck`、`build`、`test`（38 个测试）和 `test:coverage`（86.62/72.31/95.67/86.62，阈值 85/70/90/85），全部通过。

- [x] 将 `shared` 的公共入口限制为配置、验证、协议、状态机、限额和身份验证 API，禁止导出组件私有实现。（审核：`shared/src/index.ts` 显式白名单，运行包不导入子路径）
- [x] 为错误码、帧类型、状态迁移、默认限额和配置字段生成可供三个运行组件引用的契约文档。（验证：`docs/shared-contract.md` 中文记录协议与安全契约）
- [x] 验证 `server`、`egress-agent`、`edge-client` 均能仅依赖 `shared` 进行编译，不产生反向依赖。（验证：三个 runtime 编译并动态加载 dist 成功；依赖扫描无反向引用）
- [x] 执行全工作区 lint、类型检查、测试、构建及覆盖率阈值检查。（验证：`corepack pnpm lint/typecheck/build/test/test:coverage` 通过，38 tests）

## 最终完成定义

以下项目作为本清单的完成标准，不要求每个开发阶段都执行，由所有相关阶段完成后统一验收。

- 开始时间：未记录
- 结束时间：2026-07-16 13:44:40 +08:00
- 验收总结：`shared` 基础协议、受限目标、流控与能力凭据已完成并提交；后续 `02` 至 `04` checklist 可在不改变该公共协议的前提下实现多用户共享 agent 的 broker、端侧和部署。

- [x] `shared` 在不依赖网络、真实密钥或 `remote-client` 的前提下通过全部契约与安全单元测试。（验证：`corepack pnpm test:coverage`，9 个文件、38 个测试通过）
- [x] 协议层不会接受未限制的帧、越权目标或无效状态转换。（验证：帧边界、目标验证、流状态和 capability 拒绝路径单元测试通过）
- [x] 后续组件可用此库实现多 edge 用户到同一 agent 的隔离 capability，而无须改变公共协议。（验证：capability 绑定用户、设备、agent、stream 与精确目标；契约文档已固定根入口）
