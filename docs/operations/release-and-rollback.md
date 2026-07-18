# 发布、升级与回滚

## 产物边界

一个 release 使用根 `package.json` 的版本号，协议版本固定来自
`@remote-codex/shared.PROTOCOL_VERSION`。`deployment/release-policy.json` 是受审查的机器可读
allowlist，声明四个生产 workspace：`ops`、`server-host`、`egress-agent-host`、
`edge-client-host`，以及它们所需的 `shared`、`server`、`egress-agent`、`edge-client` 运行库。

候选产物只含策略明确列出的运行时 `.js`、package metadata、锁文件、部署脚本和必要中文文档。
不得原样复制整个 `dist/`；`*.test.*`、测试 helper、source map、类型声明、`.tsbuildinfo`、coverage、
源码、`.env`、证书和私钥均不属于 production release。配置根、身份材料、TLS 材料、授权文件、
状态日志和 release 必须分开保存，升级不能覆盖或复制这些材料。`deployment/examples/` 只供源码仓库
评审配置形状，不进入 production candidate，不能当作部署配置分发。

## 离线准备与清单

在 Node.js 22、pnpm 10 的受控构建机上，从已审查 commit 开始：

```powershell
corepack pnpm install --frozen-lockfile
corepack pnpm verify:repository-without-e2e
```

`verify:repository-without-e2e` 执行 lint、typecheck、所有非 E2E 自动测试和 build；它明确排除
`server/src/end-to-end.test.ts`，不是完整发布验收。未获准真实联调时，记录 E2E 为 `deferred`，
不能把本命令改名或归档为“完整通过”。正式发布前仍须在隔离预生产执行完整 `corepack pnpm test`
及真实网络验收。

使用构建后的 `ops` CLI 将生产文件暂存到一个全新的目录。工具不会复制私钥、配置根、测试产物
或未知文件，输出目录已存在时会失败：

```powershell
node ops/dist/cli-main.js release stage `
  --source C:\src\remote-codex `
  --policy C:\src\remote-codex\deployment\release-policy.json `
  --output C:\artifacts\remote-codex-0.1.0

node ops/dist/cli-main.js release inventory `
  --root C:\artifacts\remote-codex-0.1.0 `
  --policy C:\src\remote-codex\deployment\release-policy.json `
  --output C:\artifacts\remote-codex-0.1.0.inventory.json

node ops/dist/cli-main.js release validate `
  --root C:\artifacts\remote-codex-0.1.0 `
  --policy C:\src\remote-codex\deployment\release-policy.json `
  --inventory C:\artifacts\remote-codex-0.1.0.inventory.json
```

策略和 inventory 必须随发布记录归档，但 inventory 放在候选目录之外。验证器扫描整个候选目录，
拒绝缺失或未知文件、符号链接、秘密文件名/PEM/凭据正文、范围外结构化 listener/server URL、
`remote-client` 依赖、workspace 依赖漂移、协议/schema 不一致以及文件 hash 变化。CLI 只输出版本、
协议版本、文件/字节计数和聚合 SHA-256；inventory 内只含相对路径、大小和逐文件 SHA-256。

构建机将候选目录、inventory 和受信 policy 分别传到目标主机；受信 policy 及审批记录中的预期
aggregate SHA-256 必须通过独立可信渠道提供，不能只信候选目录内的副本。目标主机在任何组件安装或
激活前，使用已单独供应并审批的 verifier toolchain 再次验证不可变候选：

```powershell
node C:\RemoteCodex\verifier\ops\dist\cli-main.js release validate `
  --root C:\RemoteCodex\archive\remote-codex-0.1.0 `
  --policy C:\RemoteCodex\trust\release-policy.json `
  --inventory C:\RemoteCodex\trust\remote-codex-0.1.0.inventory.json
```

逐字比较该命令输出的 `releaseVersion`、`protocolVersion`、`fileCount` 和 `aggregateSha256` 与审批记录；
任一不一致都停止发布。verifier toolchain 必须来自同一已审查工具版本且已预装依赖，它不从待验证
候选加载代码。候选目录保持只读且不生成 `node_modules`；inventory 始终在候选外保存。

验证通过后，从不可变候选复制一个新的 activation 目录，再从已审批且隔离的 pnpm store 执行：

```powershell
corepack pnpm install --prod --offline --frozen-lockfile --ignore-scripts
node --input-type=module -e "await Promise.all(['./ops/dist/index.js','./server-host/dist/index.js','./egress-agent-host/dist/index.js','./edge-client-host/dist/index.js'].map((path) => import(path))); console.log(JSON.stringify({ok:true,productionWorkspaceImports:4,listenersStarted:0}))"
```

pnpm 依据已归档 lockfile 校验依赖完整性；`--ignore-scripts` 禁止依赖安装脚本。import smoke 只加载四个
production workspace，不调用 host CLI/runtime，也不启动 listener。生成的 `node_modules` 只属于
activation，不能回写候选或 inventory。安装需要联网、lockfile 漂移、import 失败或出现 listener
时立即删除该 activation 并停止发布。随后用 activation 的 `ops deployment validate` 分别校验三个
独立配置根，再按 Server、Agent、Edge runbook 执行组件状态和 listener 检查。

## 兼容规则与升级顺序

当前二进制帧 `protocolVersion` 为 `2`。每帧首字节不等于 `2` 时解码器以
`PROTOCOL_VERSION_UNSUPPORTED` 拒绝；没有协议降级协商。生产 manifest schema 为 `2`，Server
host config schema 为 `1`，解析器都拒绝未知版本和未知字段。release 版本与这些 schema 分离：
release 可以升级而配置仍沿用兼容 schema，但启用前必须用新 release 的 `deployment validate`
复核原配置根。

同一协议和 schema 的兼容升级顺序为：

1. 部署并验证新 Server，确认 `/health`、TLS、唯一 listener 和脱敏日志；旧连接会在进程切换时
   关闭，不能恢复旧 stream。
2. 逐台停止并升级 Egress Agent；每台重新完成 Ed25519 challenge，旧 WSS、capability、TCP 和
   stream ID 均作废。
3. 逐台停止并升级 Edge Client；它重新认证，loopback CONNECT 在离线期间只返回固定失败，
   不排队、不直连、不选择其他 Agent。

若 `protocolVersion`、帧语义、签名输入、capability 或 schema 变化，则禁止旧新 peer 混跑。进入维护
窗口，先停止 Edge，再停止 Agent，确认 stream/TCP 清零后停止 Server；部署新 Server，再启动
新 Agent，最后启动新 Edge。不得通过接受旧帧、降低 TLS、关闭认证、放宽目标或复制旧流实现兼容。

## 配置、授权与密钥变更

- release 切换不自动变更配置根。每个组件先以新 release 离线校验旧 manifest；不兼容时先生成经
  审批的新版本配置并保留旧快照，不能在运行中猜测转换。
- Agent 授权、用户/设备撤销和配额收紧使用[身份与授权 runbook](identity-and-authorization.md)的
  原子命令。授权注册表变更按 Server 受控重启生效；撤销后关闭相关 peer/stream，不把流改路由到
  其他 Agent。
- Agent/Edge 认证 key 常规轮换采用新 key ID、新目录、新公钥注册、组件切换、确认上线、移除旧
  公钥的顺序。Server signing key 灾难替换必须停服，并向全部 Agent/Edge 分发新验签公钥后恢复。
  旧 capability 最长只有短期有效期，但泄露时仍不能等待自然过期代替停服和换 key。

## 回滚

回滚前必须对只读归档中的旧 candidate 使用受信 policy、旧 inventory 和独立审批 hash 重新验证；
不能验证已经写入 `node_modules` 的旧 activation 目录。旧 release 还必须支持当前协议和配置 schema；
TLS/身份 key 未撤销；旧授权快照不会恢复已撤销用户或放宽配额。任一条件不满足时保持相关组件停止，
按事件响应处理，不能强行回退。

同一协议内的单组件失败可停止该组件、切换到已验证旧 release、重新运行离线 bundle 校验后启动。
涉及 Server、协议或 schema 时采用完整安全回滚：停止 Edge、停止 Agent、确认旧流和目标 TCP 归零、
停止 Server，切回旧 Server，再启动旧 Agent，最后启动旧 Edge。配置回滚只能使用与旧 schema 匹配且
不恢复撤销/旧密钥的受审快照。

回滚后重复 Server 外部检查、Agent/Edge 状态脚本、唯一 listener 和脱敏日志检查。任何 WSS 或进程
重启都必须创建新 session 和 stream；“恢复旧流”不是成功条件。发布/回滚演练必须在隔离预生产由
负责人手工记录时间、release/inventory hash、组件顺序、监听器/stream/TCP 清零证据和回滚结论。
仓库自动测试不声称完成过真实演练。
