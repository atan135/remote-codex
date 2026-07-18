# Public Server 部署与加固

## 固定入口与前置条件

Public Server 采用 Node.js 22 进程直接终止 TLS，不部署反向代理，也不启动 ACME HTTP
listener。唯一公网端口必须在 `8000-9000`；标准样例使用 `8443`。同一个 listener 只提供：

- `GET /health`：无凭据固定健康状态，不读取 query、header 或 body。
- `WSS /tunnel`：唯一隧道入口，要求 TLS 1.3、允许的 HTTPS `Origin`、受限 header、握手并发、
  连接频率和消息大小。

样例的唯一公开 URL 是 `wss://tunnel.example.invalid:8443/tunnel`。`/metrics`、`/debug`、
`/admin`、管理 API、普通 HTTP、SOCKS、CONNECT 和其他 TCP listener 均不存在。云安全组和主机
防火墙只放行所选 `8000-9000` 端口中的一个 TCP 端口；不要额外开放 `80`、`443` 或调试端口。

主机必须启用可信时间同步服务。安装前确认 `timedatectl show -p NTPSynchronized --value`
返回 `yes`，并确认 Node.js `>=22 <23`、systemd 和 journald 可用。域名、证书、主机账号和
部署目录必须只属于 Remote Codex，不能复用 `remote-client` 资源。

## 文件与账号

创建无登录 shell 的专用 `remote-codex` 用户和组。推荐布局：

```text
/opt/remote-codex/releases/<version>/    root:root，发布内容只读
/opt/remote-codex/current -> releases/<version>
/etc/remote-codex/server/                remote-codex:remote-codex，0700
  manifest.json                          0600
  config.json                            0600
  host.json                              0600
  peer-identities.json                   0600
  authorizations.json                    0600
  keys/...                               私钥 0600，公钥只读
  tls/fullchain.pem                      不可写
  tls/private-key.pem                    0600
```

production `manifest.json` 必须使用 `schemaVersion: 2` 并显式引用 `hostConfigPath`；
`host.json` 自身使用独立的 `schemaVersion: 1`。`host.json` 必须引用严格相对路径，
`listenHost` 固定为 `0.0.0.0`，监听端口只能在 `8000-9000`，`publicHostname` 不能是 IP
literal 或通配符，`allowedOrigins` 只能包含完整、
非 IP 的 HTTPS origin。参考
`deployment/examples/server/host.json`，其中不含证书或密钥正文。

将 `deployment/linux/server/remote-codex-server.service` 安装到 `/etc/systemd/system/` 后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now remote-codex-server.service
sudo systemctl status remote-codex-server.service
```

单元以非 root 身份运行，设置文件描述符、任务、内存、CPU、重启和停止期限，并只允许常规
IP/Unix socket address family。`ExecStartPre` 会离线校验配置、权限、身份和 TLS 文件；端口被占用
时启动原子失败，不会改用随机端口或范围外端口。

## 证书续期与 reload

证书由外部受控 PKI 或 ACME DNS-01 challenge 续期。禁止为 HTTP-01 临时开放 `80`、`443` 或
其他 listener。续期程序应先在同目录生成新文件、校验证书链与私钥匹配，再用原子 rename
替换 `fullchain.pem` 和 `private-key.pem`。

可安装并启用随仓库提供的 `.path` 与 reload `.service`：

```bash
sudo systemctl enable --now remote-codex-server-cert-reload.path
sudo systemctl reload remote-codex-server.service
```

`SIGHUP` 会重新执行受限文件权限和完整 bundle 校验，再验证证书/私钥。进程对 runtime config、
host config、peer ID/key ID/公钥、授权文档、server 签名 key metadata 和经 loader 验证配对的
SPKI 公钥实际材料建立不写入日志的 SHA-256 fingerprint。fingerprint 不导出或复制 PKCS#8 私钥
字节。只有该 non-TLS fingerprint 完全不变、TLS 文件内容变化且新密钥对有效时才更新当前
TLS context；目标、host、端口、Origin、资源限制、peer、授权或签名身份变化会记录
`SERVER_HOST_RELOAD_REQUIRES_RESTART` 并保留现有 context，必须走受控重启。无效新证书也不会
替换已生效证书。

## 外网手工验收

本仓库开发测试不访问公网。部署后从独立外部网络运行：

```bash
bash deployment/linux/server/verify-public-server.sh \
  tunnel.example.invalid 8443 https://tunnel.example.invalid:8443
```

脚本验证可信 HTTPS health、错误 method、隐藏 endpoint、普通 HTTP、TLS 1.2、超大握手 header
和允许 Origin 的 WSS `101` 握手，不读取或输出任何身份凭据。之后还必须启动真实 agent 与 edge，
确认两类 peer 完成认证并能建立业务 stream；这项真实联调由部署负责人手工记录，不能用匿名
`101` 代替。

主机同时检查只存在一个预期 listener：

```bash
sudo ss -ltnp | grep 8443
sudo ss -ltnp | grep -E ':(80|443|3000|9229)\b' && exit 1 || true
```

## 日志、指标和敏感信息复核

进程只向 stdout 输出一行 JSON，journald 负责持久化、限额和轮转。生命周期日志只含事件、错误
码、监听元数据和唯一公开 URL；stream 审计由字段白名单重建；周期指标只含 peer/stream 计数和
缓冲水位。没有 HTTP metrics endpoint。查看方式：

仓库提供 `deployment/linux/server/journald-remote-codex.conf` 作为主机级 journald 限额、保留期、
压缩和速率限制基线。journald 配置作用于整台主机，安装到 `/etc/systemd/journald.conf.d/` 前必须
由主机运维负责人按共享服务容量复核；安装后执行 `sudo systemctl restart systemd-journald`，并
验证既有服务日志没有受到不可接受的截断。

```bash
sudo journalctl -u remote-codex-server.service --since today --output=cat
sudo journalctl -u remote-codex-server.service --since today --output=cat \
  | grep -E -i '("authorization"|"proxy-authorization"|"cookie"|"token"|"capability"|"privateKey"|Bearer[[:space:]]|BEGIN[[:space:]]+(PRIVATE[[:space:]]+KEY|CERTIFICATE))' \
  && exit 1 || true
```

不能把请求 payload、原始 frame、header、cookie、token、capability、私钥、证书正文、完整配置
或异常对象加入日志。生产日志审查必须由部署负责人基于真实运行日志完成。

## 升级与回滚

每次发布写入新的只读 `/opt/remote-codex/releases/<version>`，先运行完整构建和离线
`deployment validate`，再原子更新 `current` symlink 并重启。停止会先关闭 peer 与 stream；旧
stream 不跨进程恢复。验证 `/health`、真实 agent 在线和外部脚本后才能删除旧版本。

回滚时停止服务，将 `current` 原子切回已知安全版本，恢复与该版本 schema 匹配且仍有效的配置，
再启动并重复同一组检查。不得通过放宽 Origin、目标、身份、授权、TLS 或端口范围来救火；回滚
失败时保持服务停止并按事件响应流程处理。
