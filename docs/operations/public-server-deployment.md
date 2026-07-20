# Public Server 部署与加固

## 固定拓扑

Public Server 不使用 Nginx 或其他反向代理。`server-host` 直接在公网
`0.0.0.0:8443` 终止 TLS/WSS，唯一公开 WSS URL 是
`wss://<publicHostname>:8443/tunnel`。同一 listener 只提供以下路径：

- `GET /health`：无凭据固定健康状态。
- `WSS /tunnel`：唯一隧道入口，要求允许的 HTTPS `Origin`、受限 header、握手并发、连接频率和消息大小。

`server-host` 不提供 `80`、静态文件、重写、重定向、通用 proxy、`/metrics`、`/debug`、`/admin`、SOCKS、
CONNECT 或管理 API。其他路径固定返回 `404`。直连模式不接收或信任 `X-Forwarded-For`；连接频率限制
使用 TCP socket 的对端地址。

云安全组和主机防火墙只放行公网 TCP `8443`。不要为此服务开放 TCP `80` 或 `443`；若主机运行无关
服务，其 listener 和防火墙规则必须独立审查。

## 文件、账号与 host 配置

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

不要将配置根、私钥、证书或授权文件放入 Git 工作树、release 目录或 Web 根目录。production
`manifest.json` 与 `host.json` 均使用 `schemaVersion: 2`；所有路径严格相对配置根，不能使用符号链接。
当前直连部署的关键字段如下：

```json
{
  "schemaVersion": 2,
  "listenHost": "0.0.0.0",
  "listenPort": 8443,
  "publicHostname": "remote-codex.zergzerg.cn",
  "publicPort": 8443,
  "allowedOrigins": ["https://remote-codex.zergzerg.cn:8443"],
  "tlsCertificatePath": "tls/fullchain.pem",
  "tlsPrivateKeyPath": "tls/private-key.pem",
  "tlsMinimumVersion": "TLSv1.3",
  "clientAddressSource": "socket"
}
```

`listenHost: "0.0.0.0"` 时，`publicPort` 必须等于 `listenPort`，且
`clientAddressSource` 必须为 `socket`。`tlsMinimumVersion` 仅接受 `TLSv1.2` 或 `TLSv1.3`，当前
配置及推荐值为 `TLSv1.3`。Agent 与 Edge 的 `serverUrl` 必须精确写为
`wss://remote-codex.zergzerg.cn:8443/tunnel`，它们发送的 Origin 必须与 `allowedOrigins` 一致。

安装 `deployment/linux/server/remote-codex-server.service` 后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now remote-codex-server.service
sudo systemctl status remote-codex-server.service
```

该单元以非 root 身份运行，启动前离线校验配置、权限、身份与 TLS 文件。端口被占用时启动原子失败，
不会改用随机端口。

## 证书续期与 reload

`server-host` 使用 `tls/fullchain.pem` 与 `tls/private-key.pem` 直接提供 TLS。续期程序应先在同目录
生成新文件、校验证书链与私钥匹配，再以原子 rename 替换文件。然后执行：

```bash
sudo systemctl reload remote-codex-server.service
```

可安装并启用随仓库提供的证书 `.path` 与 reload `.service`。`SIGHUP` 只接受 TLS 文件变化；目标、
Origin、端口、代理地址来源、资源限制、peer、授权或签名身份变化必须走受控重启。

## 手工检查

部署后从外部网络运行：

```bash
bash deployment/linux/server/verify-public-server.sh \
  remote-codex.zergzerg.cn 8443 https://remote-codex.zergzerg.cn:8443
```

脚本验证 `/health`、错误 method、隐藏 endpoint、纯 HTTP、TLS 1.1、超大握手 header 和允许 Origin 的
WSS `101`。随后必须启动真实 agent 与 edge，确认两类 peer 完成认证并能建立业务 stream。

主机上确认 `server-host` 是唯一的预期公网 listener：

```bash
sudo ss -ltnp | grep -E '(^|\s)(0\.0\.0\.0|\[::\]):8443\b'
sudo ss -ltnp | grep -E '(:80|:443)' && exit 1 || true
```

还必须从另一台机器确认 TCP `8443` 可访问，并从非预期端口确认连接失败。防火墙和云安全组的实际状态
不能由进程内测试替代。

## 日志、升级与回滚

Node 只向 stdout 输出白名单 JSON，由 journald 持久化。日志不得记录 request payload、原始 frame、
header、cookie、token、capability、私钥或证书正文。升级以新的只读
`/opt/remote-codex/releases/<version>` 进行，先运行完整构建与离线 `deployment validate`，再原子更新
`current` 并重启 Node。回滚不得放宽 Origin、目标、TLS、身份、授权或端口边界。
