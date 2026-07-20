# Public Server 部署与加固

## 固定拓扑

Public Server 使用 Nginx 作为唯一公网 TLS/WSS 入口，唯一公开 URL 是
`wss://<publicHostname>/tunnel`。Nginx 只监听 `443`，只反代以下路径：

- `GET /health`：无凭据固定健康状态。
- `WSS /tunnel`：唯一隧道入口，要求允许的 HTTPS `Origin`、受限 header、握手并发、连接频率和消息大小。

Node.js `server-host` 继续终止其到 Nginx 的 loopback TLS，但必须只监听
`127.0.0.1:<listenPort>`。`listenPort` 可使用任意未占用的 `1-65535` 端口；标准样例为 `8443`。
Nginx 不提供静态文件、重写、重定向、通用 proxy、`/metrics`、`/debug`、`/admin`、SOCKS、CONNECT
或管理 API。不要为此 server 开放 `80`，证书续期使用 DNS-01 或预置证书。

Nginx 必须覆盖而非追加 `X-Forwarded-For`：`proxy_set_header X-Forwarded-For $remote_addr`。当
`host.json` 的 `clientAddressSource` 为 `loopback-x-forwarded-for` 时，Node 只信任来源 socket 为
`127.0.0.1`、且恰好包含一个合法 IP 的该 header；缺失、重复、链式或非法值会在 WSS 握手时以
`400` 拒绝。反代主机不得提供给不受信任的本地用户。

## Nginx

将 [Nginx 配置模板](../../deployment/linux/nginx/remote-codex.conf) 作为该域名的唯一 vhost，替换
`server_name`、证书路径、日志路径和后端端口。模板针对
`remote-codex.zergzerg.cn:443 -> 127.0.0.1:8443`，并具有以下关键限制：

- 公网 TLS 仅允许 `TLSv1.2` 与 `TLSv1.3`；不得启用 TLS 1.1。
- 上游使用 `https://127.0.0.1:8443`，开启 SNI 与证书校验；根据发行版调整系统 CA bundle 路径。
- `/tunnel` 使用 HTTP/1.1 Upgrade、关闭 request/response buffering，并把读写超时设置为高于心跳周期。
- 所有未明确允许的路径返回 `404`，Nginx access/error log 不得使用 debug 或记录 header/payload 的自定义格式。

应用配置前执行：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

云安全组和主机防火墙只放行公网 TCP `443`。必须确认 `8443` 或其他 Node 后端端口不能从非 loopback
接口访问。

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

production `manifest.json` 使用 `schemaVersion: 2`；`host.json` 使用
`schemaVersion: 2`。所有路径严格相对配置根，不能使用符号链接。反代部署的关键字段如下：

```json
{
  "schemaVersion": 2,
  "listenHost": "127.0.0.1",
  "listenPort": 8443,
  "publicHostname": "remote-codex.zergzerg.cn",
  "publicPort": 443,
  "allowedOrigins": ["https://remote-codex.zergzerg.cn"],
  "tlsCertificatePath": "tls/fullchain.pem",
  "tlsPrivateKeyPath": "tls/private-key.pem",
  "tlsMinimumVersion": "TLSv1.3",
  "clientAddressSource": "loopback-x-forwarded-for"
}
```

`tlsMinimumVersion` 仅接受 `TLSv1.2` 或 `TLSv1.3`，默认和推荐值为 `TLSv1.3`。它控制 Nginx 到
Node 的 loopback TLS 下限；公网下限由 Nginx 控制。若使用 `listenHost: "0.0.0.0"` 的直连模式，
`clientAddressSource` 必须是 `socket`，且 `publicPort` 必须与 `listenPort` 相同。

安装 `deployment/linux/server/remote-codex-server.service` 后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now remote-codex-server.service
sudo systemctl status remote-codex-server.service
```

该单元以非 root 身份运行，启动前离线校验配置、权限、身份与 TLS 文件。端口被占用时启动原子失败，
不会改用随机端口。

## 证书续期与 reload

Nginx 与 Node 使用同一域名的有效证书材料，但各自持有独立、非符号链接的 PEM 副本。续期程序应先
在同目录生成新文件、校验证书链与私钥匹配，再以原子 rename 替换文件。之后依次执行：

```bash
sudo systemctl reload nginx
sudo systemctl reload remote-codex-server.service
```

可安装并启用随仓库提供的 Node 证书 `.path` 与 reload `.service`；Nginx 的证书 reload 仍由部署
系统或证书续期 hook 负责。`SIGHUP` 只接受 TLS 文件变化；目标、Origin、端口、代理地址来源、
资源限制、peer、授权或签名身份变化必须走受控重启。

## 手工检查

部署后从外部网络运行：

```bash
bash deployment/linux/server/verify-public-server.sh \
  remote-codex.zergzerg.cn 443 https://remote-codex.zergzerg.cn
```

脚本验证 `/health`、错误 method、隐藏 endpoint、纯 HTTP、TLS 1.1、超大握手 header 和允许
Origin 的 WSS `101`。随后必须启动真实 agent 与 edge，确认两类 peer 完成认证并能建立业务 stream。

主机上确认只有两个预期 listener，且 Node 后端没有公网绑定：

```bash
sudo ss -ltnp | grep ':443'
sudo ss -ltnp | grep '127.0.0.1:8443'
sudo ss -ltnp | grep -E '(^|\s)(0\.0\.0\.0|\[::\]):8443\b' && exit 1 || true
```

## 日志、升级与回滚

Node 只向 stdout 输出白名单 JSON，由 journald 持久化。Nginx 日志只保留连接元数据，不能写入 request
payload、原始 frame、header、cookie、token、capability、私钥或证书正文。升级以新的只读
`/opt/remote-codex/releases/<version>` 进行，先运行完整构建与离线 `deployment validate`，再原子更新
`current` 并重启 Node；配置变更后同时复核 Nginx。回滚不得放宽 Origin、目标、TLS、反代 header、
身份、授权或端口边界。
