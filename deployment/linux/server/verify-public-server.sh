#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "用法: $0 <hostname> <8000-9000 端口> <允许的 HTTPS Origin>" >&2
  exit 2
fi

host="$1"
port="$2"
origin="$3"

if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 8000 || port > 9000 )); then
  echo "端口必须在 8000-9000 范围内" >&2
  exit 2
fi
if ! REMOTE_CODEX_VERIFY_HOST="$host" REMOTE_CODEX_VERIFY_ORIGIN="$origin" \
  node "$(dirname "$0")/validate-public-input.mjs"
then
  echo "hostname 或 Origin 无效；禁止 userinfo、IP、通配符、路径、query 和 fragment" >&2
  exit 2
fi

base="https://${host}:${port}"

expect_code() {
  local expected="$1"
  local url="$2"
  shift 2
  local actual
  actual="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$@" "$url")"
  if [[ "$actual" != "$expected" ]]; then
    echo "${url}: 期望 ${expected}，实际 ${actual}" >&2
    exit 1
  fi
}

expect_code 200 "${base}/health"
expect_code 405 "${base}/health" --request POST
expect_code 426 "${base}/tunnel"
expect_code 404 "${base}/metrics"
expect_code 404 "${base}/debug"
expect_code 404 "${base}/admin"

if curl --silent --show-error --output /dev/null --max-time 5 "http://${host}:${port}/health"; then
  echo "非 TLS 请求不应成功" >&2
  exit 1
fi

if curl --silent --show-error --output /dev/null --max-time 5 --tls-max 1.2 "${base}/health"; then
  echo "TLS 1.2 请求不应成功" >&2
  exit 1
fi

padding="$(head -c 17000 /dev/zero | tr '\0' x)"
expect_code 431 "${base}/tunnel" \
  --http1.1 \
  --header "Connection: Upgrade" \
  --header "Upgrade: websocket" \
  --header "Sec-WebSocket-Version: 13" \
  --header "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  --header "Origin: ${origin}" \
  --header "X-Padding: ${padding}"

set +e
wss_code="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --max-time 3 \
  --http1.1 \
  --header "Connection: Upgrade" \
  --header "Upgrade: websocket" \
  --header "Sec-WebSocket-Version: 13" \
  --header "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  --header "Origin: ${origin}" \
  "${base}/tunnel")"
set -e
if [[ "$wss_code" != "101" ]]; then
  echo "WSS 握手期望 101，实际 ${wss_code}" >&2
  exit 1
fi

echo "public server 匿名入口与 TLS/WSS 边界检查通过；仍需使用真实 agent/edge 身份完成认证联调。"
