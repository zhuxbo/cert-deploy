#!/usr/bin/env bash
# Bats 公共辅助函数
# 所有 .bats 测试文件通过 load 'helpers/common' 加载

# ==============================================================================
# 环境变量
# ==============================================================================

# sslctl 的 SSRF 防护仅允许 localhost 使用 HTTP，通过 socat 代理 mock-api 到本地
export MOCK_REMOTE_URL="${MOCK_API_URL:-http://mock-api:8080}"
export MOCK_URL="http://localhost:8080"
export TOKEN="${TEST_TOKEN:-test-token}"
export SSLCTL_CONFIG_DIR="/opt/sslctl"

# ==============================================================================
# Mock API 操作
# ==============================================================================

# 切换 Mock API 场景
# $1 = scenario name（权威列表见 mock-api 的 scenarios 表，启动日志也会打印）
#      业务失败场景：unauthorized(token_invalid) / not_found(order_not_found) / rate_limited
#      协议外故障：error(HTTP 500)
#      正常场景：active / processing / expired / batch / renew-flow / releases
mock_set_scenario() {
  curl -sf --max-time 5 -X POST "$MOCK_REMOTE_URL/admin/scenario/$1" >/dev/null 2>&1
}

# 重置 Mock API 状态（清除请求日志、回调记录，恢复默认场景）
mock_reset() {
  curl -sf --max-time 5 -X POST "$MOCK_REMOTE_URL/admin/reset" >/dev/null 2>&1
}

# 获取 Mock API 收到的回调记录（JSON）
mock_get_callbacks() {
  curl -sf --max-time 5 "$MOCK_REMOTE_URL/admin/callbacks"
}

# 生成若干天后的 RFC3339 时间。使用 epoch 算术，兼容 GNU date 与 BusyBox date。
future_rfc3339() {
  local days="$1"
  local target_epoch
  target_epoch=$(( $(date +%s) + days * 86400 ))
  date -u -d "@$target_epoch" "+%Y-%m-%dT%H:%M:%SZ"
}

# 获取 Mock API 的请求日志（JSON）
mock_get_requests() {
  curl -sf --max-time 5 "$MOCK_REMOTE_URL/admin/logs"
}

# ==============================================================================
# Web 服务器操作
# ==============================================================================

# 自动检测当前容器中的 Web 服务器类型
# 返回: nginx / apache2ctl / httpd / apachectl
detect_webserver() {
  if command -v nginx &>/dev/null; then
    echo "nginx"
  elif command -v apache2ctl &>/dev/null; then
    echo "apache2ctl"
  elif command -v httpd &>/dev/null; then
    echo "httpd"
  elif command -v apachectl &>/dev/null; then
    echo "apachectl"
  fi
}

# 启动 Web 服务器
start_webserver() {
  local ws
  ws=$(detect_webserver)
  case "$ws" in
    nginx)      nginx ;;
    apache2ctl) apache2ctl start ;;
    httpd)      httpd ;;
    apachectl)  apachectl start ;;
  esac
}

# 停止 Web 服务器
stop_webserver() {
  local ws
  ws=$(detect_webserver)
  case "$ws" in
    nginx)      nginx -s stop ;;
    apache2ctl) apache2ctl stop ;;
    httpd)      httpd -k stop ;;
    apachectl)  apachectl stop ;;
  esac
}

# 重载 Web 服务器配置
reload_webserver() {
  local ws
  ws=$(detect_webserver)
  case "$ws" in
    nginx)      nginx -s reload ;;
    apache2ctl) apache2ctl graceful ;;
    httpd)      httpd -k graceful ;;
    apachectl)  apachectl graceful ;;
  esac
}

# 测试 Web 服务器配置语法
test_webserver_config() {
  local ws
  ws=$(detect_webserver)
  case "$ws" in
    nginx)      nginx -t ;;
    apache2ctl) apache2ctl configtest ;;
    httpd)      httpd -t ;;
    apachectl)  apachectl configtest ;;
  esac
}

# ==============================================================================
# 断言辅助
# ==============================================================================

# 断言上一个 run 命令成功（exit 0）
assert_success() {
  if [ "$status" -ne 0 ]; then
    echo "Expected success (exit 0), got exit $status"
    echo "Output: $output"
    return 1
  fi
}

# 断言上一个 run 命令失败（exit non-0）
assert_failure() {
  if [ "$status" -eq 0 ]; then
    echo "Expected failure (exit non-0), got exit 0"
    echo "Output: $output"
    return 1
  fi
}

# 断言输出包含指定子串
# $1 = expected substring
assert_output_contains() {
  if [[ "$output" != *"$1"* ]]; then
    echo "Expected output to contain: $1"
    echo "Actual output: $output"
    return 1
  fi
}

# 断言输出不包含指定子串
# $1 = unexpected substring
assert_output_not_contains() {
  if [[ "$output" == *"$1"* ]]; then
    echo "Expected output NOT to contain: $1"
    echo "Actual output: $output"
    return 1
  fi
}

# 断言文件存在
# $1 = file path
assert_file_exists() {
  if [ ! -f "$1" ]; then
    echo "Expected file to exist: $1"
    return 1
  fi
}

# 断言文件不存在
# $1 = file path
assert_file_not_exists() {
  if [ -f "$1" ]; then
    echo "Expected file not to exist: $1"
    return 1
  fi
}

# 断言文件包含指定内容
# $1 = file path, $2 = expected content (grep pattern)
assert_file_contains() {
  if ! grep -q "$2" "$1" 2>/dev/null; then
    echo "Expected file $1 to contain: $2"
    return 1
  fi
}

# 断言目录存在
# $1 = directory path
assert_dir_exists() {
  if [ ! -d "$1" ]; then
    echo "Expected directory to exist: $1"
    return 1
  fi
}

# 返回配置中第一个启用绑定的字段值。
# $1 = jq 字段表达式（相对于 binding，例如 .paths.certificate）
binding_value() {
  local expr="$1"
  jq -r --argjson enabled true \
    ".certificates[].bindings[] | select(.enabled == \$enabled) | $expr" \
    "$SSLCTL_CONFIG_DIR/config.json" | head -1
}

# 验证证书和私钥公钥一致。
assert_cert_key_match() {
  local cert_path="$1"
  local key_path="$2"
  local cert_pub key_pub
  cert_pub=$(openssl x509 -in "$cert_path" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_pub=$(openssl pkey -in "$key_path" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  if [ -z "$cert_pub" ] || [ "$cert_pub" != "$key_pub" ]; then
    echo "Certificate and private key do not match: $cert_path / $key_path"
    return 1
  fi
}

# 返回 PEM 文件中首张证书的 SHA256 指纹（去除分隔符）。
cert_fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':'
}

# 返回 TLS 端点当前呈现的叶子证书 SHA256 指纹。
tls_fingerprint() {
  local address="$1"
  local server_name="$2"
  echo | openssl s_client -connect "$address" -servername "$server_name" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':'
}

# 等待 Web 服务器异步 reload 后呈现目标证书，超时仍保持强断言失败。
wait_for_tls_fingerprint() {
  local address="$1"
  local server_name="$2"
  local expected="$3"
  local attempts="${4:-40}"
  local delay="${5:-0.25}"
  local live=""

  for _ in $(seq 1 "$attempts"); do
    live=$(tls_fingerprint "$address" "$server_name")
    if [ -n "$live" ] && [ "$live" = "$expected" ]; then
      return 0
    fi
    sleep "$delay"
  done

  echo "TLS certificate fingerprint mismatch after reload: expected=$expected live=$live"
  return 1
}

# ==============================================================================
# 测试生命周期辅助
# ==============================================================================

# 确保 socat 代理正在运行（将 mock-api 转发到 localhost:8080）
# sslctl 的 SSRF 防护仅允许 localhost 使用 HTTP
ensure_mock_proxy() {
  # 已经在监听则跳过
  if curl -sf --max-time 3 http://localhost:8080/health >/dev/null 2>&1; then
    return
  fi
  # 从 MOCK_REMOTE_URL 提取 host:port
  local remote_host remote_port
  remote_host=$(echo "$MOCK_REMOTE_URL" | sed -E 's|https?://||; s|/.*||; s|:.*||')
  remote_port=$(echo "$MOCK_REMOTE_URL" | sed -E 's|https?://||; s|/.*||; s|.*:||')
  remote_port="${remote_port:-8080}"
  # 除 stdin/stdout/stderr 外，还要关闭 Bats 用于 TAP 协调的 fd 3/4；否则
  # socat 会长期持有内部管道，导致 docker compose exec -T 在用例结束后挂起。
  socat TCP-LISTEN:8080,fork,reuseaddr TCP:"$remote_host":"$remote_port" 3>&- 4>&- </dev/null >/dev/null 2>&1 &
  # 等待端口就绪
  for i in $(seq 1 10); do
    if curl -sf --max-time 3 http://localhost:8080/health >/dev/null 2>&1; then
      break
    fi
    sleep 0.3
  done
}

# 确保 Web 服务器正在运行（在 setup_file 中调用）
ensure_webserver_running() {
  ensure_mock_proxy
  local ws
  ws=$(detect_webserver)
  if [ "$ws" = "nginx" ]; then
    nginx -t 2>/dev/null && nginx 2>/dev/null || true
  else
    start_webserver 2>/dev/null || true
  fi
}

# 通用 setup 函数（��个测试前调用，重置 Mock API 状态）
common_setup() {
  mock_reset || true
}

# 生成自签名测试证书和私钥到 /tmp
generate_test_cert() {
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /tmp/test.key -out /tmp/test.crt \
    -subj "/CN=test.example.com" 2>/dev/null
}

# 执行初始 setup（写入配置，后续测试依赖）
run_initial_setup() {
  sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --yes --no-service 2>&1
}
