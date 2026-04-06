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
# $1 = scenario name (active/processing/expired/error/unauthorized/not_found/batch/renew-flow/releases)
mock_set_scenario() {
  curl -sf --max-time 5 -X POST "$MOCK_REMOTE_URL/admin/scenario/$1"
}

# 重置 Mock API 状态（清除请求日志、回调记录，恢复默认场景）
mock_reset() {
  curl -sf --max-time 5 -X POST "$MOCK_REMOTE_URL/admin/reset"
}

# 获取 Mock API 收到的回调记录（JSON）
mock_get_callbacks() {
  curl -sf --max-time 5 "$MOCK_REMOTE_URL/admin/callbacks"
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
  socat TCP-LISTEN:8080,fork,reuseaddr TCP:"$remote_host":"$remote_port" &
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
  sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --yes 2>&1
}
