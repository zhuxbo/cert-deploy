#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  mock_reset || true
  mock_set_scenario active || true
  rm -f "$SSLCTL_CONFIG_DIR/config.json"
  run_initial_setup

}

setup() {
  common_setup
  # 每个测试前确保 daemon 未运行
  pkill -f "sslctl daemon" 2>/dev/null || true
  sleep 1

  # 每个用例都重新设为临期，避免前一用例部署成功后更新到期日导致续签路径未执行。
  local soon config_file
  soon=$(future_rfc3339 5)
  config_file="$SSLCTL_CONFIG_DIR/config.json"
  jq --arg t "$soon" '
    (.certificates[]?.metadata.cert_expires_at) = $t |
    (.certificates[]?.bindings[]?.paths.webroot) = "/var/www/html"
  ' "$config_file" > "${config_file}.tmp" \
    && mv "${config_file}.tmp" "$config_file"
  rm -f /var/www/html/.well-known/pki-validation/test.txt
}

teardown() {
  pkill -f "sslctl daemon" 2>/dev/null || true
  rm -f /var/www/html/.well-known/pki-validation/test.txt
}

# ==============================================================================
# daemon 命令测试
# ==============================================================================

@test "daemon: 启动后自动续签" {
  # setup 已将 cert_expires_at 设为 5 天后（< renew_before_days 14），daemon 应尝试续签
  mock_set_scenario active

  # 后台启动 daemon
  sh -c 'exec /usr/local/bin/sslctl daemon 3>/dev/null 4>/dev/null' </dev/null >/tmp/daemon-e2e.out 2>&1 &
  local daemon_pid=$!

  # 轮询等待 daemon 发起 API 请求（最多 30 秒）
  local api_called=false
  for i in $(seq 1 30); do
    requests=$(mock_get_requests 2>/dev/null || echo "")
    if [[ "$requests" == *"/api/"* ]]; then
      api_called=true
      break
    fi
    sleep 1
  done

  # 验证 daemon 进程仍在运行
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "daemon 进程已退出（预期仍在运行）"
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    return 1
  fi

  # 硬断言：daemon 必须查询过 API（cert_expires_at 已设为 5 天后）
  if [ "$api_called" != "true" ]; then
    echo "daemon 启动后未查询 API（证书即将过期，应触发续签）"
    echo "Requests: $(mock_get_requests 2>/dev/null)"
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    return 1
  fi

  # API 查询只表示续签已经开始；部署和回调仍在异步执行，需单独等待目标订单的回调。
  local callbacks="[]"
  local callback_seen=false
  for i in $(seq 1 30); do
    callbacks=$(mock_get_callbacks 2>/dev/null || echo "[]")
    if echo "$callbacks" | jq -e 'any(.[]; .order_id == 1001)' >/dev/null 2>&1; then
      callback_seen=true
      break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  if [ "$callback_seen" != "true" ]; then
    echo "daemon 续签后未发送回调"
    echo "Callbacks: $callbacks"
    echo "Requests: $(mock_get_requests 2>/dev/null)"
    cat /tmp/daemon-e2e.out 2>/dev/null || true
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    return 1
  fi

  # 清理
  kill "$daemon_pid" 2>/dev/null || true
  wait "$daemon_pid" 2>/dev/null || true
}

@test "daemon: 正确处理 processing 状态" {
  # renew-flow 场景：首次查询返回 processing
  mock_set_scenario renew-flow

  # 后台启动 daemon
  sh -c 'exec /usr/local/bin/sslctl daemon 3>/dev/null 4>/dev/null' </dev/null >/tmp/daemon-e2e.out 2>&1 &
  local daemon_pid=$!

  # 轮询等待 daemon 处理 processing 响应并放置验证文件（最多 20 秒）
  local processing_seen=false
  for i in $(seq 1 20); do
    requests=$(mock_get_requests 2>/dev/null || echo "")
    if echo "$requests" | jq -e 'any(.[]; .method == "GET" and .path == "/api/deploy" and ((.query.order // []) | index("1001") != null))' >/dev/null 2>&1 \
      && [ "$(cat /var/www/html/.well-known/pki-validation/test.txt 2>/dev/null)" = "test-validation-content-12345" ]; then
      processing_seen=true
      break
    fi
    sleep 1
  done

  if [ "$processing_seen" != "true" ]; then
    echo "daemon 未实际处理 processing 响应或未放置验证文件"
    echo "Requests: $(mock_get_requests 2>/dev/null)"
    cat /tmp/daemon-e2e.out 2>/dev/null || true
    return 1
  fi

  # daemon 应该仍在运行（不会因 processing 状态崩溃）
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "daemon 进程意外退出"
    return 1
  fi

  # 检查 daemon 日志中包含处理记录
  local log_dir="$SSLCTL_CONFIG_DIR/logs"
  if [ -d "$log_dir" ]; then
    # 日志存在说明 daemon 正常启动和运行
    local log_count
    log_count=$(find "$log_dir" -name "daemon*" -type f 2>/dev/null | wc -l)
    if [ "$log_count" -gt 0 ]; then
      echo "daemon 日志文件已创建"
    fi
  fi

  # 清理
  kill "$daemon_pid" 2>/dev/null || true
  wait "$daemon_pid" 2>/dev/null || true
}
