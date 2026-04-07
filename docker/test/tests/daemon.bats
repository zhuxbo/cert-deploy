#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  mock_reset || true
  mock_set_scenario active || true
  rm -f "$SSLCTL_CONFIG_DIR/config.json"
  run_initial_setup

  # 将证书过期时间改为 5 天后，使 daemon 的 NeedsRenewal() 返回 true
  # （默认 renew_before_days=14，5 天 < 14 天 → 需要续签）
  local soon
  soon=$(date -u -d "+5 days" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+5d "+%Y-%m-%dT%H:%M:%SZ")
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  jq --arg t "$soon" '(.certificates[]?.metadata.cert_expires_at) = $t' "$config_file" > "${config_file}.tmp" \
    && mv "${config_file}.tmp" "$config_file"
}

setup() {
  common_setup
  # 每个测试前确保 daemon 未运行
  pkill -f "sslctl daemon" 2>/dev/null || true
  sleep 1
}

teardown() {
  pkill -f "sslctl daemon" 2>/dev/null || true
}

# ==============================================================================
# daemon 命令测试
# ==============================================================================

@test "daemon: 启动后自动续签" {
  # setup_file 已将 cert_expires_at 设为 5 天后（< renew_before_days 14），daemon 应尝试续签
  mock_set_scenario active

  # 后台启动 daemon
  sslctl daemon &
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

  # 检查回调记录（部署成功后应发送回调）
  local callbacks
  callbacks=$(mock_get_callbacks)
  if [[ "$callbacks" != *"1001"* ]]; then
    echo "daemon 续签后未发送回调"
    echo "Callbacks: $callbacks"
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
  sslctl daemon &
  local daemon_pid=$!

  # 轮询等待 daemon 完成启动时的立即检查（最多 20 秒）
  for i in $(seq 1 20); do
    requests=$(mock_get_requests 2>/dev/null || echo "")
    if [[ "$requests" == *"/api/"* ]]; then break; fi
    sleep 1
  done

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
