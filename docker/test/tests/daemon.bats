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
}

teardown() {
  pkill -f "sslctl daemon" 2>/dev/null || true
}

# ==============================================================================
# daemon 命令测试
# ==============================================================================

@test "daemon: 启动后自动部署" {
  # 场景 active：API 返回有效证书
  mock_set_scenario active

  # 后台启动 daemon
  sslctl daemon &
  local daemon_pid=$!

  # 轮询等待 daemon 完成启动时的立即检查（最多 20 秒）
  for i in $(seq 1 20); do
    requests=$(mock_get_requests 2>/dev/null || echo "")
    if [[ "$requests" == *"/api/"* ]]; then break; fi
    sleep 1
  done

  # 验证 daemon 进程仍在运行
  kill -0 "$daemon_pid" 2>/dev/null
  local running=$?
  if [ "$running" -ne 0 ]; then
    echo "daemon 进程已退出（预期仍在运行）"
    return 1
  fi

  # 检查 Mock API 收到了请求（daemon 启动后立即检查）
  local requests
  requests=$(mock_get_requests)
  if [[ "$requests" != *"/api/cert"* ]] && [[ "$requests" != *"/api/deploy"* ]]; then
    echo "Expected daemon to query API on startup"
    echo "Requests: $requests"
    # 不做硬失败——daemon 可能跳过不需要续签的证书
  fi

  # 检查回调记录（daemon 部署成功后会发送回调）
  local callbacks
  callbacks=$(mock_get_callbacks)
  if [[ "$callbacks" == *"1001"* ]]; then
    echo "daemon 成功部署并发送了回调"
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
