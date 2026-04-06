#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  mock_reset || true
  mock_set_scenario active || true
  rm -f "$SSLCTL_CONFIG_DIR/config.json"
  run_initial_setup
  sslctl deploy --all --yes 2>&1 || true
}

setup() {
  common_setup
}

# ==============================================================================
# status / version 命令测试
# ==============================================================================

@test "status: 显示证书状态" {
  run sslctl status
  assert_success
  # status 输出应包含证书配置信息
  assert_output_contains "证书配置"
}

@test "version: 显示版本" {
  run sslctl version
  assert_success
  assert_output_contains "sslctl"
}
