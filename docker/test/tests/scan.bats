#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
}

setup() {
  common_setup
}

# ==============================================================================
# scan 命令测试
# ==============================================================================

@test "scan: 全量扫描" {
  run sslctl scan
  assert_success
  assert_output_contains "test.example.com"
}

@test "scan: 仅 SSL 站点" {
  run sslctl scan --ssl-only
  assert_success
  assert_output_contains "test.example.com"
}
