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
}

teardown() {
  # 确保 config.json 备份在异常退出时也能恢复
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  [[ -f "${config_file}.bak" ]] && mv "${config_file}.bak" "$config_file"
}

# ==============================================================================
# upgrade 命令测试
# ==============================================================================

@test "upgrade: release_url 未配置时报错" {
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  cp "$config_file" "${config_file}.bak"

  # 用 jq 移除 release_url 字段
  jq 'del(.release_url)' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"

  # 非交互环境下，未配置 release_url 应报错
  run sslctl upgrade
  assert_failure
  assert_output_contains "release_url"

  # 恢复配置
  mv "${config_file}.bak" "$config_file"
}

@test "upgrade: 拒绝非 HTTPS 地址" {
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  cp "$config_file" "${config_file}.bak"

  # 用 jq 写入 HTTP 地址
  jq '.release_url = "http://mock-api:8080/releases"' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"

  run sslctl upgrade
  assert_failure
  # 应包含 HTTPS 或安全相关的错误信息
  if [[ "$output" != *"HTTPS"* ]] && [[ "$output" != *"https"* ]] && [[ "$output" != *"不安全"* ]]; then
    echo "Expected output to mention HTTPS requirement"
    echo "Actual output: $output"
    mv "${config_file}.bak" "$config_file"
    return 1
  fi

  mv "${config_file}.bak" "$config_file"
}

@test "upgrade: --check 参数可用" {
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  cp "$config_file" "${config_file}.bak"

  # 写入一个 HTTPS 地址（不存在的域名，测试参数解析正常）
  jq '.release_url = "https://nonexistent.example.com/sslctl"' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"

  # --check 应尝试连接远程服务器，因为域名不存在会失败，但不应因参数问题失败
  run sslctl upgrade --check
  assert_failure
  assert_output_not_contains "unknown flag"
  assert_output_not_contains "用法"

  mv "${config_file}.bak" "$config_file"
}
