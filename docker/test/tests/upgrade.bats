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
  # 恢复 config.json 备份
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  if [[ -f "${config_file}.bak" ]]; then
    mv "${config_file}.bak" "$config_file"
  fi
  # 恢复原始二进制（upgrade 会替换为 mock 数据）
  cp /opt/sslctl-binary /usr/local/bin/sslctl 2>/dev/null || true
  chmod +x /usr/local/bin/sslctl 2>/dev/null || true
}

# ==============================================================================
# upgrade 命令测试
# ==============================================================================
# e2e 构建使用 -tags e2e，跳过 HTTPS 强制和签名验证，可测试完整升级链路。
# HTTPS 和签名验证由 pkg/upgrade 单元测试覆盖。

@test "upgrade: release_url 未配置时报错" {
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  cp "$config_file" "${config_file}.bak"

  jq 'del(.release_url)' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"

  run sslctl upgrade
  assert_failure
  assert_output_contains "release_url"

  mv "${config_file}.bak" "$config_file"
}

@test "upgrade: --check 检查更新" {
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  cp "$config_file" "${config_file}.bak"

  # 指向 mock-api releases 端点
  jq '.release_url = "http://localhost:8080/releases"' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"

  mock_set_scenario releases

  run sslctl upgrade --check
  assert_success
  # mock-api 返回 v99.0.0，应提示有新版本
  assert_output_contains "99.0.0"

  mv "${config_file}.bak" "$config_file"
}

@test "upgrade: 成功升级（下载/校验/替换）" {
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  cp "$config_file" "${config_file}.bak"

  jq '.release_url = "http://localhost:8080/releases"' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"

  mock_set_scenario releases

  # 记录升级前的二进制 inode
  local before_inode
  before_inode=$(stat -c '%i' /usr/local/bin/sslctl 2>/dev/null || stat -f '%i' /usr/local/bin/sslctl)

  run sslctl upgrade
  assert_success
  assert_output_contains "99.0.0"
  assert_output_contains "升级完成"

  # 验证二进制已被替换（inode 变化）
  local after_inode
  after_inode=$(stat -c '%i' /usr/local/bin/sslctl 2>/dev/null || stat -f '%i' /usr/local/bin/sslctl)
  if [ "$before_inode" = "$after_inode" ]; then
    echo "二进制 inode 未变化，升级可能未实际替换文件"
    return 1
  fi

  # teardown 会恢复原始二进制
  mv "${config_file}.bak" "$config_file"
}

