#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  # 重置 Mock API 到 active 场景，确保配置可用
  mock_reset || true
  mock_set_scenario active || true
  # 清理旧配置，重新 setup
  rm -f "$SSLCTL_CONFIG_DIR/config.json"
  run_initial_setup
  # 验证 setup 成功并提取证书名（持久化到文件，供各测试读取）
  if [ ! -f "$SSLCTL_CONFIG_DIR/config.json" ]; then
    echo "setup_file FAILED: config.json not created" >&2
    return 1
  fi
  local cert_name
  cert_name=$(jq -r '.certificates[0].cert_name' "$SSLCTL_CONFIG_DIR/config.json")
  if [ -z "$cert_name" ] || [ "$cert_name" = "null" ]; then
    echo "setup_file FAILED: no cert_name in config.json" >&2
    jq . "$SSLCTL_CONFIG_DIR/config.json" >&2
    return 1
  fi
  echo "$cert_name" > /tmp/deploy-test-cert-name
}

setup() {
  common_setup
  CERT_NAME=$(cat /tmp/deploy-test-cert-name 2>/dev/null || echo "")
}

# ==============================================================================
# deploy 命令测试
# ==============================================================================

@test "deploy: 部署指定证书" {
  # 证书名从 config.json 动态获取（格式: domain-orderID）
  run sslctl deploy --cert "$CERT_NAME"
  assert_success
}

@test "deploy: 绑定站点部署" {
  run sslctl deploy --cert "$CERT_NAME" --site test.example.com --yes
  assert_success
}

@test "deploy: 部署全部" {
  run sslctl deploy --all
  assert_success
}

@test "deploy: Web 服务器配置有效" {
  # 先部署证书确保配置已更新
  sslctl deploy --cert "$CERT_NAME" 2>&1 || true
  run test_webserver_config
  assert_success
}

@test "deploy: 备份已创建" {
  # 部署后应在 backup 目录下创建备份
  sslctl deploy --cert "$CERT_NAME" 2>&1 || true
  assert_dir_exists "$SSLCTL_CONFIG_DIR/backup"
  # 检查 backup 目录下有内容（至少有一个站点的备份子目录）
  local count
  count=$(find "$SSLCTL_CONFIG_DIR/backup" -mindepth 1 -maxdepth 2 -type d 2>/dev/null | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "Expected backup directories to exist under $SSLCTL_CONFIG_DIR/backup"
    return 1
  fi
}

@test "deploy: 回调已发送" {
  # 先重置以清空回调记录
  mock_reset
  # 执行部署
  sslctl deploy --cert "$CERT_NAME" 2>&1 || true
  # 检查 Mock API 收到的回调
  local callbacks
  callbacks=$(mock_get_callbacks)
  # 回调应包含订单 ID 1001
  if [[ "$callbacks" != *"1001"* ]]; then
    echo "Expected callback with order_id 1001"
    echo "Callbacks: $callbacks"
    return 1
  fi
}
