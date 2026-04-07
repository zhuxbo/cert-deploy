#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
}

setup() {
  common_setup
}

# ==============================================================================
# setup 命令测试
# ==============================================================================

@test "setup: 单证书部署成功" {
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --yes
  assert_success
  assert_file_exists "$SSLCTL_CONFIG_DIR/config.json"
  assert_dir_exists "$SSLCTL_CONFIG_DIR/certs"
}

@test "setup: 批量部署" {
  mock_set_scenario batch
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order "1001,test.example.com" --yes
  assert_success
}

@test "setup: 全部部署" {
  mock_set_scenario batch
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --yes
  assert_success
}

@test "setup: 指定私钥" {
  openssl genrsa -out /tmp/test-setup.key 2048 2>/dev/null
  run sslctl setup --key /tmp/test-setup.key --url "$MOCK_URL" --token "$TOKEN" --order 1001 --yes
  assert_success
  rm -f /tmp/test-setup.key
}

@test "setup: 文件验证模式（processing 状态应失败）" {
  mock_set_scenario processing
  run sslctl setup --file-validation --webroot /var/www/html --url "$MOCK_URL" --token "$TOKEN" --order 1002 --yes
  # processing 场景下证书未就绪，setup 应失败退出
  assert_failure
  assert_output_contains "processing"
  # 注意: 文件验证挑战文件的放置发生在 daemon 续签流程中（certops/renew.go），
  # setup 在证书未就绪时直接退出，不会写入验证文件
  assert_file_not_exists "/var/www/html/.well-known/pki-validation/test.txt"
}

@test "setup: 不安装服务" {
  # 清理之前测试可能安装的服务文件
  rm -f /etc/systemd/system/sslctl.service /etc/init.d/sslctl 2>/dev/null || true
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_success
  # 验证没有安装 systemd/openrc 服务文件
  if [ -f /etc/systemd/system/sslctl.service ]; then
    echo "Unexpected: systemd service file exists"
    return 1
  fi
  if [ -f /etc/init.d/sslctl ]; then
    echo "Unexpected: init.d service file exists"
    return 1
  fi
}

@test "setup: API 错误" {
  mock_set_scenario error
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --yes
  assert_failure
}

@test "setup: 认证失败" {
  mock_set_scenario unauthorized
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --yes
  assert_failure
}

@test "setup: 订单不存在" {
  mock_set_scenario not_found
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --yes
  assert_failure
}

@test "setup: processing 状态" {
  mock_set_scenario processing
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1002 --yes
  # processing 状态下证书未签发，输出应包含 processing 相关信息
  assert_output_contains "processing"
}
