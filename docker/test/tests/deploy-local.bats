#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  # 生成测试用自签名证书和私钥
  generate_test_cert
}

setup() {
  common_setup
}

# ==============================================================================
# deploy local 命令测试
# ==============================================================================

@test "deploy-local: 基本部署" {
  run sslctl deploy local --cert /tmp/test.crt --key /tmp/test.key --site test.example.com
  assert_success
}

@test "deploy-local: 带中间证书" {
  # 生成自签名 CA 证书作为中间证书
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /tmp/ca.key -out /tmp/ca.crt \
    -subj "/CN=Test CA" 2>/dev/null

  run sslctl deploy local --cert /tmp/test.crt --key /tmp/test.key --ca /tmp/ca.crt --site test.example.com
  assert_success

  rm -f /tmp/ca.key /tmp/ca.crt
}

@test "deploy-local: 无效证书" {
  echo "invalid" > /tmp/bad.crt
  run sslctl deploy local --cert /tmp/bad.crt --key /tmp/test.key --site test.example.com
  assert_failure
  rm -f /tmp/bad.crt
}
