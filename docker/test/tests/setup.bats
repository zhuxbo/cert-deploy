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
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_success
  assert_file_exists "$SSLCTL_CONFIG_DIR/config.json"
  assert_dir_exists "$SSLCTL_CONFIG_DIR/certs"
}

@test "setup: 批量部署" {
  mock_set_scenario batch
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order "1001,test.example.com" --no-service --yes
  assert_success
}

@test "setup: 全部部署" {
  mock_set_scenario batch
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --no-service --yes
  assert_success
}

@test "setup: 指定私钥" {
  openssl genrsa -out /tmp/test-setup.key 2048 2>/dev/null
  run sslctl setup --key /tmp/test-setup.key --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_success
  rm -f /tmp/test-setup.key
}

@test "setup: 文件验证模式（processing 状态应失败）" {
  mock_set_scenario processing
  run sslctl setup --file-validation --webroot /var/www/html --url "$MOCK_URL" --token "$TOKEN" --order 1002 --no-service --yes
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
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_failure
}

@test "setup: 认证失败" {
  mock_set_scenario unauthorized
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_failure
}

@test "setup: 订单不存在" {
  mock_set_scenario not_found
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_failure
}

@test "setup: processing 状态" {
  mock_set_scenario processing
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1002 --no-service --yes
  assert_failure
  assert_output_contains "processing"
}

# ==============================================================================
# SSL 自动安装：目标块选择与失败语义
# ==============================================================================

# nginx_site_dir 返回本发行版启用站点的目录
# Alpine nginx 的 conf.d/ 在顶层 include（非 http{} 内），server{} 需放入 http.d/
nginx_site_dir() {
  if [ -d /etc/nginx/http.d ]; then
    echo /etc/nginx/http.d
  else
    echo /etc/nginx/conf.d
  fi
}

WILDCARD_FAMILY_CONF=""

teardown() {
  # 仅清理本文件自建的 fixture，对其他用例无副作用
  if [ -n "$WILDCARD_FAMILY_CONF" ] && [ -f "$WILDCARD_FAMILY_CONF" ]; then
    rm -f "$WILDCARD_FAMILY_CONF"
    rm -f /etc/nginx/ssl/wildcard-family.crt /etc/nginx/ssl/wildcard-family.key
    nginx -t &>/dev/null && nginx -s reload &>/dev/null || true
  fi
}

# 回归：目标站点自身在非 80 端口且未配 SSL，而同域族的通配符块已配 SSL。
# 安装器必须报明确错误并让该绑定计为失败（非零退出）；若因通配符块已有 SSL 而短路成
# "无需安装"，setup 会继续部署证书并报成功，但目标站点 HTTPS 实际未生效。
# 通配符块使用独立证书路径，避免覆盖基础 fixture 的 default.crt。
@test "setup: 目标块非 80 时不被同域族通配符 SSL 块短路，明确失败" {
  if [ "$(detect_webserver)" != "nginx" ]; then
    skip "仅 nginx 适用"
  fi

  WILDCARD_FAMILY_CONF="$(nginx_site_dir)/wildcard-family.conf"

  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/wildcard-family.key \
    -out /etc/nginx/ssl/wildcard-family.crt \
    -subj "/CN=*.example.com" 2>/dev/null

  # Mock 证书 SAN 为 example.com / *.example.com，通配符只匹配单级子域名，
  # 故目标块用 www.example.com（被 *.example.com 覆盖），干扰块用 *.example.com 本身。
  cat > "$WILDCARD_FAMILY_CONF" <<'EOF'
server {
    listen 8080;
    server_name www.example.com;
    root /var/www/html;
}

server {
    listen 8443 ssl;
    server_name *.example.com;
    ssl_certificate /etc/nginx/ssl/wildcard-family.crt;
    ssl_certificate_key /etc/nginx/ssl/wildcard-family.key;
    root /var/www/html;
}
EOF

  nginx -t
  nginx -s reload

  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_failure
  assert_output_contains "未找到可安装 HTTPS 的 server 块"

  # 非 80 的目标块不得被注入 listen 443
  run grep -c "listen 443 ssl" "$WILDCARD_FAMILY_CONF"
  [ "$output" = "0" ]

  # 通配符块原有证书路径不得被安装器改写
  assert_file_contains "$WILDCARD_FAMILY_CONF" "ssl_certificate /etc/nginx/ssl/wildcard-family.crt;"

  # 配置整体仍可通过 nginx 校验
  run nginx -t
  assert_success
}
