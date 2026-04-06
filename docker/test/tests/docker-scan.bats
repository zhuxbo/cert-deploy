#!/usr/bin/env bats

load 'helpers/common'

# DinD (Docker-in-Docker) 环境测试
# 测试 sslctl 对 Docker 容器内 Nginx 的扫描能力
# 运行环境：docker:dind 容器，内部启动 nginx 子容器

setup_file() {
  # 等待 Docker daemon 就绪（dind 容器启动后 dockerd 需要几秒初始化）
  local max_wait=30
  local count=0
  while ! docker info &>/dev/null && [ $count -lt $max_wait ]; do
    sleep 1
    count=$((count + 1))
  done

  if ! docker info &>/dev/null; then
    skip "Docker daemon 未就绪"
  fi

  # 准备自定义 nginx 配置（默认 nginx:1.27-alpine 的 server_name 是 _，scanner 会跳过）
  mkdir -p /tmp/nginx-conf
  cat > /tmp/nginx-conf/default.conf <<'CONF'
server {
    listen 80;
    server_name docker-test.example.com;

    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}

server {
    listen 443 ssl;
    server_name docker-ssl.example.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}
CONF

  # 生成自签名证书供 SSL 站点使用
  mkdir -p /tmp/nginx-ssl
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /tmp/nginx-ssl/key.pem -out /tmp/nginx-ssl/cert.pem \
    -subj "/CN=docker-ssl.example.com" 2>/dev/null

  # 启动 nginx 容器（挂载自定义配置和证书）
  docker pull nginx:1.27-alpine 2>/dev/null || true
  docker run -d --name test-nginx \
    -v /tmp/nginx-conf/default.conf:/etc/nginx/conf.d/default.conf:ro \
    -v /tmp/nginx-ssl:/etc/nginx/ssl:ro \
    nginx:1.27-alpine

  # 等待 nginx 容器就绪
  local nginx_wait=10
  local nginx_count=0
  while ! docker exec test-nginx nginx -t &>/dev/null && [ $nginx_count -lt $nginx_wait ]; do
    sleep 1
    nginx_count=$((nginx_count + 1))
  done
}

teardown_file() {
  docker rm -f test-nginx 2>/dev/null || true
  rm -rf /tmp/nginx-conf /tmp/nginx-ssl
}

setup() {
  # DinD 环境不一定能访问 mock-api，跳过 mock_reset
  true
}

# ==============================================================================
# Docker 容器扫描测试
# ==============================================================================

@test "docker-scan: 发现 Docker Nginx 容器站点" {
  run sslctl scan
  assert_success

  # 验证发现了 Docker 容器中的站点
  assert_output_contains "docker-test.example.com"

  # 验证来源标记为 docker
  assert_output_contains "docker"
}

@test "docker-scan: 发现容器 SSL 站点" {
  run sslctl scan --ssl-only
  assert_success

  # --ssl-only 应只包含配置了 ssl_certificate 的站点
  assert_output_contains "docker-ssl.example.com"
}

@test "docker-scan: 输出包含容器名" {
  run sslctl scan
  assert_success

  # 输出中应包含容器名称
  assert_output_contains "test-nginx"
}

@test "docker-scan: 扫描结果保存到配置" {
  # 先执行扫描
  run sslctl scan
  assert_success

  # 验证扫描结果文件已生成
  assert_file_exists "$SSLCTL_CONFIG_DIR/scan-result.json"

  # 验证扫描结果中包含 Docker 站点信息
  assert_file_contains "$SSLCTL_CONFIG_DIR/scan-result.json" "docker-test.example.com"
  assert_file_contains "$SSLCTL_CONFIG_DIR/scan-result.json" "docker"
}
