#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
}

setup() {
  common_setup
}

# 每个测试结束后清理可能残留的相对路径测试站点
# 即使测试断言失败，teardown 也会执行，防止配置残留导致后续测试级联失败
teardown() {
  for name in relpath.example.com flagtest.example.com setupprefix.example.com; do
    _cleanup_relative_path_site "$name" 2>/dev/null || true
  done
  reload_webserver 2>/dev/null || true
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

# ==============================================================================
# prefix 相对路径解析测试
# ==============================================================================

# 辅助函数：获取当前 Web 服务器的 prefix 路径
# 兼容 BusyBox grep（Alpine 无 -P 选项），改用 sed 提取
_get_prefix() {
  local ws
  ws=$(detect_webserver)
  if [ "$ws" = "nginx" ]; then
    nginx -V 2>&1 | sed -n 's/.*--prefix=\([^ ]*\).*/\1/p'
  else
    local bin=""
    if command -v httpd &>/dev/null; then bin="httpd"
    elif command -v apache2ctl &>/dev/null; then bin="apache2ctl"
    elif command -v apachectl &>/dev/null; then bin="apachectl"
    fi
    [ -n "$bin" ] && $bin -V 2>&1 | sed -n 's/.*HTTPD_ROOT="\([^"]*\)".*/\1/p'
  fi
}

# 辅助函数：获取配置目录（存放 vhost 的目录）
_get_conf_dir() {
  local ws
  ws=$(detect_webserver)
  if [ "$ws" = "nginx" ]; then
    if [ -d /etc/nginx/http.d ]; then
      echo "/etc/nginx/http.d"    # Alpine
    elif [ -d /etc/nginx/conf.d ]; then
      echo "/etc/nginx/conf.d"
    else
      echo "/etc/nginx/sites-enabled"
    fi
  else
    if [ -d /etc/apache2/sites-available ]; then
      echo "/etc/apache2/sites-available"  # Ubuntu/Debian
    elif [ -d /etc/apache2/conf.d ]; then
      echo "/etc/apache2/conf.d"           # Alpine
    elif [ -d /etc/httpd/conf.d ]; then
      echo "/etc/httpd/conf.d"             # Rocky
    fi
  fi
}

# 辅助函数：创建使用相对路径的站点配置
# $1 = 相对路径前缀（如 "ssl/"），$2 = server_name
_create_relative_path_site() {
  local rel_prefix="$1"
  local server_name="$2"
  local ws conf_dir prefix

  ws=$(detect_webserver)
  conf_dir=$(_get_conf_dir)
  prefix=$(_get_prefix)

  # 先创建证书（绝对路径），确保文件存在
  mkdir -p "$prefix/${rel_prefix}"
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout "$prefix/${rel_prefix}${server_name}.key" \
    -out "$prefix/${rel_prefix}${server_name}.crt" \
    -subj "/CN=$server_name" 2>/dev/null

  if [ "$ws" = "nginx" ]; then
    cat > "$conf_dir/${server_name}.conf" <<CONF
server {
    listen 443 ssl;
    server_name $server_name;
    ssl_certificate ${rel_prefix}${server_name}.crt;
    ssl_certificate_key ${rel_prefix}${server_name}.key;
    root /var/www/html;
}
CONF
  else
    cat > "$conf_dir/${server_name}.conf" <<CONF
<VirtualHost *:443>
    ServerName $server_name
    SSLEngine on
    SSLCertificateFile ${rel_prefix}${server_name}.crt
    SSLCertificateKeyFile ${rel_prefix}${server_name}.key
    DocumentRoot /var/www/html
</VirtualHost>
CONF
    # Ubuntu/Debian 需要 a2ensite
    if command -v a2ensite &>/dev/null; then
      a2ensite "${server_name}.conf" 2>/dev/null || true
    fi
  fi
}

# 辅助函数：清理相对路径测试站点
_cleanup_relative_path_site() {
  local server_name="$1"
  local ws conf_dir prefix rel_prefix="${2:-ssl/}"

  ws=$(detect_webserver)
  conf_dir=$(_get_conf_dir)
  prefix=$(_get_prefix)

  if [ "$ws" = "nginx" ]; then
    rm -f "$conf_dir/${server_name}.conf"
  else
    if command -v a2dissite &>/dev/null; then
      a2dissite "${server_name}.conf" 2>/dev/null || true
    fi
    rm -f "$conf_dir/${server_name}.conf"
  fi
  rm -f "$prefix/${rel_prefix}${server_name}.crt" "$prefix/${rel_prefix}${server_name}.key"
}

@test "scan: 相对路径自动解析（prefix 自动探测）" {
  local prefix
  prefix=$(_get_prefix)
  [ -n "$prefix" ] || skip "无法获取 prefix，跳过"

  _create_relative_path_site "ssl/" "relpath.example.com"
  reload_webserver 2>/dev/null || true

  run sslctl scan
  assert_success
  assert_output_contains "relpath.example.com"
  # 不应触发 prefix 未知错误
  assert_output_not_contains "prefix unknown"
}

@test "scan: --nginx-prefix / --apache-prefix 显式指定" {
  local ws prefix flag_name
  ws=$(detect_webserver)
  prefix=$(_get_prefix)
  [ -n "$prefix" ] || skip "无法获取 prefix，跳过"

  if [ "$ws" = "nginx" ]; then
    flag_name="--nginx-prefix"
  else
    flag_name="--apache-prefix"
  fi

  _create_relative_path_site "ssl/" "flagtest.example.com"
  reload_webserver 2>/dev/null || true

  run sslctl scan $flag_name "$prefix"
  assert_success
  assert_output_contains "flagtest.example.com"
}

@test "scan: setup 命令接受 prefix 参数不报错" {
  local ws prefix flag_name
  ws=$(detect_webserver)
  prefix=$(_get_prefix)
  [ -n "$prefix" ] || skip "无法获取 prefix，跳过"

  if [ "$ws" = "nginx" ]; then
    flag_name="--nginx-prefix"
  else
    flag_name="--apache-prefix"
  fi

  # 不创建相对路径站点，仅验证 setup 能接受 prefix 参数且扫描阶段不报 prefix 错误
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes $flag_name "$prefix"
  # setup 会因正常部署流程（部署证书到 test.example.com）决定成功/失败，
  # 但不应出现 prefix 未知的阻断错误
  assert_output_not_contains "无法确定"
  assert_output_not_contains "prefix unknown"
}
