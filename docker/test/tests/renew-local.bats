#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  mock_reset
  mock_set_scenario active
  rm -f "$SSLCTL_CONFIG_DIR/config.json"
  run_initial_setup
  CERT_NAME=$(jq -r '.certificates[0].cert_name' "$SSLCTL_CONFIG_DIR/config.json")
  echo "$CERT_NAME" > /tmp/renew-local-cert-name
}

setup() {
  ensure_mock_proxy
  pkill -f "sslctl daemon" 2>/dev/null || true
  rm -f /tmp/renew-local-web.conf
  CERT_NAME=$(cat /tmp/renew-local-cert-name)
}

teardown() {
  pkill -f "sslctl daemon" 2>/dev/null || true
  if [ -f /tmp/renew-local-web.conf ]; then
    local config_path
    config_path=$(binding_value '.paths.config_file')
    cp /tmp/renew-local-web.conf "$config_path"
    reload_webserver >/dev/null 2>&1 || true
    rm -f /tmp/renew-local-web.conf
  fi
  rm -f "$SSLCTL_CONFIG_DIR"/config.json.renew-local.*
}

start_daemon_until() {
  local condition="$1"
  sh -c 'exec /usr/local/bin/sslctl daemon 3>/dev/null 4>/dev/null' </dev/null >/tmp/renew-local-daemon.out 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 40); do
    if eval "$condition"; then
      return 0
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      cat /tmp/renew-local-daemon.out >&2
      return 1
    fi
    sleep 0.5
  done
  cat /tmp/renew-local-daemon.out >&2
  return 1
}

stop_daemon() {
  kill "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
}

@test "renew-local: processing 保留 pending，失败回滚并上报 message，成功后转正" {
  local config_file="$SSLCTL_CONFIG_DIR/config.json"
  local soon pending_path cert_path key_path config_path old_fp callbacks temp_config
  soon=$(future_rfc3339 5)
  temp_config=$(mktemp "${config_file}.renew-local.XXXXXX")
  jq --arg t "$soon" '
    .certificates[0].renew_mode = "local" |
    .certificates[0].validation_method = "delegation" |
    .certificates[0].metadata.cert_expires_at = $t
  ' "$config_file" > "$temp_config"
  mv "$temp_config" "$config_file"

  pending_path="$SSLCTL_CONFIG_DIR/pending-keys/$CERT_NAME/pending-key.pem"
  start_daemon_until "[ -f '$pending_path' ] && [ \"\$(jq -r '.certificates[0].metadata.last_issue_state' '$config_file')\" = processing ]"
  stop_daemon
  assert_file_exists "$pending_path"

  cert_path=$(binding_value '.paths.certificate')
  key_path=$(binding_value '.paths.private_key')
  config_path=$(binding_value '.paths.config_file')
  old_fp=$(cert_fingerprint "$cert_path")
  cp "$config_path" /tmp/renew-local-web.conf
  printf '\nsslctl_invalid_directive\n' >> "$config_path"

  start_daemon_until "mock_get_callbacks | jq -e 'map(select(.status == \"failure\" and (.message | length) > 0)) | length > 0' >/dev/null"
  stop_daemon
  cp /tmp/renew-local-web.conf "$config_path"
  rm -f /tmp/renew-local-web.conf

  assert_file_exists "$pending_path"
  [ "$(cert_fingerprint "$cert_path")" = "$old_fp" ]
  assert_cert_key_match "$cert_path" "$key_path"
  callbacks=$(mock_get_callbacks)
  echo "$callbacks" | jq -e 'map(select(.status == "failure" and (.message | length) > 0 and (.message | length) <= 256)) | length > 0' >/dev/null

  start_daemon_until "[ ! -f '$pending_path' ] && mock_get_callbacks | jq -e 'map(select(.status == \"success\")) | length > 0' >/dev/null"
  stop_daemon

  assert_file_not_exists "$pending_path"
  assert_cert_key_match "$cert_path" "$key_path"
  wait_for_tls_fingerprint '127.0.0.1:443' 'test.example.com' "$(cert_fingerprint "$cert_path")"
}
