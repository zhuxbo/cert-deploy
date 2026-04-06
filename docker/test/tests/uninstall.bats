#!/usr/bin/env bats

# 注意: uninstall.bats 必须最后执行（run-tests.sh 已保证排序）
# uninstall 会清理服务和配置，导致后续测试无法运行

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  mock_reset || true
  mock_set_scenario active || true
  rm -f "$SSLCTL_CONFIG_DIR/config.json"
  run_initial_setup
}

# ==============================================================================
# uninstall 命令测试
# ==============================================================================

@test "uninstall: 卸载清理" {
  # sslctl 二进制通过 volume :ro 挂载，uninstall 无法删除它
  # 但应该能完成服务卸载和其他清理操作

  # 先将 sslctl 复制到容器内可写位置，模拟真实安装
  cp /usr/local/bin/sslctl /tmp/sslctl-copy
  chmod +x /tmp/sslctl-copy

  # 用可写副本执行卸载（echo "n" 拒绝删除配置目录，避免破坏测试状态）
  run bash -c 'echo "n" | /tmp/sslctl-copy uninstall'
  assert_success
  assert_output_contains "卸载完成"

  # 验证卸载输出包含预期的清理步骤
  assert_output_contains "卸载"

  # 验证配置目录被保留（因为回答了 n）
  assert_dir_exists "$SSLCTL_CONFIG_DIR"

  rm -f /tmp/sslctl-copy
}
