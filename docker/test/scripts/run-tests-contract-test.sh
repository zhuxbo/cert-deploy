#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$SCRIPT_DIR/run-tests.sh"
E2E_WORKFLOW="$SCRIPT_DIR/../../../.github/workflows/e2e.yml"
COMMON="$SCRIPT_DIR/../tests/helpers/common.bash"
DAEMON_TEST="$SCRIPT_DIR/../tests/daemon.bats"
RENEW_LOCAL_TEST="$SCRIPT_DIR/../tests/renew-local.bats"
TESTS_DIR="$SCRIPT_DIR/../tests"

assert_contains() {
    local pattern="$1"
    local description="$2"
    if ! grep -Eq "$pattern" "$RUNNER"; then
        echo "FAIL: $description"
        return 1
    fi
}

assert_contains 'trap .*cleanup.* EXIT' \
    "runner 必须在 EXIT 时清理 Compose 资源"
assert_contains 'trap .*cleanup.* INT' \
    "runner 必须在 INT 时清理 Compose 资源"
assert_contains 'trap .*cleanup.* TERM' \
    "runner 必须在 TERM 时清理 Compose 资源"
assert_contains 'COMPOSE_PROJECT_NAME=' \
    "runner 必须为每次执行分配唯一 Compose project name"
assert_contains 'RUN_DIND=true' \
    "默认全量测试必须包含 DinD"
assert_contains 'docker-\*\.bats' \
    "DinD 默认必须运行全部 docker-*.bats"
assert_contains 'is_dind_test' \
    "指定 docker-* 测试时必须只路由到 DinD"
if ! grep -Fq -- "-e docker-" "$RUNNER"; then
    echo "FAIL: 常规矩阵必须排除全部 docker-* 测试"
    exit 1
fi
if ! grep -Eq 'default: true' "$E2E_WORKFLOW" || \
   ! grep -Fq -- "github.event_name == 'push'" "$E2E_WORKFLOW"; then
    echo "FAIL: CI 默认全量测试必须包含 DinD"
    exit 1
fi
if ! grep -Fq -- 'bash scripts/run-tests.sh' "$E2E_WORKFLOW"; then
    echo "FAIL: CI 必须复用本地 E2E 入口"
    exit 1
fi
if ! grep -Fq -- '--dind-only' "$E2E_WORKFLOW"; then
    echo "FAIL: CI DinD 必须通过本地 E2E 入口运行"
    exit 1
fi
if grep -Fq -- 'bats --tap' "$E2E_WORKFLOW"; then
    echo "FAIL: CI 不得维护独立的 Bats 测试清单"
    exit 1
fi
if ! grep -Eq 'socat .*3>&- 4>&-' "$COMMON"; then
    echo "FAIL: 后台 socat 必须关闭 Bats 内部 fd 3/4"
    exit 1
fi
if ! grep -Eq 'sslctl setup .*--no-service' "$COMMON"; then
    echo "FAIL: 公共 E2E 初始化不得隐式启动后台服务"
    exit 1
fi
for daemon_test in "$DAEMON_TEST" "$RENEW_LOCAL_TEST"; do
    if ! grep -Fq -- "exec /usr/local/bin/sslctl daemon 3>/dev/null 4>/dev/null" "$daemon_test"; then
        echo "FAIL: 后台 daemon 必须隔离 Bats 内部 fd 3/4: $daemon_test"
        exit 1
    fi
done
if grep -REh '(^|[[:space:]])sslctl setup' "$TESTS_DIR" | grep -qv -- '--no-service'; then
    echo "FAIL: 容器 E2E 不得隐式启动后台服务"
    exit 1
fi
if grep -REq 'date .* -v[+-]' "$TESTS_DIR"; then
    echo "FAIL: 容器 E2E 日期生成不得依赖 BSD date -v"
    exit 1
fi

echo "PASS: run-tests.sh contract"
