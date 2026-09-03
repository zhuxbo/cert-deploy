#!/usr/bin/env bash
# 变更影响规划器的离线契约测试。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() { echo "变更检查规划器测试失败: $*" >&2; exit 1; }

new_fixture() {
    local name="$1"
    local fixture="$TEST_ROOT/$name"

    mkdir -p "$fixture/app" "$fixture/core" "$fixture/pkg/config" "$fixture/docker/test/mock-api"
    (
        cd "$fixture"
        git init -q
        git config user.name test
        git config user.email test@example.test
    )
    cat >"$fixture/go.mod" <<'EOF'
module example.test/project

go 1.26.0

toolchain go1.26.8
EOF
    cat >"$fixture/core/core.go" <<'EOF'
package core

func Value() int { return 1 }
EOF
    cat >"$fixture/app/app.go" <<'EOF'
package app

import "example.test/project/core"

func Value() int { return core.Value() }
EOF
    cat >"$fixture/pkg/config/config.go" <<'EOF'
package config

func Enabled() bool { return true }
EOF
    cat >"$fixture/pkg/config/config_test.go" <<'EOF'
package config

import "testing"

func TestEnabled(t *testing.T) {
	if !Enabled() { t.Fatal("expected enabled") }
}
EOF
    cat >"$fixture/docker/test/mock-api/main.go" <<'EOF'
package main

func main() {}
EOF
    printf '# fixture\n' >"$fixture/README.md"
    (
        cd "$fixture"
        git add .
        git commit -qm baseline
    )
    printf '%s\n' "$fixture"
}

plan() {
    local fixture="$1"
    local output="$2"
    shift 2
    mkdir -p "$TEST_ROOT/go-cache" "$TEST_ROOT/go-tmp"
    GOCACHE="$TEST_ROOT/go-cache" GOTMPDIR="$TEST_ROOT/go-tmp" TMPDIR="$TEST_ROOT" \
        python3 "$ROOT/build/plan-checks.py" --root "$fixture" --base HEAD "$@" >"$output"
}

assert_json() {
    local output="$1"
    local expression="$2"
    local message="$3"
    PLAN_PATH="$output" PLAN_EXPRESSION="$expression" python3 - <<'PY' || fail "$message"
import json
import os

with open(os.environ["PLAN_PATH"], encoding="utf-8") as handle:
    plan = json.load(handle)
assert eval(
    os.environ["PLAN_EXPRESSION"],
    {"__builtins__": {"len": len, "set": set, "sorted": sorted, "sum": sum}},
    {"plan": plan},
)
PY
}

fixture="$(new_fixture docs-only)"
printf '\nchanged\n' >>"$fixture/README.md"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none"' "文档变更不应触发变异测试"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == []' "文档变更不应触发 Go 测试"

fixture="$(new_fixture direct-and-reverse)"
printf '\n// changed\n' >>"$fixture/core/core.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "changed-lines"' "普通生产代码变更应使用 changed-line 模式"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == ["./app", "./core"]' "未包含直接包与反向依赖包"
assert_json "$fixture/plan.json" 'plan["mutation"]["packages"] == ["./core"]' "变异目标应限制在直接变更包"
assert_json "$fixture/plan.json" 'plan["mutation"]["canary_packages"] == []' "生产变更不应凭空增加测试哨兵"

fixture="$(new_fixture critical-package)"
printf '\n// changed\n' >>"$fixture/pkg/config/config.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "changed-lines"' "关键包生产代码变更也应限制到 changed-line"
assert_json "$fixture/plan.json" 'plan["mutation"]["packages"] == ["./pkg/config"]' "关键包目标错误"

fixture="$(new_fixture tests-only)"
printf '\n// changed\n' >>"$fixture/pkg/config/config_test.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none"' "仅测试变更不应扫描生产代码"
assert_json "$fixture/plan.json" 'plan["mutation"]["canary_packages"] == ["./pkg/config"]' "仅测试变更应运行关键包哨兵"

fixture="$(new_fixture prod-and-tests)"
printf '\n// changed\n' >>"$fixture/pkg/config/config.go"
printf '\n// changed\n' >>"$fixture/pkg/config/config_test.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "changed-lines"' "生产与测试同时变更时应保留 changed-line"
assert_json "$fixture/plan.json" 'plan["mutation"]["canary_packages"] == ["./pkg/config"]' "生产与测试同时变更时不应跳过哨兵"

fixture="$(new_fixture module-change)"
printf '\n' >>"$fixture/go.mod"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none"' "依赖图变更不应触发全量变异"
assert_json "$fixture/plan.json" 'plan["go"]["build_all"] is True' "依赖图变更应触发全平台构建"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == ["./app", "./core", "./docker/test/mock-api", "./pkg/config"]' "依赖图变更未覆盖所有 Go 测试包"
assert_json "$fixture/plan.json" '"file_shards" not in plan["mutation"]' "规划结果仍包含全量文件分片"

fixture="$(new_fixture excluded-mock)"
printf '\n// changed\n' >>"$fixture/docker/test/mock-api/main.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none"' "测试桩不应被当作生产代码变异"

fixture="$(new_fixture forced-full)"
plan "$fixture" "$fixture/plan.json" --full
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == ["./app", "./core", "./docker/test/mock-api", "./pkg/config"]' "显式全量未覆盖所有 Go 测试包"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] != "full"' "显式全量不应升级 mutation"

echo "变更检查规划器测试通过"
