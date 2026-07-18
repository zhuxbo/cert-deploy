#!/usr/bin/env bash
# deploy-spec.md §12 的本仓确定性防漂移检查。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() { echo "防漂移检查失败: $*" >&2; exit 1; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }

EXPECTED_CLAUDE_SHA256="5d904a04b7b6ecb89a5b9254f9afcd12803cbe140d3f9af7bc3a6cf15d5de1fa"
EXPECTED_FINISH_COMMAND_SHA256="121bc2a3671b23555cb7e01074d2b5ac3463eb10a6287e00153e2f166d97c6ad"
EXPECTED_RELEASE_COMMAND_SHA256="f2e26d7329c5f1c31e80f4afb2df8e3086b042a91e1978b2e6be244c2bbfc760"

[[ "$(sha256_file CLAUDE.md)" == "$EXPECTED_CLAUDE_SHA256" ]] || fail "CLAUDE.md 不符合固定模板"
[[ "$(sha256_file .claude/commands/finish-check.md)" == "$EXPECTED_FINISH_COMMAND_SHA256" ]] || fail "finish-check 工具入口发生漂移"
[[ "$(sha256_file .claude/commands/remote-release.md)" == "$EXPECTED_RELEASE_COMMAND_SHA256" ]] || fail "remote-release 工具入口发生漂移"

[[ -f AGENTS.md && -f skills/SKILL.md ]] || fail "缺少 AGENTS.md 或根 Skill"
for phrase in "只记录长期有效" "只直接维护 \`AGENTS.md\`" "新增、删除或重命名 skill" "删除失效或重复内容"; do
    grep -Fq "$phrase" AGENTS.md || fail "AGENTS.md 缺少更新原则: $phrase"
done

if find skills -mindepth 1 -type d -print -quit | grep -q .; then
    fail "skills/ 中存在二级目录"
fi
while IFS= read -r leaf; do
    base="$(basename "$leaf")"
    [[ "$base" == "SKILL.md" || "$base" =~ ^[a-z0-9]+(-[a-z0-9]+)*\.md$ ]] || fail "叶子文件名不符合 kebab-case: $leaf"
done < <(find skills -maxdepth 1 -type f -name '*.md' | sort)

routes=()
while IFS= read -r route; do routes+=("$route"); done < <(grep -oE '`skills/[a-z0-9-]+\.md`' skills/SKILL.md | tr -d '`' | sort -u)
((${#routes[@]} >= 6)) || fail "skills/SKILL.md 路由不完整"
for route in "${routes[@]}"; do [[ -f "$route" ]] || fail "Skill 路由不存在: $route"; done

if rg -n 'skills/[a-z0-9-]+/SKILL\.md|skills/(go-dev|nginx-apache|deploy-ops|build-release)/' \
    --hidden -g '!.git/**' -g '!deploy-spec.md' -g '!build/check-agent-config.sh' . >/tmp/sslctl-old-skill-refs.$$; then
    cat /tmp/sslctl-old-skill-refs.$$ >&2
    rm -f /tmp/sslctl-old-skill-refs.$$
    fail "仍引用旧二级 Skill 路径"
fi
rm -f /tmp/sslctl-old-skill-refs.$$

grep -Fq 'bash build/check-agent-config.sh' .github/workflows/ci.yml || fail "CI 未执行智能体防漂移检查"
grep -Fq 'bash build/test-release.sh' .github/workflows/ci.yml || fail "CI 未执行发布行为回归检查"

for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
    grep -Fq "$name" skills/build-release.md || fail "构建 Skill 缺少正式资产: $name"
    grep -Fq "$name" build/release_helper.py || fail "发布 helper 缺少正式资产: $name"
done
grep -Fq 'resume-main)' build/release.sh || fail "缺少 main 恢复入口"
grep -Fq 'require_main_tag' build/release.sh || fail "main 恢复未绑定不可变 tag"
if grep -E 'resume-main\).*prepare_bundle' build/release.sh >/dev/null; then fail "main 恢复错误调用构建"; fi
grep -Fq '至少两个节点' build/release.sh || fail "发布脚本未拒绝单节点退化"
grep -Fq '候选 releases.json 不一致' build/release.sh || fail "缺少多节点候选索引一致性门禁"
grep -Fq 'main 版本已存在，不可覆盖' build/release_helper.py || fail "main 不可变门禁缺失"

echo "智能体配置与发布结构防漂移检查通过"
