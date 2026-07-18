#!/usr/bin/env bash
# 发布 helper/阶段门禁的离线回归测试；不联网、不改 Git 引用。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
HELPER="$SCRIPT_DIR/release_helper.py"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sslctl-release-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT

assets="$TEST_DIR/assets"
mkdir -p "$assets"
printf 'linux-amd64\n' >"$assets/sslctl-linux-amd64.gz"
printf 'linux-arm64\n' >"$assets/sslctl-linux-arm64.gz"
printf 'windows-amd64\n' >"$assets/sslctl-windows-amd64.exe.gz"

key_dir="$TEST_DIR/keys"
bash "$SCRIPT_DIR/generate-keys.sh" "$key_dir" test-key >/dev/null
key="$key_dir/release-key.pem"
[[ "$(stat -f '%Lp' "$key" 2>/dev/null || stat -c '%a' "$key")" == "600" ]]
signatures="$TEST_DIR/signatures.json"
bash "$SCRIPT_DIR/sign-release.sh" --key "$key" --key-id test-key --trusted-public-key "$key_dir/release-key.pub" \
    --assets-dir "$assets" --output "$signatures" >/dev/null
bash "$SCRIPT_DIR/sign-release.sh" --key-id test-key --trusted-public-key "$key_dir/release-key.pub" \
    --assets-dir "$assets" --verify-signatures "$signatures" >/dev/null
if bash "$SCRIPT_DIR/sign-release.sh" --key "$key" --key-id test-key --assets-dir "$assets" --output "$TEST_DIR/untrusted.json" >/dev/null 2>&1; then
    echo "客户端未信任的签名 key ID 未被拒绝" >&2
    exit 1
fi
if bash "$SCRIPT_DIR/sign-release.sh" --key "$key" --key-id key-1 --assets-dir "$assets" --output "$TEST_DIR/mismatched.json" >/dev/null 2>&1; then
    echo "与客户端内置公钥不匹配的私钥未被拒绝" >&2
    exit 1
fi

commit="$(git -C "$ROOT" rev-parse HEAD)"
dev_bundle="$TEST_DIR/dev-bundle"
mkdir -p "$dev_bundle"
cp -R "$assets" "$dev_bundle/assets"
python3 "$HELPER" create-manifest --version 1.2.3-rc.1 --assets-dir "$dev_bundle/assets" \
    --signatures "$signatures" --output "$dev_bundle/manifest.json" --source-commit "$commit" --dirty true \
    --created-at 2026-07-19T00:00:00Z --build-time 2026-07-19T00:00:00Z --go-version test
python3 "$HELPER" verify-manifest --bundle "$dev_bundle" --version 1.2.3-rc.1 >/dev/null
python3 "$HELPER" update-index --index "$TEST_DIR/missing.json" --bundle "$dev_bundle" --version 1.2.3-rc.1 --output "$TEST_DIR/dev-index.json"
python3 "$HELPER" verify-index --index "$TEST_DIR/dev-index.json" --bundle "$dev_bundle" --version 1.2.3-rc.1
python3 "$HELPER" update-index --index "$TEST_DIR/dev-index.json" --bundle "$dev_bundle" --version 1.2.3-rc.1 --output "$TEST_DIR/dev-index-2.json"

main_bundle="$TEST_DIR/main-bundle"
mkdir -p "$main_bundle"
cp -R "$assets" "$main_bundle/assets"
python3 "$HELPER" create-manifest --version 1.2.3 --assets-dir "$main_bundle/assets" \
    --signatures "$signatures" --output "$main_bundle/manifest.json" --source-commit "$commit" --dirty false \
    --created-at 2026-07-19T00:00:00Z --build-time 2026-07-19T00:00:00Z --go-version test
python3 "$HELPER" update-index --index "$TEST_DIR/dev-index.json" --bundle "$main_bundle" --version 1.2.3 --output "$TEST_DIR/main-index.json"
python3 "$HELPER" verify-index --index "$TEST_DIR/main-index.json" --bundle "$main_bundle" --version 1.2.3
if python3 "$HELPER" check-new-main --index "$TEST_DIR/main-index.json" --version 1.2.3 >/dev/null 2>&1; then
    echo "main preflight 未拒绝已存在版本" >&2
    exit 1
fi
python3 "$HELPER" check-new-main --index "$TEST_DIR/main-index.json" --version 1.2.4
if python3 "$HELPER" update-index --index "$TEST_DIR/main-index.json" --bundle "$main_bundle" --version 1.2.3 --output "$TEST_DIR/forbidden.json" 2>/dev/null; then
    echo "main 同版本覆盖未被拒绝" >&2
    exit 1
fi

cp "$TEST_DIR/main-index.json" "$TEST_DIR/resume-index.json"
python3 "$HELPER" update-index --allow-existing-main --index "$TEST_DIR/resume-index.json" --bundle "$main_bundle" --version 1.2.3 --output "$TEST_DIR/resumed.json"
cmp "$TEST_DIR/resume-index.json" "$TEST_DIR/resumed.json"

if python3 "$HELPER" channel 01.2.3 >/dev/null 2>&1; then
    echo "非法 SemVer 未被拒绝" >&2
    exit 1
fi
if python3 "$HELPER" create-manifest --version 2.0.0 --assets-dir "$assets" \
    --signatures "$signatures" --output "$TEST_DIR/dirty-main.json" --source-commit "$commit" --dirty true \
    --created-at 2026-07-19T00:00:00Z --build-time 2026-07-19T00:00:00Z --go-version test 2>/dev/null; then
    echo "main dirty bundle 未被拒绝" >&2
    exit 1
fi
extra_bundle="$TEST_DIR/extra-bundle"
cp -R "$main_bundle" "$extra_bundle"
printf 'extra\n' >"$extra_bundle/assets/unexpected.gz"
if python3 "$HELPER" verify-manifest --bundle "$extra_bundle" >/dev/null 2>&1; then
    echo "额外正式资产未被拒绝" >&2
    exit 1
fi
printf 'tamper' >>"$dev_bundle/assets/sslctl-linux-amd64.gz"
if python3 "$HELPER" verify-manifest --bundle "$dev_bundle" >/dev/null 2>&1; then
    echo "bundle 篡改未被拒绝" >&2
    exit 1
fi

dry_output="$(bash "$SCRIPT_DIR/release.sh" --dry-run resume-main 1.2.3 --bundle "$main_bundle")"
grep -Fq '只读 bundle' <<<"$dry_output"
grep -Fq '不执行任何动作' <<<"$dry_output"

echo "发布离线回归测试通过"
