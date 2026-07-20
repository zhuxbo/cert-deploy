#!/usr/bin/env bash
# sslctl 发布阶段执行器。Git/PR/GitHub Release 编排见 skills/remote-release.md。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$SCRIPT_DIR/release.conf"
HELPER="$SCRIPT_DIR/release_helper.py"
KEEP_VERSIONS=5
SSH_TIMEOUT=10
DRY_RUN=false
MODE=""
VERSION=""
BUNDLE=""
LOCKED_SERVERS=()
RELEASE_LOCK_TOKEN=""

log() { printf '[release] %s\n' "$*"; }
die() { printf '[release] 错误: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法: build/release.sh <version>
用法: build/release.sh [--dry-run] <mode> <version> [--bundle <absolute-path>]

简单入口：预发布版本自动执行 prepare、publish-dev；publish-dev 内含全节点验收。
稳定版本自动识别为 main，但必须按 skills/remote-release.md 完成正式发布流程。

mode:
  prepare       构建、签名并持久化唯一 bundle
  publish-dev   将现有 dev bundle 暂存、提升并全节点验收
  verify-dev    验收现有 dev bundle
  stage-main    将现有 main bundle 暂存到所有节点，不改公开索引
  promote-main  tag 存在后从 staging 提升 main 并全节点验收
  verify-main   验收现有 main bundle
  resume-main   tag 后仅用现有 bundle 幂等恢复，禁止构建
  abort-main    tag 前显式废弃未完成的 main prepare 状态和残留 bundle
  check-nodes   检查全部发布节点连通性

真实发布必须遵循 skills/remote-release.md；--dry-run 不联网、不构建、不修改 Git。
EOF
}

SIMPLE_VERSION=""
SIMPLE_DRY_RUN=false
if (($# == 1)) && [[ "$1" != -* ]]; then
    SIMPLE_VERSION="${1#v}"
elif (($# == 2)) && [[ "$1" == "--dry-run" && "$2" != -* ]]; then
    SIMPLE_DRY_RUN=true
    SIMPLE_VERSION="${2#v}"
fi

if [[ -n "$SIMPLE_VERSION" ]]; then
    if SIMPLE_CHANNEL="$(python3 "$HELPER" channel "$SIMPLE_VERSION" 2>/dev/null)"; then
        log "自动识别通道: $SIMPLE_CHANNEL (version=$SIMPLE_VERSION)"
        if [[ "$SIMPLE_CHANNEL" == "main" ]]; then
            die "稳定版本必须按 skills/remote-release.md 的正式发布流程执行，不能由服务器阶段脚本绕过 Git/PR/CI/tag/GitHub Release 门禁"
        fi
        if [[ "$SIMPLE_DRY_RUN" == true ]]; then
            log "将自动执行 prepare -> publish-dev（内含全节点验收）；不执行任何动作"
            exit 0
        fi

        SIMPLE_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/sslctl-dev-v${SIMPLE_VERSION}.XXXXXX")"
        SIMPLE_BUNDLE="$SIMPLE_PARENT/bundle"
        log "dev bundle: $SIMPLE_BUNDLE"
        if ! bash "$SCRIPT_DIR/release.sh" prepare "$SIMPLE_VERSION" --bundle "$SIMPLE_BUNDLE"; then
            die "dev bundle 构建失败；诊断后重新执行简单入口"
        fi
        if ! bash "$SCRIPT_DIR/release.sh" publish-dev "$SIMPLE_VERSION" --bundle "$SIMPLE_BUNDLE"; then
            die "dev 发布失败；bundle 已保留，可修复后用 publish-dev/verify-dev 续跑: $SIMPLE_BUNDLE"
        fi
        log "dev 发布完成: $SIMPLE_VERSION"
        exit 0
    fi
fi

while (($#)); do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --bundle) BUNDLE="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) die "未知选项: $1" ;;
        *)
            if [[ -z "$MODE" ]]; then MODE="$1"; elif [[ -z "$VERSION" ]]; then VERSION="${1#v}"; else die "多余参数: $1"; fi
            shift
            ;;
    esac
done

case "$MODE" in
    prepare|publish-dev|verify-dev|stage-main|promote-main|verify-main|resume-main|abort-main) ;;
    check-nodes) ;;
    "") usage; exit 2 ;;
    *) die "未知 mode: $MODE" ;;
esac

if [[ "$MODE" != "check-nodes" ]]; then
    [[ -n "$VERSION" ]] || die "必须指定版本"
    CHANNEL="$(python3 "$HELPER" channel "$VERSION")"
    [[ -n "$BUNDLE" ]] || die "必须通过 --bundle 指定持久 bundle 路径"
    [[ "$BUNDLE" == /* && "$BUNDLE" != "/" ]] || die "bundle 必须是非根绝对路径"
    case "$MODE" in
        publish-dev|verify-dev) [[ "$CHANNEL" == "dev" ]] || die "$MODE 只接受预发布 SemVer" ;;
        stage-main|promote-main|verify-main|resume-main|abort-main) [[ "$CHANNEL" == "main" ]] || die "$MODE 只接受稳定 SemVer" ;;
    esac
fi

if [[ "$DRY_RUN" == true ]]; then
    log "DRY-RUN mode=$MODE version=${VERSION:-n/a} channel=${CHANNEL:-n/a} bundle=${BUNDLE:-n/a}"
    case "$MODE" in
        prepare) log "将校验分支/工作区，构建一次三项资产，签名并写入 manifest；不执行任何动作" ;;
        publish-dev) log "将从现有 bundle 暂存全部节点，核对后原子推进 dev 索引；不执行任何动作" ;;
        stage-main) log "将只读现有 bundle 并暂存全部节点，正式目录与索引保持不变；不执行任何动作" ;;
        promote-main|resume-main) log "将校验不可变 tag 与 manifest commit，只读 bundle 并从 staging 恢复；不执行任何动作" ;;
        abort-main) log "将只在 tag 和正式目录不存在时显式废弃未完成 release-state 与残留 bundle；不执行任何动作" ;;
        verify-dev|verify-main) log "将验收全部节点及各节点公网域名；不执行任何动作" ;;
        check-nodes) log "将检查配置中的全部节点；不执行任何动作" ;;
    esac
    exit 0
fi

load_config() {
    [[ -f "$CONFIG_FILE" ]] || die "配置不存在: $CONFIG_FILE"
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    KEEP_VERSIONS=5
    declare -p SERVERS >/dev/null 2>&1 || die "SERVERS 未配置"
    ((${#SERVERS[@]} >= 2)) || die "本仓发布要求至少两个节点，禁止退化为单节点"
    [[ -n "${SSH_USER:-}" && -n "${SSH_KEY:-}" ]] || die "SSH_USER/SSH_KEY 未配置"
    [[ "$SSH_USER" =~ ^[0-9A-Za-z._-]+$ ]] || die "SSH_USER 格式无效"
    SSH_KEY="${SSH_KEY/#\~/${HOME}}"
    [[ -f "$SSH_KEY" ]] || die "SSH 密钥不存在: $SSH_KEY"
    if [[ -n "${SIGN_KEY:-}" && "$SIGN_KEY" != /* ]]; then SIGN_KEY="$PROJECT_ROOT/$SIGN_KEY"; fi
    names=""
    for server in "${SERVERS[@]}"; do
        IFS=',' read -r name host port directory <<<"$server"
        [[ -n "$name" && -n "$host" && -n "$directory" ]] || die "无效服务器配置: $server"
        [[ "$name" =~ ^[0-9A-Za-z._-]+$ && "$host" =~ ^[0-9A-Za-z.:-]+$ ]] || die "服务器名称或主机格式无效: $name"
        [[ "${port:-22}" =~ ^[0-9]+$ ]] || die "SSH 端口格式无效: $name"
        [[ "$directory" =~ ^/[0-9A-Za-z._/-]+$ && "$directory" != *".."* ]] || die "发布目录格式无效: $name"
        [[ ",$names," != *",$name,"* ]] || die "服务器名称重复: $name"
        names="${names:+$names,}$name"
    done
}

load_bundle_root() {
    [[ -n "${BUNDLE_ROOT:-}" && "$BUNDLE_ROOT" == /* && "$BUNDLE_ROOT" != "/" ]] || die "main 发布要求 BUNDLE_ROOT 为非根绝对路径"
    BUNDLE_ROOT="${BUNDLE_ROOT%/}"
    [[ "$BUNDLE_ROOT" != "$PROJECT_ROOT" && "$BUNDLE_ROOT" != "$PROJECT_ROOT/"* ]] || die "BUNDLE_ROOT 必须位于仓库外"
}

workspace_fingerprint() {
    python3 - "$PROJECT_ROOT" <<'PY'
import hashlib, os, stat, subprocess, sys
root = os.fsencode(os.path.abspath(sys.argv[1]))
paths = subprocess.check_output([
    "git", "-C", os.fsdecode(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"
]).split(b"\0")
digest = hashlib.sha256()
for relative in sorted(set(path for path in paths if path)):
    digest.update(relative + b"\0")
    path = os.path.join(root, relative)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        digest.update(b"missing\0")
        continue
    digest.update(oct(stat.S_IMODE(info.st_mode)).encode() + b"\0")
    if stat.S_ISLNK(info.st_mode):
        digest.update(b"link\0" + os.fsencode(os.readlink(path)) + b"\0")
    elif stat.S_ISREG(info.st_mode):
        digest.update(b"file\0")
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    else:
        digest.update(b"other\0")
print(digest.hexdigest())
PY
}

snapshot_worktree() {
    local output="$1"
    python3 - "$PROJECT_ROOT" "$output" <<'PY'
import hashlib, os, shutil, stat, subprocess, sys
root, output = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
paths = subprocess.check_output([
    "git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"
]).split(b"\0")
digest = hashlib.sha256()
for relative_bytes in sorted(set(path for path in paths if path)):
    relative = os.fsdecode(relative_bytes)
    source, destination = os.path.join(root, relative), os.path.join(output, relative)
    digest.update(relative_bytes + b"\0")
    try:
        info = os.lstat(source)
    except FileNotFoundError:
        digest.update(b"missing\0")
        continue
    digest.update(oct(stat.S_IMODE(info.st_mode)).encode() + b"\0")
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(source)
        digest.update(b"link\0" + os.fsencode(target) + b"\0")
        os.symlink(target, destination)
    elif stat.S_ISREG(info.st_mode):
        digest.update(b"file\0")
        with open(source, "rb") as source_file, open(destination, "wb") as destination_file:
            for block in iter(lambda: source_file.read(1024 * 1024), b""):
                digest.update(block)
                destination_file.write(block)
        shutil.copymode(source, destination, follow_symlinks=False)
    else:
        raise SystemExit(f"不支持的工作区文件类型: {relative}")
print(digest.hexdigest())
PY
}

canonical_main_bundle() {
    local commit="$1"
    printf '%s/main/v%s-%s\n' "$BUNDLE_ROOT" "$VERSION" "$commit"
}

validate_bundle_location() {
    local commit="$1" expected
    if [[ "$CHANNEL" == "main" ]]; then
        expected="$(canonical_main_bundle "$commit")"
        [[ "$BUNDLE" == "$expected" ]] || die "main bundle 路径必须唯一且固定为: $expected"
    fi
}

release_state_path() {
    local commit="$1"
    printf '%s/.release-state/main/v%s-%s.json\n' "$PROJECT_ROOT" "$VERSION" "$commit"
}

bundle_digest() {
    python3 - "$BUNDLE" <<'PY'
import hashlib, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
expected = {
    "manifest.json", "manifest.sig",
    "assets/sslctl-linux-amd64.gz", "assets/sslctl-linux-arm64.gz", "assets/sslctl-windows-amd64.exe.gz",
}
actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
if actual != expected:
    raise SystemExit("bundle 文件集合与持久状态契约不一致")
digest = hashlib.sha256()
for relative in sorted(actual):
    digest.update(relative.encode() + b"\0")
    with (root / relative).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
print("sha256:" + digest.hexdigest())
PY
}

verify_release_state() {
    local commit="$1" digest state
    [[ "$CHANNEL" == "main" ]] || return 0
    state="$(release_state_path "$commit")"
    digest="$(bundle_digest)"
    if [[ -f "$state" ]]; then
        python3 "$HELPER" state-verify --state "$state" --version "$VERSION" --source-commit "$commit" \
            --bundle "$BUNDLE" --bundle-digest "$digest"
    fi
    verify_remote_release_state "$commit" "$digest"
}

remote_release_state_command() {
    local operation="$1" commit="$2" digest="${3:-}" server state remote_bundle digest_args
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        state="$SERVER_DIR/.release-state/main/v$VERSION-$commit.json"
        remote_bundle="$SERVER_DIR/.release-state/bundles/v$VERSION-$commit"
        ssh_run "$SERVER_HOST" "$SERVER_PORT" "mkdir -p '$SERVER_DIR/.release-state/main' '$SERVER_DIR/.release-state/bundles'"
        if [[ "$operation" == "begin" ]]; then
            rsync_file "$HELPER" "$SERVER_HOST" "$SERVER_PORT" "$SERVER_DIR/.release-state/release_helper.py"
        fi
        digest_args=""
        [[ -n "$digest" ]] && digest_args="--bundle-digest '$digest'"
        ssh_run "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$SERVER_DIR/.release-state/release_helper.py' 'state-$operation' --state '$state' --version '$VERSION' --source-commit '$commit' --bundle '$remote_bundle' $digest_args"
    done
}

begin_remote_release_state() {
    remote_release_state_command begin "$1"
}

complete_remote_release_state() {
    remote_release_state_command complete "$1" "$2"
}

verify_remote_release_state() {
    remote_release_state_command verify "$1" "$2"
}

abort_remote_release_state() {
    remote_release_state_command abort "$1"
}

acquire_release_locks() {
    local server
    RELEASE_LOCK_TOKEN="sslctl-${CHANNEL}-${VERSION}-$$-$(date +%s)"
    LOCKED_SERVERS=()
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        if ! ssh_run "$SERVER_HOST" "$SERVER_PORT" \
            "mkdir '$SERVER_DIR/.release-lock' && printf '%s\\n' '$RELEASE_LOCK_TOKEN' >'$SERVER_DIR/.release-lock/owner'"; then
            release_release_locks
            die "$SERVER_NAME 发布锁已被占用；确认无发布进程后再人工处理陈旧锁"
        fi
        LOCKED_SERVERS+=("$server")
    done
}

release_release_locks() {
    local server owner
    if ((${#LOCKED_SERVERS[@]})); then
        for server in "${LOCKED_SERVERS[@]}"; do
            parse_server "$server"
            owner="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "cat '$SERVER_DIR/.release-lock/owner' 2>/dev/null" || true)"
            if [[ "$owner" == "$RELEASE_LOCK_TOKEN" ]]; then
                ssh_run "$SERVER_HOST" "$SERVER_PORT" "rm -f '$SERVER_DIR/.release-lock/owner' && rmdir '$SERVER_DIR/.release-lock'" || true
            fi
        done
    fi
    LOCKED_SERVERS=()
}

with_release_locks() {
    acquire_release_locks
    trap 'release_release_locks' EXIT
    trap 'release_release_locks; exit 130' INT TERM
    "$@"
    release_release_locks
    trap - EXIT INT TERM
}

parse_server() {
    IFS=',' read -r SERVER_NAME SERVER_HOST SERVER_PORT SERVER_DIR <<<"$1"
    SERVER_PORT="${SERVER_PORT:-22}"
}

server_public_url() {
    printf 'https://%s/sslctl\n' "$SERVER_HOST"
}

ssh_run() {
    local host="$1" port="$2"; shift 2
    ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o "ConnectTimeout=$SSH_TIMEOUT" \
        -p "$port" "$SSH_USER@$host" "$@"
}

rsync_file() {
    local source="$1" host="$2" port="$3" destination="$4"
    rsync -az -e "ssh -i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p $port" \
        "$source" "$SSH_USER@$host:$destination"
}

verify_local_bundle() {
    python3 "$HELPER" verify-manifest --bundle "$BUNDLE" --version "$VERSION" >/dev/null
    local signatures_file signature_key_id
    signatures_file="$(mktemp "${TMPDIR:-/tmp}/sslctl-signatures.XXXXXX")"
    signature_key_id="$(python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print(next(iter(m["assets"].values()))["signature"].split(":",2)[1])' "$BUNDLE/manifest.json")"
    python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); json.dump({k:v["signature"] for k,v in m["assets"].items()}, open(sys.argv[2], "w"))' \
        "$BUNDLE/manifest.json" "$signatures_file"
    if ! bash "$SCRIPT_DIR/sign-release.sh" --key-id "$signature_key_id" --assets-dir "$BUNDLE/assets" \
        --verify-signatures "$signatures_file" >/dev/null; then
        rm -f "$signatures_file"
        return 1
    fi
    rm -f "$signatures_file"
    [[ -f "$BUNDLE/manifest.sig" ]] || die "bundle 缺少 manifest.sig"
    bash "$SCRIPT_DIR/sign-release.sh" --key-id "$signature_key_id" --manifest "$BUNDLE/manifest.json" \
        --verify-manifest-signature "$BUNDLE/manifest.sig" >/dev/null
    verify_bundle_versions
}

verify_bundle_versions() {
    local name temp
    temp="$(mktemp "${TMPDIR:-/tmp}/sslctl-version.XXXXXX")"
    trap 'rm -f "$temp"' RETURN
    for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
        gzip -dc "$BUNDLE/assets/$name" >"$temp"
        strings "$temp" | grep -Fx "$VERSION" >/dev/null || die "产物未包含精确注入版本: $name"
    done
    rm -f "$temp"
    trap - RETURN
}

manifest_value() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])' "$BUNDLE/manifest.json" "$1"
}

prepare_bundle() {
    load_config
    [[ ! -e "$BUNDLE" ]] || die "bundle 路径已存在；禁止覆盖: $BUNDLE"
    [[ -n "${SIGN_KEY:-}" && -n "${SIGN_KEY_ID:-}" ]] || die "SIGN_KEY/SIGN_KEY_ID 未配置"
    [[ -f "$SIGN_KEY" ]] || die "签名私钥不存在: $SIGN_KEY"

    local source_commit dirty source_epoch created_at build_time go_version work_dir source_dir artifacts_dir snapshot_fingerprint signatures preflight_index before_fingerprint after_fingerprint current_commit current_branch toolchain state_file digest
    source_commit="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
    current_branch="$(git -C "$PROJECT_ROOT" branch --show-current)"
    dirty=false
    [[ -z "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=normal)" ]] || dirty=true
    before_fingerprint="$(workspace_fingerprint)"
    validate_bundle_location "$source_commit"

    if [[ "$CHANNEL" == "main" ]]; then
        [[ "$(git -C "$PROJECT_ROOT" branch --show-current)" == "main" ]] || die "main bundle 只能从 main 分支 prepare"
        [[ "$dirty" == false ]] || die "main bundle 要求干净工作区"
        [[ "$(git -C "$PROJECT_ROOT" rev-parse refs/remotes/origin/main)" == "$source_commit" ]] || die "本地 main 必须与 origin/main 一致"
        ! git -C "$PROJECT_ROOT" show-ref --verify --quiet "refs/tags/v$VERSION" || die "本地 tag 已存在: v$VERSION"
        [[ -z "$(git -C "$PROJECT_ROOT" ls-remote --tags origin "refs/tags/v$VERSION")" ]] || die "远端 tag 已存在: v$VERSION"
        for server in "${SERVERS[@]}"; do
            parse_server "$server"
            preflight_index="$(mktemp "${TMPDIR:-/tmp}/sslctl-main-index.XXXXXX")"
            curl --fail --silent --show-error --location "$(server_public_url)/releases.json" >"$preflight_index"
            python3 "$HELPER" check-new-main --index "$preflight_index" --version "$VERSION"
            rm -f "$preflight_index"
            ssh_run "$SERVER_HOST" "$SERVER_PORT" "test ! -e '$SERVER_DIR/main/v$VERSION'" || die "$SERVER_NAME 已存在正式版本 v$VERSION"
        done
        source_epoch="$(git -C "$PROJECT_ROOT" show -s --format=%ct "$source_commit")"
        state_file="$(release_state_path "$source_commit")"
        python3 "$HELPER" state-begin --state "$state_file" --version "$VERSION" --source-commit "$source_commit" --bundle "$BUNDLE"
        begin_remote_release_state "$source_commit"
    else
        source_epoch="$(date +%s)"
    fi

    mkdir -p "$BUNDLE/assets" "$BUNDLE/.work"
    work_dir="$BUNDLE/.work"
    source_dir="$work_dir/source"
    artifacts_dir="$work_dir/artifacts"
    snapshot_fingerprint="$(snapshot_worktree "$source_dir")"
    after_fingerprint="$(workspace_fingerprint)"
    if [[ "$snapshot_fingerprint" != "$before_fingerprint" || "$after_fingerprint" != "$before_fingerprint" ]]; then
        rm -rf -- "$BUNDLE"
        die "捕获构建源快照时工作区发生变化；已丢弃未发布 bundle"
    fi
    SOURCE_DATE_EPOCH="$source_epoch" SSLCTL_SOURCE_DIR="$source_dir" bash "$SCRIPT_DIR/build.sh" "$VERSION" "$artifacts_dir"
    for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
        cp "$artifacts_dir/$name" "$BUNDLE/assets/$name"
    done
    signatures="$BUNDLE/.signatures.json"
    bash "$SCRIPT_DIR/sign-release.sh" --key "$SIGN_KEY" --key-id "$SIGN_KEY_ID" --assets-dir "$BUNDLE/assets" --output "$signatures"
    created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    build_time="$(python3 -c 'import datetime,sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$source_epoch")"
    toolchain="$(awk '$1 == "toolchain" { print $2; exit }' "$source_dir/go.mod")"
    go_version="$(GOTOOLCHAIN="$toolchain" go version)"
    python3 "$HELPER" create-manifest --version "$VERSION" --assets-dir "$BUNDLE/assets" --signatures "$signatures" \
        --output "$BUNDLE/manifest.json" --source-commit "$source_commit" --dirty "$dirty" \
        --created-at "$created_at" --build-time "$build_time" --go-version "$go_version"
    bash "$SCRIPT_DIR/sign-release.sh" --key "$SIGN_KEY" --key-id "$SIGN_KEY_ID" --manifest "$BUNDLE/manifest.json" \
        --output "$BUNDLE/manifest.sig" >/dev/null
    current_commit="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
    after_fingerprint="$(workspace_fingerprint)"
    if [[ "$current_commit" != "$source_commit" || "$(git -C "$PROJECT_ROOT" branch --show-current)" != "$current_branch" || "$after_fingerprint" != "$before_fingerprint" ]]; then
        rm -rf -- "$BUNDLE"
        die "构建期间分支、HEAD 或工作区快照发生变化；已丢弃未发布 bundle"
    fi
    rm -rf "$work_dir"
    rm -f "$signatures"
    verify_local_bundle
    if [[ "$CHANNEL" == "main" ]]; then
        digest="$(bundle_digest)"
        python3 "$HELPER" state-complete --state "$state_file" --version "$VERSION" --source-commit "$source_commit" \
            --bundle "$BUNDLE" --bundle-digest "$digest"
        complete_remote_release_state "$source_commit" "$digest"
    fi
    log "bundle 已生成并校验: $BUNDLE"
}

abort_main_bundle() {
    local state_dir state_file commit recorded_bundle
    state_dir="$PROJECT_ROOT/.release-state/main"
    if [[ -f "$BUNDLE/manifest.json" ]]; then
        commit="$(manifest_value source_commit)"
        state_file="$(release_state_path "$commit")"
    else
        state_file="$(find "$state_dir" -maxdepth 1 -type f -name "v$VERSION-*.json" -print 2>/dev/null || true)"
        [[ -n "$state_file" && "$state_file" != *$'\n'* ]] || die "无 manifest 时，本地必须且只能存在一份该版本的 release-state"
        commit="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_commit"])' "$state_file")"
    fi
    if [[ -f "$state_file" ]]; then
        recorded_bundle="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bundle"])' "$state_file")"
        [[ "$recorded_bundle" == "$BUNDLE" ]] || die "abort-main 必须传入 release-state 记录的原 bundle: $recorded_bundle"
    fi
    ! git -C "$PROJECT_ROOT" show-ref --verify --quiet "refs/tags/v$VERSION" || die "本地版本 tag 已存在，禁止废弃"
    [[ -z "$(git -C "$PROJECT_ROOT" ls-remote --tags origin "refs/tags/v$VERSION")" ]] || die "远端版本 tag 已存在，禁止废弃"
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        ssh_run "$SERVER_HOST" "$SERVER_PORT" "test ! -e '$SERVER_DIR/main/v$VERSION'" || die "$SERVER_NAME 已存在正式版本，禁止废弃"
    done
    abort_remote_release_state "$commit"
    if [[ -f "$state_file" ]]; then
        python3 "$HELPER" state-abort --state "$state_file" --version "$VERSION" --source-commit "$commit" --bundle "$BUNDLE"
    fi
    if [[ -e "$BUNDLE" ]]; then rm -rf -- "$BUNDLE"; fi
    log "未完成 main bundle 已显式废弃，release-state 保留审计记录"
}

stage_server() {
    local server="$1" commit stage expected_manifest_sig actual_manifest_sig
    parse_server "$server"
    commit="$(manifest_value source_commit)"
    stage="$SERVER_DIR/.staging/sslctl/v$VERSION-$commit"
    log "暂存节点 $SERVER_NAME"
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "mkdir -p '$stage/assets'"
    rsync_file "$BUNDLE/manifest.json" "$SERVER_HOST" "$SERVER_PORT" "$stage/manifest.json"
    rsync_file "$BUNDLE/manifest.sig" "$SERVER_HOST" "$SERVER_PORT" "$stage/manifest.sig"
    rsync_file "$HELPER" "$SERVER_HOST" "$SERVER_PORT" "$stage/release_helper.py"
    for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
        rsync_file "$BUNDLE/assets/$name" "$SERVER_HOST" "$SERVER_PORT" "$stage/assets/$name"
    done
    ssh_run "$SERVER_HOST" "$SERVER_PORT" \
        "python3 '$stage/release_helper.py' verify-manifest --bundle '$stage' --version '$VERSION' >/dev/null"
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "STAGE='$stage' VERSION='$VERSION' sh -eu -c '
arch=\$(uname -m)
case \"\$arch\" in
  x86_64|amd64) asset=sslctl-linux-amd64.gz ;;
  aarch64|arm64) asset=sslctl-linux-arm64.gz ;;
  *) echo \"不支持在发布节点验证的架构: \$arch\" >&2; exit 1 ;;
esac
temp=\$(mktemp)
trap \"rm -f \\\"\$temp\\\"\" EXIT
gzip -dc \"\$STAGE/assets/\$asset\" >\"\$temp\"
chmod 700 \"\$temp\"
\"\$temp\" --version | grep -F \"\$VERSION\" >/dev/null
'"
    expected_manifest_sig="$(shasum -a 256 "$BUNDLE/manifest.sig" | awk '{print $1}')"
    actual_manifest_sig="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "sha256sum '$stage/manifest.sig' | cut -d' ' -f1")"
    [[ "$actual_manifest_sig" == "$expected_manifest_sig" ]] || die "$SERVER_NAME manifest.sig 传输后不一致"
    if [[ "$CHANNEL" == "main" ]]; then
        if ssh_run "$SERVER_HOST" "$SERVER_PORT" "test -e '$SERVER_DIR/main/v$VERSION'"; then
            [[ "$MODE" == "resume-main" ]] || die "$SERVER_NAME 已存在正式版本 v$VERSION"
            verify_remote_asset_set "$SERVER_DIR/main/v$VERSION"
            for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
                expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assets"][sys.argv[2]]["sha256"].removeprefix("sha256:"))' "$BUNDLE/manifest.json" "$name")"
                actual="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "sha256sum '$SERVER_DIR/main/v$VERSION/$name' | cut -d' ' -f1")"
                [[ "$actual" == "$expected" ]] || die "$SERVER_NAME 已有正式资产与 bundle 不一致: $name"
            done
        fi
    fi
    local allow_existing=""
    [[ "$MODE" == "resume-main" ]] && allow_existing="--allow-existing-main"
    ssh_run "$SERVER_HOST" "$SERVER_PORT" \
        "python3 '$stage/release_helper.py' update-index --index '$SERVER_DIR/releases.json' --bundle '$stage' --version '$VERSION' --output '$stage/releases.json' $allow_existing"
    ssh_run "$SERVER_HOST" "$SERVER_PORT" \
        "python3 '$stage/release_helper.py' verify-index --index '$stage/releases.json' --bundle '$stage' --version '$VERSION'"
    STAGED_INDEX_SHA="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "python3 '$stage/release_helper.py' index-safety-digest --index '$stage/releases.json'")"
}

stage_all() {
    local candidate_sha=""
    verify_local_bundle
    if [[ "$CHANNEL" == "main" ]]; then
        local commit digest
        commit="$(manifest_value source_commit)"
        digest="$(bundle_digest)"
        complete_remote_release_state "$commit" "$digest"
        verify_release_state "$commit"
    fi

    for server in "${SERVERS[@]}"; do
        stage_server "$server"
        if [[ -z "$candidate_sha" ]]; then candidate_sha="$STAGED_INDEX_SHA"; fi
        [[ "$STAGED_INDEX_SHA" == "$candidate_sha" ]] || die "各节点候选 releases.json 不一致，禁止推进"
    done
    log "全部节点 staging 与候选索引校验完成"
}

promote_server() {
    local server="$1" commit stage destination temp old
    parse_server "$server"
    commit="$(manifest_value source_commit)"
    stage="$SERVER_DIR/.staging/sslctl/v$VERSION-$commit"
    destination="$SERVER_DIR/$CHANNEL/v$VERSION"
    temp="$SERVER_DIR/$CHANNEL/.v$VERSION.new-$commit"
    old="$SERVER_DIR/$CHANNEL/.v$VERSION.old-$commit"
    log "提升节点 $SERVER_NAME"
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "STAGE='$stage' DEST='$destination' TEMP='$temp' OLD='$old' CHANNEL='$CHANNEL' python3 - <<'PY'
import os, shutil
stage, dest, temp, old, channel = (os.environ[k] for k in ('STAGE','DEST','TEMP','OLD','CHANNEL'))
if os.path.lexists(temp): shutil.rmtree(temp)
os.makedirs(os.path.dirname(dest), exist_ok=True)
shutil.copytree(os.path.join(stage, 'assets'), temp)
if channel == 'main' and os.path.lexists(dest):
    shutil.rmtree(temp)
elif channel == 'dev' and os.path.lexists(dest):
    if os.path.lexists(old): shutil.rmtree(old)
    os.replace(dest, old)
if os.path.lexists(temp): os.replace(temp, dest)
if os.path.lexists(old): shutil.rmtree(old)
os.replace(os.path.join(stage, 'releases.json'), os.path.join(os.path.dirname(os.path.dirname(dest)), 'releases.json'))
PY"
    rsync_file "$PROJECT_ROOT/deploy/install.sh" "$SERVER_HOST" "$SERVER_PORT" "$SERVER_DIR/install.sh"
    rsync_file "$PROJECT_ROOT/deploy/install.ps1" "$SERVER_HOST" "$SERVER_PORT" "$SERVER_DIR/install.ps1"
}

verify_remote_asset_set() {
    local directory="$1" actual expected
    expected=$'sslctl-linux-amd64.gz\nsslctl-linux-arm64.gz\nsslctl-windows-amd64.exe.gz'
    actual="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "find '$directory' -maxdepth 1 -type f -printf '%f\\n' | sort")"
    [[ "$actual" == "$expected" ]] || die "$SERVER_NAME 正式资产集合不精确: $directory"
}

verify_server() {
    local server="$1" commit stage local_index
    parse_server "$server"
    commit="$(manifest_value source_commit)"
    stage="$SERVER_DIR/.staging/sslctl/v$VERSION-$commit"
    local_index="$(mktemp "${TMPDIR:-/tmp}/sslctl-index.XXXXXX")"
    trap 'rm -f "$local_index"' RETURN
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "cat '$SERVER_DIR/releases.json'" >"$local_index"
    python3 "$HELPER" verify-index --index "$local_index" --bundle "$BUNDLE" --version "$VERSION"
    verify_remote_asset_set "$SERVER_DIR/$CHANNEL/v$VERSION"
    for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
        expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assets"][sys.argv[2]]["sha256"].removeprefix("sha256:"))' "$BUNDLE/manifest.json" "$name")"
        actual="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "sha256sum '$SERVER_DIR/$CHANNEL/v$VERSION/$name' | cut -d' ' -f1")"
        [[ "$actual" == "$expected" ]] || die "$SERVER_NAME 资产哈希不一致: $name"
    done
    rm -f "$local_index"
    trap - RETURN
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "test -f '$stage/manifest.json' && test -f '$stage/manifest.sig'" >/dev/null
    log "节点验收通过: $SERVER_NAME"
}

verify_public_server() {
    local server="$1" public_url temp_index temp_asset expected actual
    parse_server "$server"
    public_url="$(server_public_url)"
    temp_index="$(mktemp "${TMPDIR:-/tmp}/sslctl-public.XXXXXX")"
    temp_asset="$(mktemp "${TMPDIR:-/tmp}/sslctl-public-asset.XXXXXX")"
    trap 'rm -f "$temp_index" "$temp_asset"' RETURN
    curl --fail --silent --show-error --location "$public_url/releases.json" >"$temp_index"
    python3 "$HELPER" verify-index --index "$temp_index" --bundle "$BUNDLE" --version "$VERSION"
    curl --fail --silent --show-error --location \
        "$public_url/$CHANNEL/v$VERSION/sslctl-linux-amd64.gz" >"$temp_asset"
    expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assets"]["sslctl-linux-amd64.gz"]["sha256"].removeprefix("sha256:"))' "$BUNDLE/manifest.json")"
    actual="$(shasum -a 256 "$temp_asset" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || die "$SERVER_NAME 公网代表资产 SHA256 不一致"
    rm -f "$temp_index" "$temp_asset"
    trap - RETURN
    log "节点公网验收通过: $SERVER_NAME ($public_url)"
}

verify_all() {
    verify_local_bundle
    for server in "${SERVERS[@]}"; do verify_server "$server"; done
    for server in "${SERVERS[@]}"; do verify_public_server "$server"; done
}

cleanup_server() {
    local server="$1"
    parse_server "$server"
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "ROOT='$SERVER_DIR' CHANNEL='$CHANNEL' KEEP='$KEEP_VERSIONS' python3 - <<'PY'
import json, os, shutil
root, channel, keep = os.environ['ROOT'], os.environ['CHANNEL'], int(os.environ['KEEP'])
with open(os.path.join(root, 'releases.json'), encoding='utf-8') as handle:
    index = json.load(handle)
versions = index.get(channel, {}).get('versions', [])[:keep]
allowed = {'v' + item['version'] for item in versions}
channel_dir = os.path.join(root, channel)
if os.path.isdir(channel_dir):
    for name in os.listdir(channel_dir):
        path = os.path.join(channel_dir, name)
        if name.startswith('v') and name not in allowed and os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
PY"
}

promote_all() {
    for server in "${SERVERS[@]}"; do promote_server "$server"; done
    verify_all
    for server in "${SERVERS[@]}"; do cleanup_server "$server"; done
}

stage_all_and_promote() {
    # promote 前在全节点锁内重新基于最新公开索引生成候选，避免覆盖另一通道的新条目。
    stage_all
    promote_all
}

require_main_tag() {
    local commit local_tag remote_tag
    commit="$(manifest_value source_commit)"
    local_tag="$(git -C "$PROJECT_ROOT" rev-parse "refs/tags/v$VERSION^{commit}" 2>/dev/null || true)"
    remote_tag="$(git -C "$PROJECT_ROOT" ls-remote origin "refs/tags/v$VERSION" "refs/tags/v$VERSION^{}" | awk '/\^\{\}$/ {peeled=$1} !/\^\{\}$/ {direct=$1} END {print peeled ? peeled : direct}')"
    [[ "$local_tag" == "$commit" && "$remote_tag" == "$commit" ]] || die "v$VERSION 必须在本地和 origin 不可变地指向 manifest commit"
}

check_nodes() {
    load_config
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        ssh_run "$SERVER_HOST" "$SERVER_PORT" "python3 --version >/dev/null && test -d '$SERVER_DIR'"
        log "节点可用: $SERVER_NAME"
    done
}

case "$MODE" in
    prepare) if [[ "$CHANNEL" == "main" ]]; then load_config; load_bundle_root; with_release_locks prepare_bundle; else prepare_bundle; fi ;;
    abort-main) load_config; load_bundle_root; with_release_locks abort_main_bundle ;;
    check-nodes) check_nodes ;;
    publish-dev) load_config; with_release_locks stage_all_and_promote ;;
    verify-dev) load_config; verify_all ;;
    stage-main) load_config; load_bundle_root; validate_bundle_location "$(manifest_value source_commit)"; with_release_locks stage_all ;;
    promote-main) load_config; load_bundle_root; validate_bundle_location "$(manifest_value source_commit)"; verify_local_bundle; require_main_tag; with_release_locks stage_all_and_promote ;;
    verify-main) load_config; load_bundle_root; validate_bundle_location "$(manifest_value source_commit)"; verify_release_state "$(manifest_value source_commit)"; verify_all ;;
    resume-main) load_config; load_bundle_root; validate_bundle_location "$(manifest_value source_commit)"; verify_local_bundle; require_main_tag; with_release_locks stage_all_and_promote ;;
esac
