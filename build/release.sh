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

log() { printf '[release] %s\n' "$*"; }
die() { printf '[release] 错误: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法: build/release.sh [--dry-run] <mode> <version> [--bundle <absolute-path>]

mode:
  prepare       构建、签名并持久化唯一 bundle
  publish-dev   将现有 dev bundle 暂存、提升并全节点验收
  verify-dev    验收现有 dev bundle
  stage-main    将现有 main bundle 暂存到所有节点，不改公开索引
  promote-main  tag 存在后从 staging 提升 main 并全节点验收
  verify-main   验收现有 main bundle
  resume-main   tag 后仅用现有 bundle 幂等恢复，禁止构建
  check-nodes   检查全部发布节点连通性

真实发布必须遵循 skills/remote-release.md；--dry-run 不联网、不构建、不修改 Git。
EOF
}

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
    prepare|publish-dev|verify-dev|stage-main|promote-main|verify-main|resume-main) ;;
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
        stage-main|promote-main|verify-main|resume-main) [[ "$CHANNEL" == "main" ]] || die "$MODE 只接受稳定 SemVer" ;;
    esac
fi

if [[ "$DRY_RUN" == true ]]; then
    log "DRY-RUN mode=$MODE version=${VERSION:-n/a} channel=${CHANNEL:-n/a} bundle=${BUNDLE:-n/a}"
    case "$MODE" in
        prepare) log "将校验分支/工作区，构建一次三项资产，签名并写入 manifest；不执行任何动作" ;;
        publish-dev) log "将从现有 bundle 暂存全部节点，核对后原子推进 dev 索引；不执行任何动作" ;;
        stage-main) log "将只读现有 bundle 并暂存全部节点，正式目录与索引保持不变；不执行任何动作" ;;
        promote-main|resume-main) log "将校验不可变 tag 与 manifest commit，只读 bundle 并从 staging 恢复；不执行任何动作" ;;
        verify-dev|verify-main) log "将验收全部节点和统一公网入口；不执行任何动作" ;;
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
    [[ -n "${PUBLIC_RELEASE_URL:-}" ]] || die "PUBLIC_RELEASE_URL 未配置"
    [[ "$PUBLIC_RELEASE_URL" == https://* ]] || die "PUBLIC_RELEASE_URL 必须使用 HTTPS"
    PUBLIC_RELEASE_URL="${PUBLIC_RELEASE_URL%/}"
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

parse_server() {
    IFS=',' read -r SERVER_NAME SERVER_HOST SERVER_PORT SERVER_DIR <<<"$1"
    SERVER_PORT="${SERVER_PORT:-22}"
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
}

manifest_value() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])' "$BUNDLE/manifest.json" "$1"
}

prepare_bundle() {
    load_config
    [[ ! -e "$BUNDLE" ]] || die "bundle 路径已存在；禁止覆盖: $BUNDLE"
    [[ -n "${SIGN_KEY:-}" && -n "${SIGN_KEY_ID:-}" ]] || die "SIGN_KEY/SIGN_KEY_ID 未配置"
    [[ -f "$SIGN_KEY" ]] || die "签名私钥不存在: $SIGN_KEY"

    local source_commit dirty source_epoch created_at build_time go_version work_dir signatures preflight_index
    source_commit="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
    dirty=false
    [[ -z "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=normal)" ]] || dirty=true

    if [[ "$CHANNEL" == "main" ]]; then
        [[ "$(git -C "$PROJECT_ROOT" branch --show-current)" == "main" ]] || die "main bundle 只能从 main 分支 prepare"
        [[ "$dirty" == false ]] || die "main bundle 要求干净工作区"
        [[ "$(git -C "$PROJECT_ROOT" rev-parse refs/remotes/origin/main)" == "$source_commit" ]] || die "本地 main 必须与 origin/main 一致"
        ! git -C "$PROJECT_ROOT" show-ref --verify --quiet "refs/tags/v$VERSION" || die "本地 tag 已存在: v$VERSION"
        [[ -z "$(git -C "$PROJECT_ROOT" ls-remote --tags origin "refs/tags/v$VERSION")" ]] || die "远端 tag 已存在: v$VERSION"
        preflight_index="$(mktemp "${TMPDIR:-/tmp}/sslctl-main-index.XXXXXX")"
        curl --fail --silent --show-error --location "$PUBLIC_RELEASE_URL/releases.json" >"$preflight_index"
        python3 "$HELPER" check-new-main --index "$preflight_index" --version "$VERSION"
        rm -f "$preflight_index"
        for server in "${SERVERS[@]}"; do
            parse_server "$server"
            ssh_run "$SERVER_HOST" "$SERVER_PORT" "test ! -e '$SERVER_DIR/main/v$VERSION'" || die "$SERVER_NAME 已存在正式版本 v$VERSION"
        done
        source_epoch="$(git -C "$PROJECT_ROOT" show -s --format=%ct "$source_commit")"
    else
        source_epoch="$(date +%s)"
    fi

    mkdir -p "$BUNDLE/assets" "$BUNDLE/.work"
    work_dir="$BUNDLE/.work"
    SOURCE_DATE_EPOCH="$source_epoch" bash "$SCRIPT_DIR/build.sh" "$VERSION" "$work_dir"
    for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
        cp "$work_dir/$name" "$BUNDLE/assets/$name"
    done
    signatures="$BUNDLE/.signatures.json"
    bash "$SCRIPT_DIR/sign-release.sh" --key "$SIGN_KEY" --key-id "$SIGN_KEY_ID" --assets-dir "$BUNDLE/assets" --output "$signatures"
    created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    build_time="$(python3 -c 'import datetime,sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$source_epoch")"
    go_version="$(go version)"
    python3 "$HELPER" create-manifest --version "$VERSION" --assets-dir "$BUNDLE/assets" --signatures "$signatures" \
        --output "$BUNDLE/manifest.json" --source-commit "$source_commit" --dirty "$dirty" \
        --created-at "$created_at" --build-time "$build_time" --go-version "$go_version"
    rm -rf "$work_dir"
    rm -f "$signatures"
    verify_local_bundle
    log "bundle 已生成并校验: $BUNDLE"
}

stage_server() {
    local server="$1" commit stage
    parse_server "$server"
    commit="$(manifest_value source_commit)"
    stage="$SERVER_DIR/.staging/sslctl/v$VERSION-$commit"
    log "暂存节点 $SERVER_NAME"
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "mkdir -p '$stage/assets'"
    rsync_file "$BUNDLE/manifest.json" "$SERVER_HOST" "$SERVER_PORT" "$stage/manifest.json"
    rsync_file "$HELPER" "$SERVER_HOST" "$SERVER_PORT" "$stage/release_helper.py"
    for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
        rsync_file "$BUNDLE/assets/$name" "$SERVER_HOST" "$SERVER_PORT" "$stage/assets/$name"
    done
    ssh_run "$SERVER_HOST" "$SERVER_PORT" \
        "python3 '$stage/release_helper.py' verify-manifest --bundle '$stage' --version '$VERSION' >/dev/null"
    if [[ "$CHANNEL" == "main" ]]; then
        if ssh_run "$SERVER_HOST" "$SERVER_PORT" "test -e '$SERVER_DIR/main/v$VERSION'"; then
            [[ "$MODE" == "resume-main" ]] || die "$SERVER_NAME 已存在正式版本 v$VERSION"
            for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
                expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assets"][sys.argv[2]]["sha256"].removeprefix("sha256:"))' "$BUNDLE/manifest.json" "$name")"
                actual="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "sha256sum '$SERVER_DIR/main/v$VERSION/$name' | cut -d' ' -f1")"
                [[ "$actual" == "$expected" ]] || die "$SERVER_NAME 已有正式资产与 bundle 不一致: $name"
            done
        fi
    fi
    local -a allow_existing=()
    [[ "$MODE" == "resume-main" ]] && allow_existing+=(--allow-existing-main)
    ssh_run "$SERVER_HOST" "$SERVER_PORT" \
        "python3 '$stage/release_helper.py' update-index --index '$SERVER_DIR/releases.json' --bundle '$stage' --version '$VERSION' --output '$stage/releases.json' ${allow_existing[*]}"
    ssh_run "$SERVER_HOST" "$SERVER_PORT" \
        "python3 '$stage/release_helper.py' verify-index --index '$stage/releases.json' --bundle '$stage' --version '$VERSION'"
    STAGED_INDEX_SHA="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "sha256sum '$stage/releases.json' | cut -d' ' -f1")"
}

stage_all() {
    local candidate_sha=""
    verify_local_bundle
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

verify_server() {
    local server="$1" commit stage local_index
    parse_server "$server"
    commit="$(manifest_value source_commit)"
    stage="$SERVER_DIR/.staging/sslctl/v$VERSION-$commit"
    local_index="$(mktemp "${TMPDIR:-/tmp}/sslctl-index.XXXXXX")"
    trap 'rm -f "$local_index"' RETURN
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "cat '$SERVER_DIR/releases.json'" >"$local_index"
    python3 "$HELPER" verify-index --index "$local_index" --bundle "$BUNDLE" --version "$VERSION"
    for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
        expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assets"][sys.argv[2]]["sha256"].removeprefix("sha256:"))' "$BUNDLE/manifest.json" "$name")"
        actual="$(ssh_run "$SERVER_HOST" "$SERVER_PORT" "sha256sum '$SERVER_DIR/$CHANNEL/v$VERSION/$name' | cut -d' ' -f1")"
        [[ "$actual" == "$expected" ]] || die "$SERVER_NAME 资产哈希不一致: $name"
    done
    rm -f "$local_index"
    trap - RETURN
    ssh_run "$SERVER_HOST" "$SERVER_PORT" "test -f '$stage/manifest.json'" >/dev/null
    log "节点验收通过: $SERVER_NAME"
}

verify_public() {
    local temp_index temp_asset expected actual
    temp_index="$(mktemp "${TMPDIR:-/tmp}/sslctl-public.XXXXXX")"
    temp_asset="$(mktemp "${TMPDIR:-/tmp}/sslctl-public-asset.XXXXXX")"
    trap 'rm -f "$temp_index" "$temp_asset"' RETURN
    curl --fail --silent --show-error --location "$PUBLIC_RELEASE_URL/releases.json" >"$temp_index"
    python3 "$HELPER" verify-index --index "$temp_index" --bundle "$BUNDLE" --version "$VERSION"
    curl --fail --silent --show-error --location \
        "$PUBLIC_RELEASE_URL/$CHANNEL/v$VERSION/sslctl-linux-amd64.gz" >"$temp_asset"
    expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assets"]["sslctl-linux-amd64.gz"]["sha256"].removeprefix("sha256:"))' "$BUNDLE/manifest.json")"
    actual="$(shasum -a 256 "$temp_asset" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || die "统一公网入口代表资产 SHA256 不一致"
    rm -f "$temp_index" "$temp_asset"
    trap - RETURN
    log "统一公网入口索引验收通过"
}

verify_all() {
    verify_local_bundle
    for server in "${SERVERS[@]}"; do verify_server "$server"; done
    verify_public
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
    prepare) prepare_bundle ;;
    check-nodes) check_nodes ;;
    publish-dev) load_config; stage_all; promote_all ;;
    verify-dev) load_config; verify_all ;;
    stage-main) load_config; stage_all ;;
    promote-main) load_config; verify_local_bundle; require_main_tag; promote_all ;;
    verify-main) load_config; verify_all ;;
    resume-main) load_config; verify_local_bundle; require_main_tag; stage_all; promote_all ;;
esac
