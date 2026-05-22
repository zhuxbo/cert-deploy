#!/bin/bash
# sslctl 安装脚本
# 自动检测系统和架构，下载部署工具

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 参数解析
CHANNEL=""          # 空=自动，main/dev=指定
TARGET_VERSION=""   # 空=最新，指定=使用该版本
FORCE=false
RELEASE_HOST=""     # 域名（或域名+路径），如 release.example.com 或 cdn.example.com/mirror

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)
            CHANNEL="dev"
            shift
            ;;
        --main)
            CHANNEL="main"
            shift
            ;;
        --version)
            if [ -z "${2:-}" ]; then
                echo_error "--version 需要指定版本号"
                exit 1
            fi
            TARGET_VERSION="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help|-h)
            echo "用法: curl -fsSL <url>/install.sh | bash -s -- [host] [选项]"
            echo ""
            echo "参数:"
            echo "  [host]         升级服务器（域名或域名+路径，默认 release.cnssl.com）"
            echo ""
            echo "选项:"
            echo "  --dev          安装测试版（dev 通道）"
            echo "  --main         安装稳定版（main 通道，默认）"
            echo "  --version VER  安装指定版本"
            echo "  --force        强制重新安装（即使版本相同）"
            echo "  --help         显示此帮助信息"
            echo ""
            echo "示例:"
            echo "  bash -s -- release.example.com                     # 安装最新稳定版"
            echo "  bash -s -- release.example.com --dev               # 安装最新测试版"
            echo "  bash -s -- release.example.com --version 1.0.0     # 安装指定版本"
            echo "  bash -s -- cdn.example.com/mirror                  # 多层目录"
            echo ""
            echo "未指定域名时使用内置默认地址。"
            exit 0
            ;;
        --*)
            echo_error "未知参数: $1"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
        *)
            if [ -z "$RELEASE_HOST" ]; then
                RELEASE_HOST="$1"
            else
                echo_error "多余的参数: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# 网络超时（秒），可通过环境变量覆盖
TIMEOUT=${SSLCTL_TIMEOUT:-30}

# 检测可用的 Python（CentOS 7 默认无 python3，宝塔自带 python 可能不在 PATH）
PYTHON3=""
for _py in python3 /www/server/panel/pyenv/bin/python3 python python2; do
    if command -v "$_py" >/dev/null 2>&1 && "$_py" -c "import json" >/dev/null 2>&1; then
        PYTHON3="$_py"
        break
    fi
done

# 发布目录探测
# 先尝试根目录 https://{host}/sslctl，失败回落到 https://{host}/release/sslctl
# 首个 releases.json 可访问的候选作为 RELEASE_URL
FALLBACK_HOST="release.cnssl.com"
RELEASE_HOST="${RELEASE_HOST:-$FALLBACK_HOST}"
RELEASE_HOST="${RELEASE_HOST%/}"

probe_release_url() {
    local host="$1"
    local candidate body
    for suffix in "/sslctl" "/release/sslctl"; do
        candidate="https://${host}${suffix}"
        body=$(curl -s --connect-timeout 5 --max-time 10 "${candidate}/releases.json" 2>/dev/null || echo "")
        if echo "$body" | grep -q '"latest"'; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

echo_info "探测发布目录..."
RELEASE_URL=$(probe_release_url "$RELEASE_HOST")
if [ -z "$RELEASE_URL" ]; then
    echo_error "发布目录不可达: https://${RELEASE_HOST}/sslctl/releases.json 与 https://${RELEASE_HOST}/release/sslctl/releases.json 均无响应"
    exit 1
fi
echo_info "使用发布地址: $RELEASE_URL"

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo_error "请使用 root 权限运行此脚本"
    exit 1
fi

# 检测系统
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    echo_error "不支持的操作系统: $OS (仅支持 Linux)"
    exit 1
fi

# 检测架构
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo_error "不支持的架构: $ARCH"
        exit 1
        ;;
esac

echo_info "系统: $OS, 架构: $ARCH"

# 检测 Web 服务
# 三级检测: PATH → 常见路径 → 运行中的进程
detect_webserver() {
    local services=""

    # 检测 Nginx: PATH → 常见路径 → 进程
    if command -v nginx >/dev/null 2>&1 || \
       [ -x /usr/sbin/nginx ] || \
       [ -x /usr/local/nginx/sbin/nginx ] || \
       [ -x /opt/nginx/sbin/nginx ] || \
       pgrep -x nginx >/dev/null 2>&1; then
        services="nginx"
    fi

    # 检测 Apache: PATH → 常见路径 → 进程
    if command -v apache2ctl >/dev/null 2>&1 || \
       command -v apachectl >/dev/null 2>&1 || \
       command -v httpd >/dev/null 2>&1 || \
       [ -x /usr/sbin/httpd ] || \
       [ -x /usr/sbin/apache2 ] || \
       pgrep -x 'httpd|apache2' >/dev/null 2>&1; then
        if [ -n "$services" ]; then
            services="$services, apache"
        else
            services="apache"
        fi
    fi

    echo "$services"
}

SERVICES=$(detect_webserver)
if [ -n "$SERVICES" ]; then
    echo_info "检测到 Web 服务: $SERVICES"
else
    echo_warn "未检测到 nginx 或 apache，仍可继续安装"
fi

# 规范化版本号（确保带 v 前缀）
normalize_version() {
    local ver="$1"
    if [[ "$ver" != v* ]]; then
        echo "v$ver"
    else
        echo "$ver"
    fi
}

# 获取目标版本
get_target_version() {
    # 如果指定了版本，直接使用
    if [ -n "$TARGET_VERSION" ]; then
        # 自动推断通道（除非已指定）
        if [ -z "$CHANNEL" ]; then
            if [[ "$TARGET_VERSION" == *"-"* ]]; then
                CHANNEL="dev"
            else
                CHANNEL="main"
            fi
        fi
        # 规范化版本号
        echo "$(normalize_version "$TARGET_VERSION")"
        return
    fi

    # 获取最新版本
    local json
    json=$(curl -s --connect-timeout $TIMEOUT "$RELEASE_URL/releases.json" 2>/dev/null)
    if [ -z "$json" ]; then
        echo ""
        return
    fi

    local version=""
    local ch="${CHANNEL:-main}"
    if [ -n "$PYTHON3" ]; then
        version=$(echo "$json" | "$PYTHON3" -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ch = '$ch'
    if ch in d and 'latest' in d[ch]:
        print(d[ch]['latest'])
    elif ch == '' or ch == 'main':
        for c in ['main', 'dev']:
            if c in d and 'latest' in d[c]:
                print(d[c]['latest']); break
except: pass
" 2>/dev/null)
    else
        # 无 Python 时用 grep 粗略提取（按通道顺序找到第一个 latest）
        # 仅在简单格式下可靠：通道为顶层 key 且 latest 紧跟其后
        version=$(echo "$json" | awk -v ch="$ch" '
            $0 ~ "\""ch"\"[[:space:]]*:" { found=1 }
            found && match($0, /"latest"[[:space:]]*:[[:space:]]*"[^"]+"/) {
                s = substr($0, RSTART, RLENGTH)
                sub(/.*"latest"[[:space:]]*:[[:space:]]*"/, "", s)
                sub(/"$/, "", s)
                print s; exit
            }')
    fi

    # 自动推断通道
    if [ -z "$CHANNEL" ] && [ -n "$version" ]; then
        if [[ "$version" == *"-"* ]]; then
            CHANNEL="dev"
        else
            CHANNEL="main"
        fi
    fi

    if [ -z "$version" ]; then
        echo ""
    else
        normalize_version "$version"
    fi
}

BINARY_DST="/usr/local/bin/sslctl"

echo_info "获取目标版本..."
VERSION=$(get_target_version)

if [ -z "$VERSION" ]; then
    echo_error "无法获取版本信息: $RELEASE_URL/releases.json"
    if [ -z "$PYTHON3" ]; then
        echo_error "未找到可用的 Python（python3/python/python2 均不可用），且 awk 解析失败"
        echo_error "建议安装 python3 后重试: yum install -y python3"
    fi
    exit 1
fi

# 子 shell 中设置的 CHANNEL 不会传回，在此推断
if [ -z "$CHANNEL" ]; then
    if [[ "$VERSION" == *"-"* ]]; then
        CHANNEL="dev"
    else
        CHANNEL="main"
    fi
fi

# 显示通道信息
if [ "$CHANNEL" = "dev" ]; then
    echo_info "目标版本: $VERSION (测试版)"
else
    echo_info "目标版本: $VERSION (稳定版)"
fi

# 检测已安装版本
CURRENT_VERSION=""
if [ -x "$BINARY_DST" ]; then
    CURRENT_VERSION=$("$BINARY_DST" --version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?' || echo "")
    [ -n "$CURRENT_VERSION" ] && CURRENT_VERSION=$(normalize_version "$CURRENT_VERSION")
fi

# 版本比较
if [ -n "$CURRENT_VERSION" ]; then
    if [ "$CURRENT_VERSION" = "$VERSION" ]; then
        if [ "$FORCE" = true ]; then
            echo_info "当前版本: $CURRENT_VERSION，强制重新安装"
        else
            echo_info "当前版本 $CURRENT_VERSION 已是目标版本，使用 --force 强制重新安装"
            exit 0
        fi
    else
        echo_info "升级: $CURRENT_VERSION → $VERSION"
    fi
fi

FILENAME="sslctl-${OS}-${ARCH}.gz"
DOWNLOAD_URL="$RELEASE_URL/$CHANNEL/$VERSION/$FILENAME"

echo_info "下载 $FILENAME..."

if ! curl -fsSL --connect-timeout $TIMEOUT "$DOWNLOAD_URL" -o "/tmp/$FILENAME"; then
    echo_error "下载失败: $DOWNLOAD_URL"
    exit 1
fi
FILE_SIZE=$(stat -c%s "/tmp/$FILENAME" 2>/dev/null || stat -f%z "/tmp/$FILENAME" 2>/dev/null || echo "")
if [ -n "$FILE_SIZE" ]; then
    echo_info "下载完成 ($(awk "BEGIN{printf \"%.2f\", $FILE_SIZE/1048576}") MB)"
fi

# SHA256 校验（从 {channel}.versions[].checksums.{filename} 提取）
EXPECTED_HASH=""
if [ -n "$PYTHON3" ]; then
    EXPECTED_HASH=$(curl -s --connect-timeout $TIMEOUT "$RELEASE_URL/releases.json" 2>/dev/null | \
        "$PYTHON3" -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ch = d.get('$CHANNEL', {})
    for v in ch.get('versions', []):
        if v.get('version') == '${VERSION#v}':
            h = v.get('checksums', {}).get('$FILENAME', '')
            if h.startswith('sha256:'):
                print(h[7:])
            break
except: pass
" 2>/dev/null)
fi
if [ -n "$EXPECTED_HASH" ]; then
    ACTUAL_HASH=$(sha256sum "/tmp/$FILENAME" 2>/dev/null | cut -d' ' -f1)
    [ -z "$ACTUAL_HASH" ] && ACTUAL_HASH=$(shasum -a 256 "/tmp/$FILENAME" 2>/dev/null | cut -d' ' -f1)
    if [ -z "$ACTUAL_HASH" ]; then
        echo_error "无法计算 SHA256，中止安装"
        rm -f "/tmp/$FILENAME"
        exit 1
    fi
    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        echo_error "SHA256 校验失败: 文件可能被篡改"
        echo_error "  期望: $EXPECTED_HASH"
        echo_error "  实际: $ACTUAL_HASH"
        rm -f "/tmp/$FILENAME"
        exit 1
    fi
    echo_info "SHA256 校验通过"
else
    echo_warn "无法获取校验和（需要 Python），跳过 SHA256 校验"
fi

# 解压并安装
echo_info "安装中..."
gunzip -f "/tmp/$FILENAME"

BINARY_SRC="/tmp/sslctl-${OS}-${ARCH}"

if ! mv "$BINARY_SRC" "$BINARY_DST" 2>/dev/null; then
    echo_error "无法安装到 $BINARY_DST，正在诊断原因..."

    # 检查目录写权限
    DST_DIR=$(dirname "$BINARY_DST")
    if [ ! -w "$DST_DIR" ]; then
        echo_error "原因: 目录 $DST_DIR 没有写权限"
        echo_error "当前权限: $(ls -ld "$DST_DIR" 2>/dev/null)"
        echo_error "提示: 宝塔面板「系统加固」或其他安全软件可能修改了系统目录权限"
        echo_error "修复: 1. 有加固软件，关闭「系统加固」等安全软件，将 $BINARY_DST 加入工具「进程白名单」，然后重新运行安装脚本"
        echo_error "      2. chmod 755 $DST_DIR 修复目录权限，然后重新运行安装脚本"
        rm -f "$BINARY_SRC"
        exit 1
    fi

    # 检查 immutable 属性
    if [ -f "$BINARY_DST" ] && command -v lsattr >/dev/null 2>&1; then
        ATTRS=$(lsattr "$BINARY_DST" 2>/dev/null || true)
        if echo "$ATTRS" | grep -q -- '----i'; then
            echo_error "原因: 文件有 immutable (不可变) 属性"
            echo_error "提示: 可能由防篡改工具或安全加固软件设置"
            echo_error "修复: 1. 有安全软件，关闭「防篡改」等安全软件，将 $BINARY_DST 加入工具「进程白名单」，然后重新运行安装脚本"
            echo_error "      2. chattr -i $BINARY_DST，然后重新运行安装脚本"
            rm -f "$BINARY_SRC"
            exit 1
        fi
    fi

    # 检查 SELinux
    if command -v getenforce >/dev/null 2>&1; then
        SE_STATUS=$(getenforce 2>/dev/null || true)
        if [ "$SE_STATUS" = "Enforcing" ]; then
            echo_error "原因: SELinux 处于 Enforcing 模式，可能阻止了文件写入"
            if command -v ausearch >/dev/null 2>&1; then
                DENIED=$(ausearch -m avc -ts recent 2>/dev/null | grep "$BINARY_DST" | tail -3)
                [ -n "$DENIED" ] && echo_error "SELinux 拒绝记录:\n$DENIED"
            fi
            echo_error "修复: setenforce 0 (临时关闭) 然后重新安装，或调整 SELinux 策略"
            rm -f "$BINARY_SRC"
            exit 1
        fi
    fi

    # 检查文件系统是否只读
    if mount 2>/dev/null | grep -E ' /usr/local | /usr ' | grep -q '\bro\b'; then
        echo_error "原因: 文件系统以只读方式挂载"
        echo_error "修复: mount -o remount,rw /usr/local (或对应的挂载点)"
        rm -f "$BINARY_SRC"
        exit 1
    fi

    # 通用诊断信息
    echo_error "无法确定具体原因，以下信息可能有帮助:"
    [ -f "$BINARY_DST" ] && echo_error "已有文件: $(ls -la "$BINARY_DST" 2>/dev/null)"
    echo_error "目标目录: $(ls -ld /usr/local/bin/ 2>/dev/null)"
    echo_error "当前用户: $(id)"
    echo_error "提示: 如使用安全防护工具，请将 $BINARY_DST 加入工具白名单后重试"
    echo_error "建议: 手动执行 mv $BINARY_SRC $BINARY_DST 查看详细错误"
    rm -f "$BINARY_SRC"
    exit 1
fi

chmod +x "$BINARY_DST"

# 创建工作目录
mkdir -p /opt/sslctl/{logs,backup,certs}

# 写入配置文件（RELEASE_URL 始终有值：参数传入或内置回落）
CONFIG_FILE="/opt/sslctl/config.json"
if [ -f "$CONFIG_FILE" ]; then
    # 配置已存在，合并 release_url（不覆盖其他字段）
    if [ -n "$PYTHON3" ]; then
        if ! "$PYTHON3" - "$CONFIG_FILE" "$RELEASE_URL" "${CHANNEL:-main}" << 'PYEOF'
import json, os, sys, tempfile
config_path, release_url = sys.argv[1], sys.argv[2]
channel = sys.argv[3] if len(sys.argv) > 3 else "main"
try:
    with open(config_path, "rb") as f:
        cfg = json.loads(f.read().decode("utf-8"))
except Exception:
    sys.stderr.write("配置解析失败，未修改 release_url\n")
    sys.exit(1)
cfg["release_url"] = release_url
cfg["upgrade_channel"] = channel
data = json.dumps(cfg, indent=2, ensure_ascii=False)
# py3 str / py2 unicode 都需 encode；py2 ASCII-only 时为 str(=bytes) 已是字节
if not isinstance(data, bytes):
    data = data.encode("utf-8")
d = os.path.dirname(config_path) or "."
fd, tmp_path = tempfile.mkstemp(dir=d)
try:
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.rename(tmp_path, config_path)
except Exception:
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    raise
PYEOF
        then
            echo_error "写入 release_url 失败，配置未修改"
            exit 1
        fi
        chmod 600 "$CONFIG_FILE"
    elif command -v jq >/dev/null 2>&1; then
        tmp_file=$(mktemp)
        if jq --arg url "$RELEASE_URL" --arg ch "${CHANNEL:-main}" '.release_url = $url | .upgrade_channel = $ch' "$CONFIG_FILE" > "$tmp_file"; then
            mv "$tmp_file" "$CONFIG_FILE"
            chmod 600 "$CONFIG_FILE"
        else
            rm -f "$tmp_file"
            echo_error "配置解析失败，未修改 release_url"
            exit 1
        fi
    else
        echo_error "未找到 Python 或 jq，无法写入 release_url"
        exit 1
    fi
else
    # 首次安装，创建配置
    cat > "$CONFIG_FILE" << CFGEOF
{
  "release_url": "$RELEASE_URL",
  "upgrade_channel": "${CHANNEL:-main}"
}
CFGEOF
    chmod 600 "$CONFIG_FILE"
fi

# 检测 init 系统
detect_init_system() {
    # 检测 systemd
    if [ -d /run/systemd/system ]; then
        echo "systemd"
        return
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-system-running >/dev/null 2>&1; then
            echo "systemd"
            return
        fi
    fi

    # 检测 OpenRC
    if command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
        return
    fi
    if [ -f /sbin/openrc ]; then
        echo "openrc"
        return
    fi

    # 检测 SysVinit
    if [ -d /etc/init.d ]; then
        echo "sysvinit"
        return
    fi

    echo "unknown"
}

INIT_SYSTEM=$(detect_init_system)
echo_info "检测到 init 系统: $INIT_SYSTEM"

# 安装服务（仅首次安装时创建，升级时保留现有配置）
install_service() {
    local DAEMON_CMD="/usr/local/bin/sslctl daemon"

    case "$INIT_SYSTEM" in
        systemd)
            if [ -f /etc/systemd/system/sslctl.service ]; then
                # 升级：重启服务加载新二进制
                systemctl restart sslctl 2>/dev/null && echo_info "已重启 systemd 服务" || true
            else
                cat > /etc/systemd/system/sslctl.service << EOF
[Unit]
Description=SSL Certificate Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$DAEMON_CMD
Restart=always
RestartSec=30
User=root
Group=root
WorkingDirectory=/opt/sslctl
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/sslctl /etc/nginx /etc/apache2 /etc/httpd /etc/letsencrypt

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable sslctl
                systemctl start sslctl
                echo_info "已安装并启动 systemd 服务"
            fi
            ;;
        openrc)
            if [ -f /etc/init.d/sslctl ]; then
                rc-service sslctl restart 2>/dev/null && echo_info "已重启 OpenRC 服务" || true
            else
                cat > /etc/init.d/sslctl << 'EOF'
#!/sbin/openrc-run

name="sslctl"
description="SSL Certificate Manager"
command="/usr/local/bin/sslctl"
command_args="daemon"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
directory="/opt/sslctl"

depend() {
    need net
    after firewall
}
EOF
                chmod +x /etc/init.d/sslctl
                rc-update add sslctl default
                rc-service sslctl start
                echo_info "已安装并启动 OpenRC 服务"
            fi
            ;;
        sysvinit)
            if [ -f /etc/init.d/sslctl ]; then
                /etc/init.d/sslctl restart 2>/dev/null && echo_info "已重启 SysVinit 服务" || true
            else
                cat > /etc/init.d/sslctl << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sslctl
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SSL Certificate Manager
# Description:       SSL 证书自动部署服务
### END INIT INFO

NAME="sslctl"
DAEMON="/usr/local/bin/sslctl"
DAEMON_ARGS="daemon"
PIDFILE="/var/run/${NAME}.pid"
WORKDIR="/opt/sslctl"

read_pid() {
    local pid=""
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE" 2>/dev/null)
        # 验证 PID 为纯数字
        if [ -n "$pid" ] && [ "$pid" -eq "$pid" ] 2>/dev/null; then
            echo "$pid"
        fi
    fi
}

start() {
    echo "Starting $NAME..."
    local pid=$(read_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$NAME is already running"
        return 1
    fi
    cd "$WORKDIR"
    nohup "$DAEMON" $DAEMON_ARGS > /dev/null 2>&1 &
    echo $! > "$PIDFILE"
    echo "$NAME started"
}

stop() {
    echo "Stopping $NAME..."
    if [ ! -f "$PIDFILE" ]; then
        echo "$NAME is not running"
        return 1
    fi
    local pid=$(read_pid)
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null
    fi
    rm -f "$PIDFILE"
    echo "$NAME stopped"
}

status() {
    local pid=$(read_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$NAME is running (PID: $pid)"
        return 0
    else
        echo "$NAME is not running"
        return 1
    fi
}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)  status ;;
    *)       echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
EOF
                chmod +x /etc/init.d/sslctl

                # Debian/Ubuntu
                if command -v update-rc.d >/dev/null 2>&1; then
                    update-rc.d sslctl defaults
                # CentOS/RHEL
                elif command -v chkconfig >/dev/null 2>&1; then
                    chkconfig --add sslctl
                    chkconfig sslctl on
                fi

                /etc/init.d/sslctl start
                echo_info "已安装并启动 SysVinit 服务"
            fi
            ;;
        *)
            echo_warn "未知的 init 系统，跳过服务安装"
            echo_warn "请手动运行: sslctl daemon"
            ;;
    esac
}

install_service

echo ""
echo_info "安装完成！"
echo ""
echo "使用方法:"
echo "  sslctl scan                           # 扫描站点"
echo "  sslctl deploy --site example.com      # 部署证书"
echo "  sslctl status                         # 查看服务状态"
echo "  sslctl upgrade                        # 升级工具"
echo "  sslctl service repair                 # 修复服务"
echo "  sslctl --debug scan                   # 调试模式"
echo "  sslctl help                           # 查看帮助"
echo ""
echo "配置文件: /opt/sslctl/config.json"
