#!/bin/bash
# E2E 测试入口脚本
# 用法:
#   bash run-tests.sh                                   # 运行全部测试
#   bash run-tests.sh --distro ubuntu --server nginx    # 指定发行版和服务器
#   bash run-tests.sh --test scan                       # 指定测试文件
#   bash run-tests.sh --dind                            # 运行 Docker-in-Docker 测试
#   bash run-tests.sh --no-build                        # 跳过构建步骤
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# 默认参数
DISTROS=""
SERVERS=""
TESTS=""
NO_BUILD=false
RUN_DIND=false

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ==============================================================================
# 参数解析
# ==============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro)
            DISTROS="$2"
            shift 2
            ;;
        --server)
            SERVERS="$2"
            shift 2
            ;;
        --test)
            TESTS="$2"
            shift 2
            ;;
        --no-build)
            NO_BUILD=true
            shift
            ;;
        --dind)
            RUN_DIND=true
            shift
            ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --distro <name>   发行版 (ubuntu/debian/alpine/rocky)，默认全部"
            echo "  --server <type>   服务器 (nginx/apache)，默认全部"
            echo "  --test <name>     测试文件名 (不含 .bats 后缀)，默认全部"
            echo "  --no-build        跳过构建步骤"
            echo "  --dind            运行 Docker-in-Docker 测试"
            echo "  -h, --help        显示帮助"
            exit 0
            ;;
        *)
            echo "未知参数: $1"
            exit 1
            ;;
    esac
done

# 填充默认值
if [[ -z "$DISTROS" ]]; then
    DISTROS="ubuntu debian alpine rocky"
fi
if [[ -z "$SERVERS" ]]; then
    SERVERS="nginx apache"
fi

# ==============================================================================
# 辅助函数
# ==============================================================================

# 获取 web 服务器启动命令
get_start_cmd() {
    local server="$1"
    local distro="$2"

    if [[ "$server" == "nginx" ]]; then
        echo "nginx"
    elif [[ "$server" == "apache" ]]; then
        case "$distro" in
            ubuntu|debian) echo "apache2ctl start" ;;
            alpine)        echo "httpd" ;;
            rocky)         echo "httpd" ;;
        esac
    fi
}

# 获取 bats 命令：指定测试或全部（uninstall 排末尾）
get_bats_cmd() {
    local test_name="$1"

    if [[ -n "$test_name" ]]; then
        echo "bats --tap /tests/$test_name.bats"
    else
        # 全部测试：排除 uninstall（放最后）和 docker-scan（仅 DinD 运行）
        # shellcheck disable=SC2016
        echo 'TESTS=$(ls /tests/*.bats 2>/dev/null | grep -v -e uninstall -e docker-scan | sort); UNINSTALL=$(ls /tests/uninstall.bats 2>/dev/null); bats --tap $TESTS $UNINSTALL'
    fi
}

# ==============================================================================
# 主流程
# ==============================================================================

# 1. 构建
if [[ "$NO_BUILD" == "false" ]]; then
    echo -e "${CYAN}=== 构建 ===${NC}"
    bash "$SCRIPT_DIR/build.sh"
fi

# 确认二进制存在
if [[ ! -f "$TEST_DIR/build/sslctl" ]]; then
    echo -e "${RED}错误: $TEST_DIR/build/sslctl 不存在，请先执行构建${NC}"
    exit 1
fi

cd "$TEST_DIR"
mkdir -p reports

# 2. 启动 Mock API
echo -e "${CYAN}=== 启动 Mock API ===${NC}"
docker compose up -d mock-api
echo "等待 Mock API 健康检查..."
docker compose exec mock-api wget -q --spider http://localhost:8080/health 2>/dev/null && echo "Mock API 已就绪" || {
    # 等待 healthcheck 通过
    for i in $(seq 1 30); do
        if docker compose ps mock-api | grep -q healthy; then
            echo "Mock API 已就绪"
            break
        fi
        if [[ $i -eq 30 ]]; then
            echo -e "${RED}Mock API 启动超时${NC}"
            docker compose logs mock-api
            docker compose down -v
            exit 1
        fi
        sleep 1
    done
}

# 3. 运行测试
TOTAL=0
PASSED=0
FAILED=0
FAILED_LIST=""

# 常规服务测试（nginx/apache × distro）
for server in $SERVERS; do
    for distro in $DISTROS; do
        service="${server}-${distro}"
        TOTAL=$((TOTAL + 1))

        echo ""
        echo -e "${CYAN}=== 测试: $service ===${NC}"

        # 启动容器
        if ! docker compose up -d "$service" 2>&1; then
            echo -e "${RED}FAIL: $service (容器启动失败)${NC}"
            FAILED=$((FAILED + 1))
            FAILED_LIST="$FAILED_LIST $service"
            continue
        fi

        # 启动 web 服务器 + 运行 bats
        start_cmd=$(get_start_cmd "$server" "$distro")
        bats_cmd=$(get_bats_cmd "$TESTS")

        report_file="reports/${service}.tap"
        if docker compose exec -T "$service" bash -c "$start_cmd && $bats_cmd" > "$report_file" 2>&1; then
            echo -e "${GREEN}PASS: $service${NC}"
            PASSED=$((PASSED + 1))
        else
            echo -e "${RED}FAIL: $service${NC}"
            FAILED=$((FAILED + 1))
            FAILED_LIST="$FAILED_LIST $service"
            # 打印失败输出
            echo "--- TAP 输出 ---"
            cat "$report_file"
            echo "--- 结束 ---"
        fi

        # 停止当前服务容器（释放资源）
        docker compose stop "$service" >/dev/null 2>&1
    done
done

# 4. DinD 测试（可选）
if [[ "$RUN_DIND" == "true" ]]; then
    TOTAL=$((TOTAL + 1))
    echo ""
    echo -e "${CYAN}=== 测试: dind ===${NC}"

    if docker compose up -d dind 2>&1; then
        # DinD 需要等待 Docker daemon 就绪
        echo "等待 Docker daemon 就绪..."
        for i in $(seq 1 30); do
            if docker compose exec -T dind docker info >/dev/null 2>&1; then
                echo "Docker daemon 已就绪"
                break
            fi
            if [[ $i -eq 30 ]]; then
                echo -e "${RED}Docker daemon 启动超时${NC}"
                FAILED=$((FAILED + 1))
                FAILED_LIST="$FAILED_LIST dind"
                docker compose stop dind >/dev/null 2>&1
                # 跳到汇总
                break 2 2>/dev/null || true
            fi
            sleep 1
        done

        report_file="reports/dind.tap"
        dind_bats="bats --tap /tests/docker-scan.bats"
        if [[ -n "$TESTS" ]]; then
            dind_bats="bats --tap /tests/$TESTS.bats"
        fi

        if docker compose exec -T dind bash -c "$dind_bats" > "$report_file" 2>&1; then
            echo -e "${GREEN}PASS: dind${NC}"
            PASSED=$((PASSED + 1))
        else
            echo -e "${RED}FAIL: dind${NC}"
            FAILED=$((FAILED + 1))
            FAILED_LIST="$FAILED_LIST dind"
            echo "--- TAP 输出 ---"
            cat "$report_file"
            echo "--- 结束 ---"
        fi

        docker compose stop dind >/dev/null 2>&1
    else
        echo -e "${RED}FAIL: dind (容器启动失败)${NC}"
        FAILED=$((FAILED + 1))
        FAILED_LIST="$FAILED_LIST dind"
    fi
fi

# 5. 清理
echo ""
echo -e "${CYAN}=== 清理 ===${NC}"
docker compose down -v

# 6. 汇总结果
echo ""
echo "========================================"
echo -e " 测试汇总: 共 $TOTAL 个, ${GREEN}通过 $PASSED${NC}, ${RED}失败 $FAILED${NC}"
echo "========================================"
if [[ -n "$FAILED_LIST" ]]; then
    echo -e "${RED}失败列表:$FAILED_LIST${NC}"
fi
echo "TAP 报告: $TEST_DIR/reports/"

# 返回码
if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
