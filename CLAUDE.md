# sslctl

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache、Docker。

> **维护指引**：保持本文件精简，仅包含项目概览和快速参考。详细规范写入 `skills/` 目录。
>
> **统一规范**：跨项目共通行为规范见 `deploy-spec.md`

## 核心指令

- **不要自动提交** - 完成修改后等待用户确认"提交"再执行 git commit/push
- **测试发现 bug 必须修复代码** - 测试的目的是发现 bug 并修复，绝不修改测试去迎合错误的代码

## 项目结构

```text
cmd/           # CLI 入口（构建时使用 ./cmd/ 整个包，不能指定单文件）
  main.go      # 主入口
  rollback_helpers.go  # 回滚辅助函数
  setup/       # 一键部署命令
  daemon/      # 守护进程
  deploy/      # 证书部署
pkg/           # 可复用包
  certops/     # 证书操作服务层（扫描/部署/续签/私钥管理），依赖 webserver 抽象层
  webserver/   # Web 服务器抽象层（统一 Scanner/Deployer/Rollback 接口）
  config/      # 配置管理（文件锁+内存锁+深拷贝并发安全，含 SSRF 防护）
  errors/      # 错误类型定义（含结构化部署错误 StructuredDeployError）
  csr/         # CSR + 私钥生成（RSA/ECDSA）
  matcher/     # 域名匹配
  fetcher/     # API 客户端（含 SSRF/DNS Rebinding 防护）
  backup/      # 备份管理（哈希校验 TOCTOU 保护）
  service/     # 系统服务管理
  upgrade/     # 升级模块（版本检查/下载/Ed25519 签名验证/校验/安装）
  logger/      # 日志（含敏感信息过滤、路径脱敏、日志轮转）
  util/        # 工具函数（文件操作/权限检查）
internal/      # 内部实现
  nginx/       # Nginx 扫描/部署
  apache/      # Apache 扫描/部署
  executor/    # 统一命令执行器（白名单机制）
build/         # 构建/发布脚本
skills/        # 开发规范
testdata/      # 测试数据和工具
```

## 核心命令

```bash
# 一键部署（推荐）
sslctl setup --url <url> --token <token> --order <order_id>          # 单证书部署
sslctl setup --url <url> --token <token> --order "123,example.com"   # 批量部署
sslctl setup --url <url> --token <token>                             # 部署所有证书
sslctl setup --key /path/key.pem --webroot /var/www/html --url <url> --token <token> --order <id>  # 指定私钥+文件验证

# 站点扫描
sslctl scan                                      # 扫描站点（自动检测 Web 服务器）
sslctl scan --ssl-only                           # 仅扫描 SSL 站点

# 证书部署
sslctl deploy --cert <name>                      # 部署指定证书
sslctl deploy --cert <name> --site <server_name> # 绑定站点并部署
sslctl deploy --all                              # 部署所有证书

# 本地证书部署（不依赖 API）
sslctl deploy local --cert <file> --key <file> --site <server_name>
sslctl deploy local --cert <file> --key <file> --ca <file> --site <server_name>  # Apache

# 证书回滚
sslctl rollback --site <server_name>                    # 回滚到最新备份
sslctl rollback --site <server_name> --list             # 查看备份列表
sslctl rollback --site <server_name> --version <ts>     # 回滚到指定版本

# 服务管理
sslctl status                                    # 查看服务状态（含证书过期详情）
sslctl service repair                            # 修复服务
sslctl upgrade                                   # 升级工具
sslctl uninstall                                 # 卸载
```

## 配置文件

统一配置文件：`/opt/sslctl/config.json`

- API 配置在**证书级别**（每个证书独立的 `api` 字段），不再有全局 API
- `release_url`：升级发布地址（安装时从参数自动生成并写入，未传参则留空；升级模块从此读取，未配置时交互提示输入）
- `upgrade_channel`：升级通道（`main`/`dev`，安装时写入，默认 `main`）
- 配置迁移：`pkg/config/migrate.go` 声明式规则引擎，加载时自动检测旧格式并迁移（幂等，支持跨版本升级）

证书存储目录：`/opt/sslctl/certs/{server_name}/`

## 环境变量

| 变量               | 说明                                 |
| ------------------ | ------------------------------------ |
| `SSLCTL_API_TOKEN` | API Token（覆盖所有证书的 API 配置） |
| `SSLCTL_API_URL`   | API URL（覆盖所有证书的 API 配置）   |
| `SSLCTL_LOG_FORMAT`| 日志格式：`json` 启用 JSON 输出      |

## 测试

```bash
go test -v ./...                           # 运行单元测试
go test -coverprofile=coverage.out ./...   # 测试并生成覆盖率
bash build/test-linux.sh                   # Linux 发行版服务管理测试

# 容器端到端测试（Bats + Docker Compose）
bash docker/test/scripts/run-tests.sh                                 # 全部测试
bash docker/test/scripts/run-tests.sh --distro ubuntu --server nginx  # 指定目标
bash docker/test/scripts/run-tests.sh --dind                          # Docker-in-Docker 测试
bash docker/test/scripts/run-tests.sh --no-build --test scan          # 跳过构建，指定测试
```

容器测试目录结构、用例清单与 Mock API 说明见 `skills/build-release/SKILL.md`。

## CSR 生成

- CSR 只需要 Common Name（CN），**不需要** SAN（Subject Alternative Name），包括 IP 证书也只写 CN
- CA 签发证书的 SAN 必定包含 CN
- 默认密钥类型：RSA 2048，支持 ECDSA

## 续签模式速查

| 模式    | 说明             | 启用方式                                                 |
| ------- | ---------------- | -------------------------------------------------------- |
| `local` | 本机提交         | `--local-key` / `--key` / `--file-validation` 或配置文件 |
| `pull`  | 自动签发（默认） | 默认行为                                                 |

- `renew_before_days` 默认 14 天、上限 30 天，由服务端控制并在每次 API 交互后回写本地配置
- 判定逻辑、定时调度、秒签、文件验证、processing/active 状态、order_id 改名迁移、IP 证书等细节见 `skills/deploy-ops/SKILL.md`

## 开发规范（skills 索引）

按当前任务类型阅读对应 skill 获取详细规范：

| 领域         | 目录              | 涵盖内容                                                             |
| ------------ | ----------------- | ------------------------------------------------------------------- |
| Go 开发      | `go-dev/`         | 代码风格、错误处理、**安全开发规范**（全部安全机制）、**代码质量**、平台隔离、测试覆盖率 |
| Nginx/Apache | `nginx-apache/`   | 配置解析、证书部署、SSL 配置自动安装、安装器失败语义、Docker 站点部署    |
| 部署运维     | `deploy-ops/`     | 部署/续签流程、续签判定与调度、API 与回调契约、systemd、daemon        |
| 构建发布     | `build-release/`  | 版本发布、交叉编译、CI/CD、容器 E2E 测试目录                          |
