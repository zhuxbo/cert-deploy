# 完成检查（finish-check）

在提交代码前，按以下清单逐项检查。每一步都必须实际执行命令并报告结果，不能跳过。

---

## 0. 检查范围

先确定本次检查的 diff 范围，后续所有"审查改动"的步骤都以此范围为准：

- **工作区模式**（默认）：改动尚未提交，范围是 `git diff` + `git diff --cached`。
- **工作分支模式**：改动已按批次提交到特性分支，以基线分支（通常 `dev`）为对照：

```bash
git log --oneline <base>..HEAD    # 逐提交清单
git diff <base>...HEAD            # 全量改动
```

分支模式还需逐提交检查：每个提交只含单一主题的相关文件；提交信息为 `type: 中文主题` + 2–10 条要点式 body；无任何 AI 署名。

---

## 1. 编译检查

运行交叉编译，确认三个目标平台均能编译通过：

```bash
GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd && \
GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd && \
GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd
```

如果编译失败，修复后重新检查。

## 2. 单元测试

运行全部单元测试（含竞态检测）：

```bash
go test -race -count=1 ./...
```

- 所有测试必须通过
- 如果有失败，分析失败原因并修复代码（不要修改测试去迎合错误的代码）

## 3. Lint 检查

本项目含 Windows 专属源（`svc/mgr`、`kernel32` 等），lint 必须双平台同时跑：

```bash
golangci-lint run ./... --timeout=5m                 # Linux 视角
GOOS=windows golangci-lint run ./... --timeout=5m    # Windows 视角
```

启用的检查器：errcheck、govet、staticcheck、gosec、unused、ineffassign。
测试文件已排除 gosec 和 errcheck，`docker/test/mock-api/` 已排除 gosec。

- 任一平台报错都必须修复
- 不要通过添加 `//nolint` 注释来绕过检查，除非有充分理由并加注释说明
- 跨平台 lint 在任意机器上都能跑，无需 Windows 物理机

gofmt 要求：go.mod 目标为 `go 1.24`，CI 也用 Go 1.24 工具链，且 `.golangci.yml` 未启用 gofmt/gofumpt，故 CI 不单独检查格式。若本机 Go 工具链比 1.24 新（如 1.26），其 gofmt 采用了更新的规范（例如删除函数尾部空行），会对约 40 个基线文件报告差异——这是**工具链版本漂移，非仓库缺陷**。要求：本次改动的行符合 go.mod 目标版本（go 1.24）的 gofmt；不要因本机新版 gofmt 而重排未触碰的既有代码。

## 4. Go 项目专项检查

### 4.1 平台兼容性

检查是否涉及平台相关代码。本项目使用 Build Tag 隔离平台实现：

- `pkg/util/inode_unix.go` / `inode_windows.go`
- `pkg/util/selinux_linux.go` / `selinux_other.go`
- `pkg/config/flock_unix.go` / `flock_windows.go`
- `internal/executor/detach_unix.go` / `detach_windows.go`
- `internal/deployer/signal_unix.go` / `signal_windows.go`
- `pkg/service/systemd.go` / `openrc.go` / `sysvinit.go` / `windows.go` / `windows_stub.go`
- `cmd/console_windows.go` / `console_other.go`

如果修改了平台相关逻辑，确认：

- 对应的平台文件也做了相应修改
- Build Tag 正确（`//go:build linux`、`//go:build !windows` 等）
- Windows 和 Linux 编译均通过（已在步骤 1 覆盖）

### 4.2 命令执行白名单

如果新增了系统命令调用，检查：

- 是否通过 `internal/executor` 执行（禁止直接使用 `exec.Command`）
- 新命令是否已加入 `AllowedCommands` 或 `AllowedScanExecutables`/`AllowedScanArgs` 白名单
- 白名单测试（`executor_test.go`）是否覆盖了新命令

### 4.3 并发安全

如果修改了以下包，需特别注意并发安全：

- `pkg/config/` — 文件锁 + 内存锁 + 深拷贝，返回值不应持有内部引用
- `pkg/logger/` — `minLevel`/`jsonMode` 必须使用 `atomic` 类型
- `pkg/certops/` — 服务层操作可能被守护进程并发调用

### 4.4 安全检查

对照本项目已有的安全机制，检查改动是否引入新风险：

- **文件操作**：是否检查符号链接？是否有 TOCTOU 风险？是否使用 AtomicWrite？
- **路径处理**：用户输入的路径是否做了穿越防护？
- **SSRF**：如果涉及 HTTP 请求，是否经过 `pkg/fetcher` 的 SSRF 防护？
- **日志脱敏**：是否有私钥、Token、密码等敏感信息可能被记录到日志？
- **配置文件**：配置读写是否通过 `pkg/config`（自带文件锁和并发安全）？

### 4.5 接口一致性

如果修改了 `pkg/webserver/` 的接口定义（Scanner/Deployer/Rollback），确认：

- `internal/nginx/` 和 `internal/apache/` 的实现同步更新
- 接口参数命名一致（如 `Deploy` 方法的 `intermediate` 参数）

### 4.6 错误处理

- 新增的错误是否使用了 `pkg/errors` 的结构化错误类型（`StructuredDeployError`）？
- 错误是否包含类型分类、阶段定位和可重试判断？
- API 回调错误是否仅记录日志而非阻断主流程？

### 4.7 部署链专项（涉及 pkg/certops、cmd/setup、cmd/deploy、internal/*/installer 时）

- **回调契约**：回调请求体是否为三字段（order_id/status/deployed_at）+ 可选 message（仅 failure，脱敏且 ≤256 rune）？回调 status 仅 success/failure（pending 不上报回调）？新增失败路径（prepare/重试/触顶/panic/过期触顶）是否都发送 failure 回调？
- **假成功语义**：success 与退出码是否以实际生效为前提——部分失败退出码非零；reload/test 失败不算成功且回滚；docker 绑定空命令/无卷必须明确报错而非静默跳过；安装器"无可注入块"必须报错而非 Modified=false。
- **pending 私钥生命周期**（spec §3.8/§5.3）：配对校验通过且部署成功后才转正/清理；校验失败保留 pending、不触碰线上私钥；重试与手动部署路径必须能感知 pending（GetPrivateKeyForCert）；部署全失败时不得更新到期元数据（保持下轮完整自愈）。
- **备份/回滚对齐**：所有部署入口（setup/deploy/续签）覆盖站点证书前先备份、失败回滚；回滚用文件操作有符号链接防护。
- **并发互斥**：证书操作入口（deploy/setup/rollback/daemon）是否共享续签锁；配置写路径是否走锁内 fresh-load 读-改-写。

### 4.8 deploy-spec.md 跨仓一致性（改动触碰 deploy-spec.md 时）

`deploy-spec.md` 是四仓（sslctl / sslctlw / sslbt / sslnas）共享的统一部署规范，必须**逐字节一致**。若本次改动触碰了 `deploy-spec.md`，同步更新另三仓后逐一比对：

```bash
for d in ../sslctlw ../sslbt ../sslnas; do
  if diff -q deploy-spec.md "$d/deploy-spec.md" >/dev/null 2>&1; then
    echo "OK   $d 一致"
  else
    echo "DIFF $d 不一致"; diff deploy-spec.md "$d/deploy-spec.md"
  fi
done
```

- 全部输出 `OK` 才算通过；任一 `DIFF` 需把四仓改到字节一致后再提交。
- 客户端代码若引用了 spec 的条款编号（如回调契约、pending 私钥生命周期、renew_before_days 上限），确认编号与 spec 现行版本对应。

## 5. Git Diff 审查

按第 0 步确定的范围查看完整改动：

```bash
git status
git diff && git diff --cached        # 工作区模式
git diff <base>...HEAD               # 工作分支模式（并逐提交 git show）
```

逐项确认：

- **无意外文件**：没有不应提交的文件（临时文件、IDE 配置、.env、密钥文件）
- **无调试代码**：没有残留的 `fmt.Println`、`log.Println` 调试输出
- **无硬编码**：没有硬编码的 IP、URL、密码、Token
- **无意外删除**：没有误删原有代码或测试
- **testdata 变更**：如果修改了 `testdata/` 下的测试数据，确认是有意为之
- **go.mod/go.sum**：如果变更了依赖，确认是必要的且没有引入不必要的依赖

## 6. 测试覆盖率回归

如果新增或修改了核心逻辑，检查覆盖率是否下降：

```bash
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1
```

核心包的覆盖率基线（实测）：

- `pkg/errors` — 98.6%
- `pkg/config` — 83.7%
- `pkg/backup` — 85.9%
- `pkg/certops` — 78.5%
- 整体 — 53.5%（`go tool cover -func` 全量语句加权，含 `cmd/*`、`internal/deployer` 等低覆盖入口包；核心业务包普遍 78%+）

新增代码应有对应的测试。覆盖率不应显著下降。

## 7. 已知局限性和潜在风险

对本次改动，按以下分类列出已知局限性和潜在风险：

### 安全风险

- 是否绕过了现有安全机制（白名单、SSRF 防护、符号链接检查）？
- 是否有新的用户输入未经校验直接使用？

### 兼容性风险

- 是否影响现有的配置文件格式（`/opt/sslctl/config.json`）？
- 是否影响 CLI 命令的参数或输出格式（可能破坏脚本集成）？
- 是否影响 systemd/SysVinit/OpenRC 服务文件？

### 运行时风险

- 是否有 goroutine 泄漏风险（未关闭的 channel、未取消的 context）？
- 是否有文件句柄泄漏（defer close 是否正确）？
- 守护进程场景下是否存在资源积累问题？

### 部署风险

- 升级模块变更是否保持了 Ed25519 签名验证的完整性？
- 是否影响了 `/opt/sslctl/certs/` 的目录结构？
- SELinux 环境下文件上下文是否会被破坏？

---

将以上所有检查结果汇总，明确标注：通过 / 不通过 / 不适用。
对于不通过的项，给出修复建议。
