# sslctl 完成检查

这是本仓完成检查的唯一清单。工具入口只引用本文，不复制步骤。按变更范围执行全部适用项，并明确报告通过、不通过或不适用；不得用历史结果代替本轮证据。

## 0. 范围与安全

```bash
git status --short --branch
git diff --stat
git diff
git diff --cached
```

- 确认没有密钥、凭据、构建产物、调试代码、意外删除或无关改动。
- 检查 `deploy-spec.md` 是否被修改；若修改，必须走统一多仓同步/审计流程，单仓 CI 不拉取其他仓库移动分支比较。
- 真实发布、上传节点、Git tag、GitHub Release/PR 不属于 finish-check，除非用户另行明确授权。

## 1. 确定性治理门禁

```bash
bash build/check-agent-config.sh
bash build/test-release.sh
bash -n build/build.sh build/generate-keys.sh build/sign-release.sh build/release.sh build/check-agent-config.sh build/test-release.sh
git diff --check
```

该门禁必须验证：固定 `CLAUDE.md`、扁平 skill 路由、薄工具入口、无旧 skill 路径、CI 已执行治理检查；固定正式资产集合、SemVer、manifest、dev 可覆盖/main 不可覆盖、tag 后 resume 禁止构建和发布阶段全节点要求。

## 2. 构建与版本注入

在临时目录运行，避免复用 `dist/`：

```bash
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
bash build/build.sh 0.0.0-test.1 "$tmp_dir"
find "$tmp_dir" -maxdepth 1 -type f -print | sort
```

必须生成三份固定 gzip 资产及对应未压缩二进制。在 Linux amd64 宿主直接解压代表资产并运行 `--version`；其他宿主使用相同 ldflags 额外构建本机临时二进制并运行，确认注入值为 `0.0.0-test.1`。交叉编译只证明三平台可构建，不冒充异平台运行证据。

## 3. Go 测试、竞态与覆盖率

```bash
go test -race -count=1 ./...
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1
```

整体覆盖率基线为 53.5%；显著下降必须解释并补测试。沙箱若阻止 Go cache 或 `httptest` loopback，需在允许缓存与 loopback 的环境原样重跑，不能改代码或弱化测试迁就环境。

## 4. 双平台静态检查

```bash
golangci-lint run --timeout=5m ./...
GOOS=windows GOARCH=amd64 golangci-lint run --timeout=5m ./...
```

不得用无依据的 `nolint` 绕过。若修改 Go 文件，使用 Go 1.24 对触及文件执行 gofmt，避免新版工具链机械重排基线文件。

## 5. 领域审查

按 `skills/SKILL.md` 路由复核受影响领域：

- 部署链：成功必须代表实际生效；部分失败退出非零；test/reload 失败回滚；回调、pending 私钥、order_id、到期元数据与共享续签锁保持契约。
- 安全：命令白名单、SSRF/DNS rebinding、路径/符号链接、原子写、权限、日志脱敏和 Ed25519 防降级未被削弱。
- 跨平台：Linux/Windows build tag、服务生命周期和文件替换语义同步；交叉编译不冒充真实 Windows 运行证据。
- 发布：三项正式资产、一次构建、持久 bundle、不可变 main、中断恢复、全节点一致性和 release gates 均由脚本测试与静态门禁覆盖。

## 6. Docker E2E release gate

发布相关、部署链或 Docker 语义变更时运行：

```bash
bash docker/test/scripts/run-tests-contract-test.sh
bash docker/test/scripts/run-tests.sh
```

完整门禁包括 Nginx/Apache × ubuntu/debian/alpine/rocky 的 8 个常规任务和 DinD；`--no-dind` 仅用于调试。异步 daemon 用例必须分别等待操作启动和目标回调完成，不能把请求开始当作业务完成。

仅文档/智能体路由/不触及运行代码的发布脚本治理，可将 Docker E2E 标为不适用，但仍须执行脚本 mock、三平台构建、Go tests、lint 与治理门禁。

## 7. 最终复核与提交前证据

```bash
git diff --check
git status --short --branch
git diff --stat
git diff
git log -8 --oneline
```

逐条对照用户需求和 `deploy-spec.md` 受影响条款；只在所有适用命令本轮退出 0 后声明完成。提交前再次确认当前分支和授权范围；提交后检查 commit 内容与工作区状态。除非用户明确要求，不推送。
