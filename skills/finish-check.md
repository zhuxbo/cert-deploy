# sslctl 完成检查

这是本仓完成检查的唯一清单。工具入口只引用本文，不复制步骤。默认先分析变更，再按影响包、反向依赖、领域和风险执行适用项；不得因为全量较慢就漏检，也不得对局部变更机械重复全仓编译。明确报告通过、不通过或不适用，不得用历史结果代替本轮证据。

## 0. 范围与安全

```bash
git status --short --branch
git diff --stat
git diff
git diff --cached
python3 build/plan-checks.py ${FINISH_CHECK_BASE:+--base "$FINISH_CHECK_BASE"}
bash build/run-changed-checks.sh ${FINISH_CHECK_BASE:+--base "$FINISH_CHECK_BASE"}
base_ref="${FINISH_CHECK_BASE:-$(git merge-base HEAD '@{upstream}' 2>/dev/null || git rev-parse HEAD^)}"
git log --oneline "$base_ref"..HEAD
git log --format=full "$base_ref"..HEAD
git diff --stat "$base_ref"...HEAD
git diff "$base_ref"...HEAD
while IFS= read -r commit; do git show --check --stat --oneline "$commit"; done < <(git rev-list --reverse "$base_ref"..HEAD)
```

- `FINISH_CHECK_BASE` 可显式指定审查基线。规划器默认纳入提交范围、暂存区、工作区和未跟踪文件；分支领先 upstream 时从 merge-base 检查，只有工作区变更时从 `HEAD` 检查，完全干净时回退 `HEAD^`，不得产生空审查范围。
- 规划器把直接变更包与导入它们的反向依赖一起作为测试/lint 目标。生产 Go 代码只做 changed-line 变异；关键包测试变更时独立跑稳定哨兵；混合变更两项都跑。`go.mod`/`go.sum`、平台标签、共享契约、大影响面和 `--full` 只升级普通测试、lint 与构建，不升级全量变异。可先加 `--plan-only` 审查路由。
- 确认没有密钥、凭据、构建产物、调试代码、意外删除、无关改动、异常提交主题或 AI 署名。
- 检查 `deploy-spec.md` 是否被修改；若修改，必须走统一多仓同步/审计流程，单仓 CI 不拉取其他仓库移动分支比较。
- 真实发布、上传节点、Git tag、GitHub Release/PR 不属于 finish-check，除非用户另行明确授权。

## 1. 确定性治理门禁

```bash
bash build/check-agent-config.sh
bash build/test-release.sh
bash build/test-check-planner.sh
bash build/test-mutation.sh
bash -n build/build.sh build/generate-keys.sh build/sign-release.sh build/release.sh build/check-agent-config.sh build/test-release.sh build/run-changed-checks.sh build/run-mutation.sh build/test-check-planner.sh build/test-mutation.sh
git diff --check
```

`run-changed-checks.sh` 只在相关文件变化时执行对应契约脚本；上面的全集用于修改完成检查基础设施本身时。门禁必须验证固定 `CLAUDE.md`、Skill 路由、薄工具入口、发布结构，以及 mutation 版本、RAM 文件系统、稳定哨兵、定向路由与 CI 入口没有漂移。

## 2. 构建与版本注入

只有规划结果 `go.build_all=true`、显式 `--full` 或正式发布前才执行三平台构建；输出放临时目录，避免复用 `dist/`：

```bash
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
bash build/build.sh 0.0.0-test.1 "$tmp_dir"
find "$tmp_dir" -maxdepth 1 -type f -print | sort
```

必须生成三份固定 gzip 资产及对应未压缩二进制。在 Linux amd64 宿主直接解压代表资产并运行 `--version`；其他宿主使用相同 ldflags 额外构建本机临时二进制并运行，确认注入值为 `0.0.0-test.1`。交叉编译只证明三平台可构建，不冒充异平台运行证据。

## 3. Go 测试、竞态与覆盖率

定向模式对直接包及反向依赖执行 `go test -race -count=1` 和覆盖率；全量模式才对 `./...` 执行。具体包集合以规划器的 `go.test_packages` 为准，覆盖率文件写入临时目录。

整体覆盖率基线为 53.5%；显著下降必须解释并补测试。沙箱若阻止 Go cache 或 `httptest` loopback，需在允许缓存与 loopback 的环境原样重跑，不能改代码或弱化测试迁就环境。

Go 生产代码或测试发生变化时，还必须运行计划内的 RAM 盘隔离变异门禁：

```bash
make mutation
```

门禁固定使用 `gomutants v0.6.0`。changed-line 中 `LIVED`、`NOT COVERED`、超时和基础设施错误必须为零；稳定哨兵必须精确命中一个 mutant 且为 `KILLED`。两类任务共享 20 分钟硬截止时间。运行器必须确认底层为 tmpfs/RAM Disk，并把工作区副本、Git 索引、Go build cache、临时文件、运行时 cache 与详细报告放在其中；模块 cache 持久复用以避免重复下载，小型 gomutants cache 只在结束时原子写回一次。不得直接反复改写真实工作区，也不得用磁盘临时目录冒充内存盘。

## 4. 双平台静态检查

Linux 与 Windows lint 都只检查规划器给出的直接包和反向依赖；全量风险或正式发布前才使用 `./...`。不得用无依据的 `nolint` 绕过。

格式化已由 `.golangci.yml` 的 `formatters: gofmt` 门禁执行，未格式化会计入 issue 使本命令退出非零，`golangci-lint fmt` 可原地修复。CI 与本地都应使用 go.mod 钉死的 Go 1.26（`build/build.sh` 会强校验 `go1.26.x`）。

Go 工具链精确版本由 `go.mod` 的 `toolchain`、CI 和容器测试桩共同固定；升级时必须同步这些入口及发布契约测试。

## 5. 领域审查

按 `skills/SKILL.md` 路由复核受影响领域：

- 部署链：成功必须代表实际生效；部分失败退出非零；test/reload 失败回滚；回调、pending 私钥、order_id、到期元数据与共享续签锁保持契约。
- 安全：命令白名单、SSRF/DNS rebinding、路径/符号链接、原子写、权限、日志脱敏和 Ed25519 防降级未被削弱。
- 跨平台：Linux/Windows build tag、服务生命周期和文件替换语义同步；交叉编译不冒充真实 Windows 运行证据。
- 发布：三项正式资产、一次构建、持久 bundle、不可变 main、中断恢复、全节点一致性和 release gates 均由脚本测试与静态门禁覆盖。

## 6. Docker E2E release gate

规划器检测到部署链生产代码、发布相关或 Docker 语义变更时运行：

```bash
bash docker/test/scripts/run-tests-contract-test.sh
bash docker/test/scripts/run-tests.sh
```

完整门禁包括 Nginx/Apache × ubuntu/debian/alpine/rocky 的 8 个常规任务和 DinD；`--no-dind` 仅用于调试。异步 daemon 用例必须分别等待操作启动和目标回调完成，不能把请求开始当作业务完成。

仅文档/智能体路由或不触及运行代码的脚本治理可将 Docker E2E 标为不适用。交叉编译不能替代真实 Docker E2E；规划器命中部署链时 `run-changed-checks.sh` 会先跑契约测试再跑完整 E2E。

## 7. 最终复核与提交前证据

```bash
git diff --check
git status --short --branch
git diff --stat
git diff
git diff --stat "$base_ref"...HEAD
git log --oneline "$base_ref"..HEAD
git log --format=full "$base_ref"..HEAD
git log -8 --oneline
```

逐条对照用户需求和 `deploy-spec.md` 受影响条款；只在所有适用命令本轮退出 0 后声明完成。提交前再次确认当前分支和授权范围；提交后检查 commit 内容与工作区状态。除非用户明确要求，不推送。

正式发布前必须执行 `make finish-check-full`，获得全量 Go test/race/coverage、双平台 lint 和三平台构建的新鲜证据；mutation 仍只检查本次生产代码 changed lines 和受影响关键包的稳定哨兵，并受同一个 20 分钟硬截止时间约束。不得用全量变异替代对变更代码的严格门禁，也不得声称它证明了历史代码的全部测试质量。
