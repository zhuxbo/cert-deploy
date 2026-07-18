# sslctl 项目智能体规则

sslctl 是 Go 实现的跨平台 SSL 证书部署工具，支持 Linux/Windows、Nginx/Apache 与 Docker 场景。

## 不可违反的规则

- 始终用中文回复；只处理当前仓库。
- `deploy-spec.md` 是跨仓部署、升级、构建和发布行为的统一边界，不得在本仓静默改变其语义。
- 匹配开发、部署、发布或完成检查任务时，先读 `skills/SKILL.md`，再读其路由的叶子资源。
- 正式发布必须从干净且与远端一致的 `main` 精确提交构建一次，使用持久 bundle 恢复；不得覆盖正式 tag、GitHub Release 或正式资产。
- dev 测试版允许从脏工作区快照发布，但不得提交、推送、合并、切分支、创建 tag 或 GitHub Release。
- 未经用户明确要求不得执行真实发布、上传发布节点、创建或移动 tag、创建 GitHub Release/PR、推送分支。
- `main` / `dev` 不自动提交；用户明确要求提交时，提交信息遵循仓库历史的中文 `type: 主题` 风格，不添加 AI 署名。

## 权威入口

- 统一部署规范：`deploy-spec.md`
- Skill 路由：`skills/SKILL.md`
- 构建与签名契约：`skills/build-release.md`
- 发布编排与恢复：`skills/remote-release.md`
- 完成检查：`skills/finish-check.md`
- 用户文档：`README.md`；构建脚本使用说明：`build/README.md`

## 核心命令与平台边界

```bash
go test -race -count=1 ./...
golangci-lint run --timeout=5m ./...
GOOS=windows GOARCH=amd64 golangci-lint run --timeout=5m ./...
bash build/build.sh <version> <output-dir>
bash build/check-agent-config.sh
bash build/test-release.sh
```

正式资产固定为 Linux amd64、Linux arm64、Windows amd64 三份 gzip；签名方式为 Ed25519，签名与 SHA256 以实际公开文件名为 key 写入发布索引。真实 Windows 运行行为和 Docker E2E 不能由交叉编译替代。

## 更新原则

- 只记录长期有效、项目级、会影响智能体行为的规则；临时决策、调试记录、单一模块实现细节不得写入。
- 新增内容先判断职责：跨仓公共行为写入 `deploy-spec.md`，领域知识和工作流写入对应叶子资源，本文只保留入口与项目硬约束，不复制正文。
- 只直接维护 `AGENTS.md`；`CLAUDE.md` 始终保持固定薄入口，不在其中追加项目规则。
- 新增、删除或重命名 skill 时同步更新 `skills/SKILL.md` 及受影响引用。
- 修改后删除失效或重复内容，并检查 `CLAUDE.md` 固定模板、skill 路由、引用路径和确定性防漂移门禁；未经明确需求不得新增全局约束。
