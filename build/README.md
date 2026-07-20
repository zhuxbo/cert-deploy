# 构建与发布脚本

本目录只说明脚本接口。正式资产、签名和 bundle 契约见 `skills/build-release.md`；dev/main 发布编排、Git/GitHub 门禁、恢复和验收见 `skills/remote-release.md`；统一行为边界见 `deploy-spec.md` 第 8 节。

## 脚本职责

| 入口 | 单一职责 |
| --- | --- |
| `build.sh` | 从当前工作树或显式源快照确定性构建三平台二进制与 gzip |
| `sign-release.sh` | 对固定三项 gzip 和完整 manifest 生成/验证 Ed25519 签名 |
| `release_helper.py` | 校验 SemVer/bundle，维护发布索引和 main release-state |
| `release.sh` | prepare、全节点 staging/promote/verify、main resume 和 tag 前 abort |
| `check-agent-config.sh` | 检查智能体、Skill、薄入口和发布结构防漂移 |
| `test-release.sh` | 在临时目录离线测试发布不变量 |
| `generate-keys.sh` | 生成 Ed25519 seed、公钥和客户端公钥代码 |

## 本地构建

输出目录必须显式指定且为空，防止旧产物混入：

```bash
output_dir="$(mktemp -d)"
bash build/build.sh 1.2.3-rc.1 "$output_dir"
```

脚本生成 Linux amd64、Linux arm64、Windows amd64 的未压缩二进制和 gzip。正式发布只取三份固定命名 gzip，不发布独立 `.sha256` 文件。

## 发布配置

```bash
cp build/release.conf.example build/release.conf
chmod 600 build/release.conf
```

配置全部发布节点、SSH、Ed25519 seed 和 key ID；`BUNDLE_ROOT` 仅在 main 正式发布时必需，dev 测试版和节点检查不要求。发布脚本按每个节点域名组合 `https://<SERVER_HOST>/sslctl` 做公网验收，不向安装脚本注入地址。main bundle 必须使用脚本给出的 `<BUNDLE_ROOT>/main/v<version>-<source_commit>` 固定路径。全部发布节点的 `<SERVER_DIR>/.release-state/main/` 是跨 clone 的权威 prepare reservation；本地忽略的 `.release-state/` 只做镜像审计。改变 `BUNDLE_ROOT`、清理工作树或移走 bundle 都不能绕过重复构建门禁。`release.conf` 与 `build/keys/` 已忽略，不得提交。

dev 测试版使用简单入口，脚本按预发布版本自动选择 dev，并在内部依次完成 bundle 构建与全节点发布；`publish-dev` 已包含 SSH 和公网验收：

```bash
bash build/release.sh 0.4.1-beta.3
```

稳定版本会自动识别为 main，但不会由服务器阶段脚本直接发布；正式版仍按 `skills/remote-release.md` 完成 PR、CI/E2E、不可变 tag 和 GitHub Release 编排。分阶段命令保留用于正式发布及 dev 失败恢复。

## 安全演练

以下命令不联网、不构建、不改 Git 引用：

```bash
bash build/check-agent-config.sh
bash build/test-release.sh
bash build/release.sh --dry-run prepare 1.2.3 --bundle /tmp/sslctl-v1.2.3
bash build/release.sh --dry-run resume-main 1.2.3 --bundle /tmp/sslctl-v1.2.3
```

不要脱离 `skills/remote-release.md` 直接运行非 dry-run 发布阶段。正式版 tag 创建后的恢复只允许传入原持久 bundle，`resume-main` 不提供构建选项。tag 前的未完成 prepare 只有在确认版本 tag 和节点正式目录都不存在后，才可显式执行 `abort-main <version> --bundle <原路径>`；该动作删除残留 bundle，但保留 aborted 状态和尝试次数。
