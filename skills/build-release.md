# 构建、签名与发布 bundle

本资源只定义 sslctl 的平台构建、正式资产、签名和 bundle 契约。发布分支、GitHub、远程节点与恢复编排只在 `skills/remote-release.md` 维护；上位语义以 `deploy-spec.md` 第 8 节为准。

## 平台与正式资产

sslctl 使用 Go 1.24、`CGO_ENABLED=0` 和 `./cmd/` 包交叉编译。规范正式资产集合固定为：

| 目标 | 公开文件名 |
| --- | --- |
| linux/amd64 | `sslctl-linux-amd64.gz` |
| linux/arm64 | `sslctl-linux-arm64.gz` |
| windows/amd64 | `sslctl-windows-amd64.exe.gz` |

三份 gzip 是发布节点与 GitHub Release 必须字节一致的完整正式资产集合。`deploy/install.sh`、`deploy/install.ps1` 是发布服务器根入口，随服务器部署同步但不属于版本资产；本仓没有 GitHub-only 附加资产，也不发布独立 `.sha256` 文件。

## 确定性构建

```bash
bash build/build.sh <x.y.z[-prerelease]> <output-dir>
```

- 版本参数必须是不带 `v` 的有效 SemVer；脚本把该值原样注入 `main.version`，运行 `--version` 必须可见。
- `build/release.sh prepare` 为 main 使用目标 commit 的提交时间设置 `SOURCE_DATE_EPOCH`；`build.sh` 使用固定时间、`-trimpath`、`-buildvcs=false`、无时间戳 gzip，保证同提交、同 Go 工具链的产物可重建验证。
- 正式发布仍只允许构建一次；可重建性用于审计，tag 创建后的恢复禁止重建。
- 输出目录必须由调用者显式指定。发布流程不得依赖或混入仓库 `dist/` 的旧文件。

## SHA256 与 Ed25519

每份 gzip 先计算 `sha256:<hex>`，再使用 `build/sign-release.sh` 对 gzip 原始字节生成 `ed25519:<key-id>:<base64>`。`checksums` 与 `signatures` 都以公开文件名为 key。

签名密钥由 `build/release.conf` 的 `SIGN_KEY`、`SIGN_KEY_ID` 提供；正式发布和 dev 发布都必须签名，缺少密钥或签名失败即停止。签名脚本还会确认私钥派生公钥与 `pkg/upgrade/installer.go` 中同 key ID 的客户端公钥完全一致，防止产出客户端无法验证的资产。私钥必须离线保管且权限为 0600，绝不进入 bundle、日志或 Git。轮换时先发布同时信任新旧公钥的过渡版本，再切换签名密钥。

## 持久 bundle

`build/release.sh prepare <version> --bundle <absolute-path>` 生成且只生成一次：

```text
<bundle>/
├── manifest.json
└── assets/
    ├── sslctl-linux-amd64.gz
    ├── sslctl-linux-arm64.gz
    └── sslctl-windows-amd64.exe.gz
```

manifest 固定记录：schema、product、version、channel、source_commit、dirty、created_at、build_time、Go 版本、三项资产的 size/SHA256/Ed25519 签名。main 的 `dirty` 必须为 false；dev 必须如实记录 `source_commit` 和 `dirty`。

bundle 路径必须位于不会被 `make clean`、`build/build.sh` 或仓库清理删除的位置。推荐使用仓库外的受控发布目录；`.release-bundles/` 仅适合本地演练并已忽略。tag 创建后，`stage-main`、`promote-main`、`verify-main`、`resume-main` 只接受现有 bundle，均先重新校验 manifest、精确资产集合、大小、SHA256 和签名，不调用构建。

本仓生产拓扑至少配置两个发布节点；脚本不提供单节点发布选项。节点名称、主机、端口和绝对发布目录必须通过安全字符校验，所有节点候选 `releases.json` 字节一致后才允许推进。

## 本地检查

```bash
bash build/check-agent-config.sh
bash build/test-release.sh
bash build/release.sh --dry-run prepare 1.2.3 --bundle /tmp/sslctl-release-1.2.3
```

`test-release.sh` 只使用临时目录、测试密钥和 mock，不联网、不改 Git 引用。真实 Windows 运行、Docker E2E、SSH 节点和公网下载仍需在正式发布窗口按 `skills/remote-release.md` 验证。
