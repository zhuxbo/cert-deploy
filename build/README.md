# 构建与发布脚本

本目录只说明脚本接口。正式资产、签名和 bundle 契约见 `skills/build-release.md`；dev/main 发布编排、Git/GitHub 门禁、恢复和验收见 `skills/remote-release.md`；统一行为边界见 `deploy-spec.md` 第 8 节。

## 脚本职责

| 入口 | 单一职责 |
| --- | --- |
| `build.sh` | 从当前工作树确定性构建三平台二进制与 gzip |
| `sign-release.sh` | 对固定三项 gzip 资产生成 Ed25519 签名 JSON |
| `release_helper.py` | 校验 SemVer/bundle，确定性生成或验证发布索引 |
| `release.sh` | prepare、全节点 staging/promote/verify 和 main resume |
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

配置全部发布节点、SSH、Ed25519 seed、key ID 和 HTTPS 公网入口。`release.conf` 与 `build/keys/` 已忽略，不得提交。

## 安全演练

以下命令不联网、不构建、不改 Git 引用：

```bash
bash build/check-agent-config.sh
bash build/test-release.sh
bash build/release.sh --dry-run prepare 1.2.3 --bundle /tmp/sslctl-v1.2.3
bash build/release.sh --dry-run resume-main 1.2.3 --bundle /tmp/sslctl-v1.2.3
```

不要脱离 `skills/remote-release.md` 直接运行非 dry-run 发布阶段。正式版 tag 创建后的恢复只允许传入原持久 bundle，`resume-main` 不提供构建选项。
