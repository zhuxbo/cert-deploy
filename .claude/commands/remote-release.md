# 远程发布 sslctl

输入版本号: $ARGUMENTS

## 版本号处理

- **不要添加 `v` 前缀**，`build/release.sh` 内部会自动加
- 如果用户输入了 `v` 前缀，先去除（脚本对带 v / 不带 v 都接受，但保持一致避免歧义）
- 格式：`X.Y.Z`（正式版）或 `X.Y.Z-beta` / `X.Y.Z-alpha` / `X.Y.Z-rc.1`（预发布版）
- 允许重复发布同一版本（服务器上覆盖；释放清单 `releases.json` 幂等）

## 通道判定

`build/release.sh` 内 `get_channel()` 逻辑：

- 含 `-`（任意后缀） → **`dev` 通道**，可在任意分支发布
- 不含 `-` → **`main` 通道**，本流程强制要求当前在 main 分支且与 origin 同步

## 关键事实（与其他项目不同）

- `build/release.sh` **本身不强制**当前分支、工作区干净度、origin 同步状态——这些由本指令在跑脚本前显式校验
- `build/release.sh` 中的 `ensure_tag` 仅在 tag **不存在**时创建，**不会移动现有 tag**；`latest` 移动 tag 必须手工 `-f` 推送
- 脚本会跑 `bash build/build.sh <版本号>` 三平台交叉编译 + Ed25519 签名（`build/keys/release-key.pem`），失败则中止
- 上传到 `build/release.conf` 中配置的所有服务器（当前 cn + us），`KEEP_VERSIONS` 控制每通道保留版本数（默认 5）

## 执行步骤

### 1. 验证版本号与凭据

- 去除 `v` 前缀（如有）
- 校验格式：必须匹配 `^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$`
- 未提供则中止并提示用户输入
- 检查 `build/release.conf` 与 `build/keys/release-key.pem` 存在（前者权限应为 600）

### 2. 预飞：测试 SSH 连通性

```bash
bash build/release.sh --test
```

任一服务器失败则中止流程，提示用户检查 `release.conf` 或网络。

### 3. 预发布版（dev 通道）

任意分支均可发布，无需 tag、无需合并 main。

```bash
bash build/release.sh <版本号>
```

完成后留在当前分支。**不创建** v tag、**不移动** latest tag。

### 4. 正式版（main 通道）

#### 4.1 强制前置校验

按顺序检查并中止任意一项失败：

1. 当前分支 = `main`（若在 dev 提示走「合并流程」，见 4.2；其他分支直接报错退出）
2. 工作区干净：`git status --porcelain` 输出为空
3. `git fetch origin`
4. 本地 `main` HEAD == `origin/main` HEAD（落后 → 提示 pull；领先 → 提示先推送或反查异常提交）

#### 4.2 合并 dev → main（仅当当前在 dev 且 dev 领先 main 时）

```bash
# 1. 推送 dev 最新提交（若已同步则空操作）
git push origin dev

# 2. 创建 PR
gh pr create --base main --head dev \
  --title "Release v<版本号>" \
  --body "$(参考 PR #14 的「Summary + Commits」格式生成)"

# 3. 合并（沿用历史风格 --merge，保留 merge commit 便于打 tag）
gh pr merge <PR编号> --merge --subject "Merge pull request #<PR编号> from zhuxbo/dev" --body "Release v<版本号>"

# 4. 切到 main 同步
git checkout main
git pull --ff-only
```

PR body 应总结从上一个正式版 tag 到 dev 顶端的提交：

```bash
git log $(git describe --tags --abbrev=0 origin/main)..origin/dev --oneline
```

按主题归类（feat / fix / docs / refactor / test / ci）写成 Summary + Commits 两段。

#### 4.3 打 tag 并推送

```bash
# 1. 在当前 main HEAD 打版本 tag
git tag -a v<版本号> -m "Release v<版本号>"
git push origin v<版本号>

# 2. 强制移动 latest 移动 tag 到同一 commit
git tag -f latest v<版本号>
git push -f origin latest
```

⚠️ `latest` 是项目唯一允许 force-push 的 tag（移动 tag 语义），其余 `vX.Y.Z` 一旦推送禁止 force-push。

#### 4.4 执行远程发布

```bash
bash build/release.sh <版本号>
```

脚本会：

1. 再次确认 SSH 连通性
2. 跑 `build/build.sh <版本号>`：三平台编译（linux/amd64、linux/arm64、windows/amd64）+ gzip 压缩
3. 跑 `build/sign-release.sh`：Ed25519 签名所有 `.gz` 产物
4. rsync 上传到每台服务器的 `<release_dir>/main/v<版本号>/`
5. 远端 Python 内联脚本更新 `releases.json`：`main.latest = <版本号>`，`main.versions[]` 头部插入新版（保留最近 KEEP_VERSIONS 个）
6. 远端 ssh 执行：维护 `<release_dir>/main/latest/` 软链接目录指向新版
7. 远端清理超出保留数的旧版本目录

**任意服务器失败 → 整体退出码非零，需要排查后用 `--server <名称>` 重试单台**。

#### 4.5 同步 main 回 dev + 验证

```bash
# 把 merge commit 同步到 dev，避免下次 PR 出现「main 比 dev 新」
git checkout dev
git merge --ff-only main
git push origin dev

# 留在 dev 继续后续开发
```

`--ff-only` 失败说明 dev 在合并 PR 后又有新提交，改用 `git merge main` 解冲突。

线上验证（任一服务器 host 都行，因 `releases.json` 已同步）：

```bash
curl -s https://release.cnssl.com/sslctl/releases.json | python3 -c "import sys, json; d=json.load(sys.stdin); print('main.latest:', d['main']['latest']); print('main versions:', [v['version'] for v in d['main']['versions']])"
```

`main.latest` 应等于刚发布的版本号。

## 使用示例

```
/remote-release 0.3.10-beta    # 预发布版（dev 通道，任意分支可发，不打 tag）
/remote-release v0.3.10-beta   # 自动去除 v 前缀
/remote-release 0.3.10         # 正式版（强制 main 分支 + 干净工作区 + 同步 origin，自动打 v tag + 移动 latest tag）
```

## 高级用法（在 release.sh 层面）

```bash
bash build/release.sh --test                  # 仅测试 SSH 连通性
bash build/release.sh --server cn 0.3.10      # 只发到 cn 服务器（用于单台失败重试）
bash build/release.sh --upload-only 0.3.10    # 跳过构建直接上传 dist/ 现成产物
```

## 注意事项

- **不要在脏工作区发布正式版**：未提交的改动不会进二进制，但版本号会上线，导致用户拿到与 git tag 不一致的代码
- **构建失败立即停止**：`build/build.sh` 在交叉编译失败时返回非零，`release.sh` 不会上传
- **签名密钥保护**：`build/keys/release-key.pem` 权限必须 600，泄漏后须按 `skills/build-release/` 流程轮换并发新版强制升级
- **不要手动删除/重写已发布的 `vX.Y.Z` tag**：客户端 `sslctl upgrade` 会按 tag 拉历史版本并验签，篡改会让历史升级路径破坏
- **`latest` tag 例外**：仅本指令通过 force-push 移动，禁止其他流程改动
- **客户端验证签名**：发布后可用旧版客户端跑 `sslctl upgrade` 验证签名链路是否通；密钥不匹配则 `pkg/upgrade` 会拒绝安装
