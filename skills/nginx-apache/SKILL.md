# Nginx/Apache 证书部署规范

## Nginx

### 配置文件位置

| 发行版 | 主配置 | 站点配置 |
|-------|-------|---------|
| Ubuntu/Debian | `/etc/nginx/nginx.conf` | `/etc/nginx/sites-enabled/` |
| CentOS/RHEL | `/etc/nginx/nginx.conf` | `/etc/nginx/conf.d/` |
| 宝塔面板 | `/www/server/nginx/conf/nginx.conf` | `/www/server/panel/vhost/nginx/` |

### 证书配置

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # 推荐配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
}
```

### 配置解析

站点扫描时提取的关键信息：

- `server_name`: 域名列表
- `ssl_certificate`: 证书路径
- `ssl_certificate_key`: 私钥路径
- `listen`: 端口和 SSL 标志

四个解析函数（`parseConfigFile`、`parseHTTPConfigFile`、`parseAllConfigFile`、`scanWithNginxT`）共用统一的 `parseServerBlocks()` 引擎，通过 `parseOptions` 参数化差异（如 nginx -T 模式的文件跟踪）。正则表达式在包级别编译一次。

### 相对路径 prefix 解析（nginx 与 Apache 统一机制）

Web 服务器配置里的相对路径（nginx `ssl_certificate cert/xxx.pem`、Apache `SSLCertificateFile ssl/xxx.crt`）的解析基准由**进程启动时的 CWD / 命令行参数 / 编译时 prefix** 决定，跟配置文件自身所在目录无必然关系。面板类启动器常导致与直觉不符：

- nginx：基准 = nginx `prefix`（`nginx -p <path>` / 编译时 `--prefix=<path>` / CWD）
- Apache：基准 = `ServerRoot`（`httpd -d <path>` / 编译时 `HTTPD_ROOT` / CWD）

扫描器必须探测出真实 prefix，才能把相对路径转成绝对路径写入配置，否则证书会被写到错位置导致**静默失败**（部署"成功"但 nginx/Apache 读的仍是旧证书）。

#### nginx 探测链（`internal/nginx/scanner/scanner.go::getNginxPrefix`）

1. `SetPrefixOverride()` 显式 override（CLI `--nginx-prefix`，仅当前进程内存生效，不写配置）
2. `nginx -V` 解析 `--prefix=`（Linux 常见发行版走这条）
3. Windows 上 `Get-CimInstance Win32_Process` 读运行进程命令行的 `-p`
4. Windows `logs/error.log` 启发式（`<nginx_dir>` vs `<nginx_dir>\conf`）
5. 全失败 → 返回 `*sslerrors.PrefixUnknownError{ServerKind: Nginx}`

#### Apache 探测链（`internal/apache/scanner/prefix.go::(*Scanner).getApachePrefix`）

1. `SetPrefixOverride()` 显式 override（CLI `--apache-prefix`）
2. `Scanner.serverRoot`（`DetectApache` 已从 `httpd -V` 读到的 `HTTPD_ROOT`）
3. `getServerRootFromVersion()`—再跑一次 `httpd -V` 解析 `HTTPD_ROOT`，覆盖 `scanWithApacheCtl` 跳过 `DetectApache` 的场景
4. `getServerRootFromProcessCmdline()`—运行进程命令行的 `-d` 参数（Linux 读 `/proc/<pid>/cmdline`，Windows 读 `Get-CimInstance`）
5. Windows `logs/error.log`（以及 `error_log` 无扩展名变体）启发式
6. 全失败 → 返回 `*sslerrors.PrefixUnknownError{ServerKind: Apache}`

#### 共用约束

- 只有 `ssl_certificate`/`ssl_certificate_key`/`SSLCertificateFile`/`SSLCertificateKeyFile`/`SSLCertificateChainFile` 出现相对路径时才触发阻断；绝对路径站点继续正常处理
- `PrefixUnknownError` 必须穿透 `nginxScannerAdapter.Scan`、`apacheScannerAdapter.Scan`、`certops.ScanSites` 三层（全部用 `errors.As` 检查），避免被 Docker 成功结果或另一个服务器类型的扫描掩盖
- CLI 层（`cmd/setup/setup.go::scanSites`、`cmd/main.go::runScan`）捕获错误后调用 `err.RenderHint()` 打印给用户并退出非零码
- 推荐用户把配置里相对路径改成绝对路径后重跑，根治歧义；`--nginx-prefix` / `--apache-prefix` 只是临时逃生口，不持久化到 config.json
- 渲染文本根据 `ServerKind` 分支：指令名（`ssl_certificate` vs `SSLCertificateFile`）、验证命令（`nginx -t` vs `apachectl configtest`）、flag 名都不一样；格式由 `pkg/errors/scan.go::RenderHint` 控制，有测试锁定必含段落
- Nginx `ScanAll` 遇 `PrefixUnknownError` 不回退到文件扫描（回退会丢失错误信息），直接向上抛；文件扫描路径末尾同样经过 `resolveSitePaths` 统一处理
- Apache `ScanAll` 两条路径（`apachectl -S` 和文件扫描）末尾都经过 `resolveSitePaths`

### 重载服务

所有重载命令通过 `internal/executor` 包执行，使用白名单机制：

```go
import "github.com/zhuxbo/sslctl/internal/executor"

// 白名单中的命令
executor.Run("nginx -t")
executor.Run("nginx -s reload")
executor.Run("systemctl reload nginx")
```

支持的 Nginx 命令：
- `nginx -t`, `nginx -s reload`
- `systemctl reload/restart nginx`
- `service nginx reload/restart`
- `rc-service nginx reload/restart`

---

## Apache

### 配置文件位置

| 发行版 | 主配置 | 站点配置 |
|-------|-------|---------|
| Ubuntu/Debian | `/etc/apache2/apache2.conf` | `/etc/apache2/sites-enabled/` |
| CentOS/RHEL | `/etc/httpd/conf/httpd.conf` | `/etc/httpd/conf.d/` |
| 宝塔面板 | `/www/server/apache/conf/httpd.conf` | `/www/server/panel/vhost/apache/` |

### 证书配置

```apache
<VirtualHost *:443>
    ServerName example.com

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/privkey.pem
    SSLCertificateChainFile /path/to/chain.pem

    # 推荐配置
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
</VirtualHost>
```

> **ServerName 端口/scheme 剥离**：Apache `ServerName` 语法为 `[scheme://]fqdn[:port]`，`httpd-ssl.conf` 默认模板常写成 `ServerName www.example.com:443`。扫描器（`parseConfigFile`/`parseHTTPConfigFile`/`parseAllConfigFile`、`apachectl -S` 富化路径 `enrichSiteFromConfig`、Docker 扫描器）与安装器（`installer`）在解析 `ServerName`/`ServerAlias`、去引号后统一调用 `matcher.StripPort()` 剥离 scheme 与端口，得到纯域名再做匹配与证书目录命名。否则带端口的 `ServerName` 会导致域名匹配失败（"未找到可绑定的站点"），且 `:` 在 Windows 上是非法路径字符，会污染 `certs/{server_name}/` 目录创建。Nginx 的 `server_name` 与 `listen` 端口分开，无此问题。

### 重载服务

所有重载命令通过 `internal/executor` 包执行，使用白名单机制：

```go
import "github.com/zhuxbo/sslctl/internal/executor"

executor.Run("apachectl -t")
executor.Run("apachectl graceful")
executor.Run("systemctl reload apache2")
```

支持的 Apache 命令：
- `apachectl -t/graceful/restart`
- `apache2ctl -t/graceful/restart`
- `httpd -t`
- `systemctl reload/restart apache2/httpd`
- `service apache2/httpd reload/restart`
- `rc-service apache2/httpd reload/restart`

---

## 证书文件

### 文件类型

| 文件 | 内容 | 用途 |
|-----|------|------|
| `cert.pem` | 服务器证书 | 主证书 |
| `privkey.pem` | 私钥 | 解密 |
| `chain.pem` | 中间证书链 | 验证链 |
| `fullchain.pem` | 证书 + 中间链 | Nginx 推荐 |

### 默认存储路径

```
/opt/sslctl/certs/{domain}/
├── cert.pem
├── privkey.pem
├── chain.pem
└── fullchain.pem
```

### 权限设置

```bash
chmod 644 cert.pem chain.pem fullchain.pem
chmod 600 privkey.pem
chown root:root /opt/sslctl/certs/
```

---

## 部署流程

1. 从 API 获取证书（PEM 格式）
2. 保存证书文件到本地
3. 更新 Web 服务器配置（如需要）
4. 测试配置语法
5. 重载服务
6. 验证证书生效
7. 发送回调通知

### 证书写入顺序与校验

- **先写私钥后写证书**（nginx/apache deployer）：中途失败不留下"新证书 + 旧私钥"的错配状态。
- **中间证书校验**：API 部署必须包含中间证书（缺失报错、等待下一周期重试）；`deploy local` 的 `--ca` 参数仍可选。

### 回滚

部署前备份旧证书：

```bash
/opt/sslctl/backup/{domain}/{timestamp}/
├── cert.pem
├── privkey.pem
└── ...
```

所有部署入口（setup/deploy/续签）覆盖站点证书前先备份、失败自动回滚；回滚用文件操作带符号链接防护。

---

## SSL 配置自动安装（setup）

setup 流程为**未启用 SSL** 的站点安装 HTTPS 配置（需用户确认），备份原配置、配置测试失败自动回滚。

- 支持 `server\n{` 多行格式；SSL 指令仅插入 server 块顶层，兼容 `root` 写在 `location` 内的 SPA / 反代配置。
- **nginx**：仅向 `server_name` 匹配目标站点、且尚未配置 SSL 的 `:80` 块注入证书（已配 SSL 的块跳过防 duplicate listen）。"已配置 SSL"检测与注入共用同一匹配谓词（lower + 通配符），避免同文件多域名块被统一注入。
- **Apache**：生成 `:443` VirtualHost 时按地址 token 精确替换端口，仅端口恰为 80 才换，`*:8080` 等自定义端口不受污染。

### 安装器失败语义

- SSL 配置安装失败的绑定标记 `Enabled=false` 后跳过部署并计入失败（单证书与批量模式一致），不误报"部署成功"。
- nginx 安装器在非 80 端口 / 无可处理 HTTP server 块时返回明确错误而非静默跳过，与 Apache 一致；安装器"无可注入块"必须报错而非返回 `Modified=false`。

## Docker 站点部署（setup/deploy）

- 证书写入**宿主机侧挂载路径**（`HostCertPath`，非容器内路径）。
- test/reload 使用容器化命令：`docker exec <容器> nginx -t` / `nginx -s reload`（apache 用 `apachectl`）；executor 放行 `docker exec <容器> <固定命令>`（容器名字符白名单 + 内层命令白名单）；base deployer 对 docker exec 命令跳过宿主机 SIGUSR1 / 进程重启回退。
- 非挂载卷（copy 模式）或缺容器重载命令时 `config.ValidateDockerBinding` 返回明确错误、如实计为失败，不再静默写错位置报成功。旧版本 setup 创建的存量绑定升级后持续报失败属预期，需重跑 setup 补齐容器命令与卷校验（见根 `README.md`「存量 Docker 绑定升级说明」）。
- Apache 容器内仅 `httpd`/`apache2ctl` 时 reload 明确报错，自动探测待后续支持。
- **挂载路径精确匹配**：Docker 挂载路径按精确匹配，防止 `/etc/nginx` 匹配到 `/etc/nginx-backup`。

## 扫描防护

Nginx / Apache / Docker 扫描器均有文件数量限制 1000 + 目录深度限制 100 + 单文件大小限制 10MB，防止异常配置树拖垮扫描。

---

## 常见问题

### 证书链不完整

症状：浏览器报证书错误，但证书本身有效

解决：确保 `fullchain.pem` 包含中间证书

**Nginx fullchain 拼接逻辑**：仅当 intermediate 非空时拼接（`cert + "\n" + intermediate`），防止空中间证书导致尾部多余换行。

**通配符匹配**：统一使用 `pkg/matcher.MatchDomain`（支持精确匹配和单级子域名通配符匹配，如 `*.example.com` 匹配 `www.example.com` 但不匹配 `a.b.example.com`）。

### 权限问题

症状：Nginx/Apache 无法读取证书

解决：检查文件权限，私钥应为 600

### 配置语法错误

症状：重载失败

解决：先执行 `nginx -t` 或 `apachectl configtest`
