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

> **ServerName 端口/scheme 剥离**：Apache `ServerName` 语法为 `[scheme://]fqdn[:port]`，`httpd-ssl.conf` 默认模板常写成 `ServerName www.example.com:443`。扫描器（`parseConfigFile`/`parseHTTPConfigFile`/`parseAllConfigFile`、Docker 扫描器）与安装器（`installer`）在解析 `ServerName`/`ServerAlias`、去引号后统一调用 `matcher.StripPort()` 剥离 scheme 与端口，得到纯域名再做匹配与证书目录命名。否则带端口的 `ServerName` 会导致域名匹配失败（"未找到可绑定的站点"），且 `:` 在 Windows 上是非法路径字符，会污染 `certs/{server_name}/` 目录创建。Nginx 的 `server_name` 与 `listen` 端口分开，无此问题。

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

### 回滚

部署前备份旧证书：

```bash
/opt/sslctl/backup/{domain}/{timestamp}/
├── cert.pem
├── privkey.pem
└── ...
```

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
