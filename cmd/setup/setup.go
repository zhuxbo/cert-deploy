// Package setup 一键部署命令
package setup

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	apacheScanner "github.com/zhuxbo/sslctl/internal/apache/scanner"
	nginxScanner "github.com/zhuxbo/sslctl/internal/nginx/scanner"
	"github.com/zhuxbo/sslctl/pkg/config"
	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/service"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// setupParams 保存 setup 命令的通用参数
type setupParams struct {
	apiURL         string
	token          string
	localKey       bool
	keyFile        string // --key 指定的私钥文件路径
	fileValidation bool   // --file-validation 启用文件验证
	webroot        string // --webroot 指定的 Web 根目录
	yes            bool
	noService      bool
	ctx            context.Context
	cfgManager     *config.ConfigManager
	log            *logger.Logger
}

// Run 运行 setup 命令
func Run(args []string, debug bool) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	apiURL := fs.String("url", "", "证书 API 基础地址")
	token := fs.String("token", "", "API 认证 Token")
	order := fs.String("order", "", "订单 ID 或批量查询（支持 ID/域名/逗号分隔混合，不传则查询全部）")
	localKey := fs.Bool("local-key", false, "使用本机提交")
	keyFile := fs.String("key", "", "私钥文件路径（隐含 --local-key）")
	fileValidation := fs.Bool("file-validation", false, "启用文件验证（隐含 --local-key）")
	webroot := fs.String("webroot", "", "文件验证的 Web 根目录（隐含 --file-validation）")
	yes := fs.Bool("yes", false, "跳过确认提示")
	noService := fs.Bool("no-service", false, "不安装守护服务")
	nginxPrefix := fs.String("nginx-prefix", "", "显式指定 nginx 相对路径解析基准（仅本次生效，不写入配置）")
	apachePrefix := fs.String("apache-prefix", "", "显式指定 Apache ServerRoot 解析基准（仅本次生效，不写入配置）")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法:\n")
		fmt.Fprintf(os.Stderr, "  sslctl setup --url <base_url> --token <token> --order <order_id>          # 单证书部署\n")
		fmt.Fprintf(os.Stderr, "  sslctl setup --url <base_url> --token <token> --order \"123,example.com\"    # 批量部署\n")
		fmt.Fprintf(os.Stderr, "  sslctl setup --url <base_url> --token <token>                             # 部署所有证书\n")
		fmt.Fprintf(os.Stderr, "  sslctl setup --key /path/key.pem --webroot /var/www/html --url <url> ...  # 指定私钥+文件验证\n")
		fmt.Fprintf(os.Stderr, "\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// 隐含关系推导：--webroot → --file-validation → --local-key，--key → --local-key
	if *webroot != "" {
		*fileValidation = true
	}
	if *fileValidation || *keyFile != "" {
		*localKey = true
	}

	// 校验 --webroot 路径
	if *webroot != "" {
		if fi, err := os.Stat(*webroot); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "--webroot 路径不存在或不是目录: %s\n", *webroot)
			os.Exit(1)
		}
	}

	if *apiURL == "" || *token == "" {
		fs.Usage()
		os.Exit(1)
	}

	// --nginx-prefix / --apache-prefix 仅在本次进程内生效，影响扫描器的相对路径解析
	if *nginxPrefix != "" {
		nginxScanner.SetPrefixOverride(*nginxPrefix)
	}
	if *apachePrefix != "" {
		apacheScanner.SetPrefixOverride(*apachePrefix)
	}

	if err := util.CheckRootPrivilege(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// 创建配置管理器
	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 检查是否已有配置（重复运行时保留 Schedule 等用户自定义设置）
	if existingCfg, loadErr := cfgManager.Load(); loadErr == nil && len(existingCfg.Certificates) > 0 {
		fmt.Println("检测到已有配置，将更新证书配置（保留 Schedule 等设置）")
	}

	// 初始化日志
	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(logDir, "debug")
	}
	log, err := logger.New(logDir, "setup")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	params := &setupParams{
		apiURL:         *apiURL,
		token:          *token,
		localKey:       *localKey,
		keyFile:        *keyFile,
		fileValidation: *fileValidation,
		webroot:        *webroot,
		yes:            *yes,
		noService:      *noService,
		ctx:            context.Background(),
		cfgManager:     cfgManager,
		log:            log,
	}

	// 路由：纯数字走单订单旧路径，其他走批量
	orderStr := strings.TrimSpace(*order)
	if orderID, err := strconv.Atoi(orderStr); err == nil && orderID > 0 {
		runSingle(params, orderID)
	} else {
		runBatch(params, orderStr)
	}
}

// runSingle 单证书部署（保持原有 7 步流程）
func runSingle(p *setupParams, orderID int) {
	p.log.Info("开始 setup: order_id=%d, api_url=%s", orderID, p.apiURL)

	// 1. 检测 Web 服务器
	fmt.Println("步骤 1/7: 检测 Web 服务器...")
	serverType := webserver.DetectWebServerType()
	if serverType == "" {
		fmt.Fprintln(os.Stderr, "未检测到 Nginx 或 Apache 服务")
		os.Exit(1)
	}
	fmt.Printf("  检测到: %s\n", serverType)

	// 2. 获取证书信息
	fmt.Println("\n步骤 2/7: 获取证书信息...")
	f := fetcher.New(30 * time.Second)
	certData, _, err := f.QueryOrder(p.ctx, p.apiURL, p.token, orderID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询订单失败: %v\n", err)
		os.Exit(1)
	}

	// 订单续费后 API 返回新订单号
	if certData.OrderID > 0 && certData.OrderID != orderID {
		fmt.Printf("  订单已续费，使用新订单号: %d -> %d\n", orderID, certData.OrderID)
		orderID = certData.OrderID
	}

	if certData.Status != "active" || certData.Cert == "" {
		fmt.Fprintf(os.Stderr, "证书未就绪: status=%s\n", certData.Status)
		os.Exit(1)
	}

	// 从证书中解析域名（比 API 返回的域名更准确）
	certValidator := validator.New("")
	parsedCert, err := certValidator.ValidateCert(certData.Cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "证书验证失败: %v\n", err)
		os.Exit(1)
	}

	// 从证书提取域名：合并 CN + SAN（DNSNames + IPAddresses），去重
	certDomains := extractDomainsFromCert(parsedCert)
	if len(certDomains) == 0 {
		fmt.Fprintln(os.Stderr, "证书缺少域名信息（CN 和 SAN 均为空）")
		os.Exit(1)
	}

	// 如果 API 返回了私钥，立即验证匹配
	if certData.PrivateKey != "" {
		if err := certValidator.ValidateCertKeyPair(certData.Cert, certData.PrivateKey); err != nil {
			fmt.Fprintf(os.Stderr, "  API 返回的私钥与证书不匹配: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("  ✓ API 私钥验证通过")
	}

	fmt.Printf("  订单 ID: %d\n", certData.OrderID)
	fmt.Printf("  证书域名: %s\n", strings.Join(certDomains, ", "))

	// 3. 扫描站点并匹配
	fmt.Println("\n步骤 3/7: 扫描站点...")
	sites := scanSites(serverType, p.log)
	if len(sites) == 0 {
		fmt.Fprintln(os.Stderr, "未发现站点配置")
		os.Exit(1)
	}
	fmt.Printf("  发现 %d 个站点\n", len(sites))

	// 匹配域名
	m := matcher.New(certDomains)
	fullMatch, partialMatch, _ := m.MatchSites(sites)

	var bindings []config.SiteBinding
	var needSSLInstall []*matcher.ScannedSiteInfo
	hasDockerNonVolume := false

	// 处理完全匹配
	for _, smr := range fullMatch {
		site := smr.Site
		fmt.Printf("\n  ✓ 完全匹配: %s\n", site.ServerName)
		if !site.HasSSL {
			fmt.Printf("    站点未启用 SSL，部署时将安装 HTTPS 配置\n")
			if !p.yes {
				if !confirm("    是否安装 HTTPS 配置?") {
					continue
				}
			}
			needSSLInstall = append(needSSLInstall, site)
		}
		if site.ContainerID != "" && !site.VolumeMode {
			hasDockerNonVolume = true
		}
		bindings = append(bindings, createBinding(site, p.cfgManager))
	}

	// 处理部分匹配
	for _, smr := range partialMatch {
		site := smr.Site
		fmt.Printf("\n  ~ 部分匹配: %s\n", site.ServerName)
		fmt.Printf("    匹配域名: %s\n", strings.Join(smr.Result.MatchedDomains, ", "))
		fmt.Printf("    未覆盖域名: %s\n", strings.Join(smr.Result.MissedDomains, ", "))

		if !p.yes {
			if !confirm("    是否绑定此站点?") {
				continue
			}
		}

		if !site.HasSSL {
			fmt.Printf("    站点未启用 SSL，部署时将安装 HTTPS 配置\n")
			if !p.yes {
				if !confirm("    是否安装 HTTPS 配置?") {
					continue
				}
			}
			needSSLInstall = append(needSSLInstall, site)
		}
		if site.ContainerID != "" && !site.VolumeMode {
			hasDockerNonVolume = true
		}
		bindings = append(bindings, createBinding(site, p.cfgManager))
	}

	if len(bindings) == 0 {
		fmt.Fprintln(os.Stderr, "\n未找到可绑定的站点")
		os.Exit(1)
	}

	// 校验验证方式与域名兼容性（在部署前检查，避免部署后配置保存失败导致状态不一致）
	if p.fileValidation {
		for _, domain := range certDomains {
			if errMsg := config.ValidateValidationMethod(domain, config.ValidationMethodFile); errMsg != "" {
				fmt.Fprintf(os.Stderr, "域名 %s: %s\n", domain, errMsg)
				os.Exit(1)
			}
		}
		// --file-validation 无 --webroot 时，检查至少一个绑定有扫描到的 webroot
		if p.webroot == "" {
			hasWebroot := false
			for _, b := range bindings {
				if b.Paths.Webroot != "" {
					hasWebroot = true
					break
				}
			}
			if !hasWebroot {
				fmt.Fprintln(os.Stderr, "未扫描到 webroot，请使用 --webroot 指定")
				os.Exit(1)
			}
		}
	}

	// 4. 验证私钥
	fmt.Println("\n步骤 4/7: 验证私钥...")
	privateKey, err := getAndValidatePrivateKey(p.keyFile, bindings, certData, certValidator, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  ✓ 私钥验证通过")

	// 验证中间证书
	if certData.IntermediateCert == "" {
		fmt.Fprintln(os.Stderr, "中间证书为空，无法部署")
		os.Exit(1)
	}

	// 确认部署
	if !p.yes {
		fmt.Printf("\n将部署证书到 %d 个站点:\n", len(bindings))
		for _, b := range bindings {
			fmt.Printf("  - %s (%s)\n", b.ServerName, b.ServerType)
		}
		// Windows 非服务模式提示：部署过程需要重启进程，会短暂中断服务
		if runtime.GOOS == "windows" {
			if name := processRestartServerName(bindings); name != "" {
				fmt.Printf("\n  ⚠ %s 未注册为系统服务，部署过程将通过重启进程重载配置，服务会短暂中断数秒\n", name)
			}
		}
		if !confirm("\n确认部署?") {
			fmt.Println("已取消")
			os.Exit(0)
		}
	}

	// 5. 部署证书
	fmt.Println("\n步骤 5/7: 部署证书...")
	certName := buildCertName(certDomains[0], orderID)

	// 创建证书配置（API 配置写入证书级别）
	certConfig := &config.CertConfig{
		CertName: certName,
		OrderID:  orderID,
		Enabled:  true,
		Domains:  certDomains,
		API: config.APIConfig{
			URL:   p.apiURL,
			Token: p.token,
		},
		Bindings: bindings,
	}

	// 为未启用 SSL 的站点安装 HTTPS 配置（先写入证书文件，再安装配置，避免 nginx -t 失败）
	for _, site := range needSSLInstall {
		var binding *config.SiteBinding
		for i := range bindings {
			if bindings[i].ServerName == site.ServerName {
				binding = &bindings[i]
				break
			}
		}
		if binding == nil || !binding.Enabled {
			continue
		}

		// 先写入证书和私钥文件
		certDir := filepath.Dir(binding.Paths.Certificate)
		if err := util.EnsureDir(certDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "    %s: 创建目录失败: %v\n", site.ServerName, err)
			binding.Enabled = false
			continue
		}

		fullchain := certData.Cert
		if certData.IntermediateCert != "" {
			fullchain += "\n" + certData.IntermediateCert
		}
		if err := util.AtomicWrite(binding.Paths.Certificate, []byte(fullchain), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "    %s: 写入证书失败: %v\n", site.ServerName, err)
			binding.Enabled = false
			continue
		}
		if err := util.AtomicWrite(binding.Paths.PrivateKey, []byte(privateKey), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "    %s: 写入私钥失败: %v\n", site.ServerName, err)
			binding.Enabled = false
			continue
		}

		// 安装 SSL 配置（此时 nginx -t 可以加载已写入的证书文件）
		result, err := installSSLConfig(site, p.cfgManager)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    %s: 安装 SSL 配置失败: %v\n", site.ServerName, err)
			binding.Enabled = false
			continue
		}
		if result.Modified {
			fmt.Printf("    ✓ %s: SSL 配置已安装（备份: %s）\n", site.ServerName, result.BackupPath)
			updateSiteAfterInstall(site, p.cfgManager)
		}
	}

	// 部署到每个绑定
	var successCount, failCount int
	var failedSites []string
	for i := range bindings {
		binding := &bindings[i]
		fmt.Printf("  部署到: %s\n", binding.ServerName)

		if err := deployToSiteBinding(p.ctx, binding, certData, privateKey, p.log); err != nil {
			fmt.Fprintf(os.Stderr, "    部署失败: %v\n", err)
			failCount++
			failedSites = append(failedSites, binding.ServerName)
			binding.Enabled = false // 标记失败绑定为禁用，避免守护进程持续重试
			continue
		}
		fmt.Printf("    ✓ 部署成功\n")
		successCount++
	}

	// 全部失败时退出
	if successCount == 0 && failCount > 0 {
		p.log.Error("setup 失败: 所有 %d 个站点部署均失败", failCount)
		fmt.Fprintln(os.Stderr, "\n一键部署失败! 所有站点部署均失败")
		os.Exit(1)
	}

	p.log.Info("setup 部署完成: 成功=%d, 失败=%d", successCount, failCount)

	// 保存配置
	fmt.Println("\n步骤 6/7: 保存配置...")

	// 使用步骤 2 已解析的证书设置元数据
	certConfig.Metadata.CertExpiresAt = parsedCert.NotAfter
	certConfig.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)
	certConfig.Metadata.LastDeployAt = time.Now()

	if p.localKey {
		certConfig.RenewMode = config.RenewModeLocal
	}

	// 验证方式和 webroot（域名兼容性已在部署前校验）
	if p.fileValidation {
		certConfig.ValidationMethod = config.ValidationMethodFile
		if p.webroot != "" {
			for i := range certConfig.Bindings {
				certConfig.Bindings[i].Paths.Webroot = p.webroot
			}
		}
	} else if p.localKey {
		certConfig.ValidationMethod = config.ValidationMethodDelegation
	}

	if err := p.cfgManager.AddCert(certConfig); err != nil {
		fmt.Fprintf(os.Stderr, "保存证书配置失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  配置已保存: %s\n", p.cfgManager.GetConfigPath())

	// 通知服务端是否自动续签（非关键路径，失败仅记录警告）
	notifyAutoReissue(p, f, orderID, certConfig.RenewMode)

	// 7. 安装守护服务
	if !p.noService {
		fmt.Println("\n步骤 7/7: 安装守护服务...")
		if err := installService(); err != nil {
			fmt.Fprintf(os.Stderr, "  安装服务失败: %v\n", err)
			fmt.Println("  可稍后使用 'sslctl service repair' 修复")
		} else {
			fmt.Println("  ✓ 服务已安装并启动")
		}
	} else {
		fmt.Println("\n步骤 7/7: 跳过服务安装 (--no-service)")
	}

	fmt.Println("\n========================================")
	if failCount > 0 {
		fmt.Printf("一键部署部分完成! 成功 %d 个，失败 %d 个\n", successCount, failCount)
		fmt.Printf("失败站点: %s\n", strings.Join(failedSites, ", "))
	} else {
		fmt.Printf("一键部署完成! 共 %d 个站点\n", successCount)
	}
	fmt.Println("========================================")
	fmt.Printf("\n配置文件: %s\n", p.cfgManager.GetConfigPath())
	fmt.Printf("证书目录: %s\n", p.cfgManager.GetCertsDir())

	if !p.noService {
		fmt.Println("\n守护服务命令:")
		if runtime.GOOS == "windows" {
			fmt.Println("  sc query sslctl              # 查看状态")
			fmt.Println("  sslctl status                # 查看证书状态")
		} else {
			fmt.Println("  systemctl status sslctl    # 查看状态")
			fmt.Println("  journalctl -u sslctl -f    # 查看日志")
		}
	}

	if hasDockerNonVolume && successCount > 0 {
		fmt.Println("\n[!] 检测到 Docker 容器站点的证书路径未挂载为卷")
		fmt.Println("    重建容器后需要重新部署证书")
	}
}

// scanSites 扫描站点（使用 webserver 抽象层）
func scanSites(serverType string, log *logger.Logger) []*matcher.ScannedSiteInfo {
	var sites []*matcher.ScannedSiteInfo

	// 确定服务器类型
	wsType := webserver.TypeNginx
	if serverType == "apache" {
		wsType = webserver.TypeApache
	}

	// 使用抽象层创建扫描器
	scanner, err := webserver.NewScanner(wsType)
	if err != nil {
		log.Error("创建扫描器失败: %v", err)
		return sites
	}

	// 扫描站点
	allSites, err := scanner.Scan()
	if err != nil {
		// Prefix 未知是阻塞性错误：打印修复指引并中止，避免写入错误位置
		var prefixErr *sslerrors.PrefixUnknownError
		if errors.As(err, &prefixErr) {
			log.Error("%s prefix 未知，部署中止", serverType)
			fmt.Fprint(os.Stderr, prefixErr.RenderHint())
			os.Exit(1)
		}
		log.Error("扫描 %s 失败: %v", serverType, err)
		return sites
	}

	// 转换为 matcher.ScannedSiteInfo
	for _, site := range allSites {
		sites = append(sites, &matcher.ScannedSiteInfo{
			ServerName:  site.ServerName,
			ServerAlias: site.ServerAlias,
			ConfigFile:  site.ConfigFile,
			HasSSL:      site.CertificatePath != "",
			CertPath:    site.CertificatePath,
			KeyPath:     site.PrivateKeyPath,
			ChainPath:   site.ChainFile,
			ServerType:  string(site.ServerType),
			ContainerID: site.ContainerID,
			VolumeMode:  site.VolumeMode,
		})
	}

	// 合并同域名站点（处理 80/443 分开的 server block）
	sites = mergeSameNameSites(sites)

	return sites
}

// mergeSameNameSites 合并同域名的站点
// 同一域名有多个 server block 时（如 80 和 443 分开），合并为一条，优先保留 SSL 条目的信息
func mergeSameNameSites(sites []*matcher.ScannedSiteInfo) []*matcher.ScannedSiteInfo {
	seen := make(map[string]int) // ServerName -> result 中的索引
	var result []*matcher.ScannedSiteInfo

	for _, site := range sites {
		if idx, exists := seen[site.ServerName]; exists {
			existing := result[idx]
			if site.HasSSL && !existing.HasSSL {
				// 当前条目有 SSL，替换已有的非 SSL 条目
				// 继承非 SSL 条目的 Webroot（HTTP block 通常有 root 指令）
				if site.Webroot == "" && existing.Webroot != "" {
					site.Webroot = existing.Webroot
				}
				result[idx] = site
			} else if !existing.HasSSL || !site.HasSSL {
				// 已有条目有 SSL、当前没有：仅继承 Webroot
				if existing.Webroot == "" && site.Webroot != "" {
					existing.Webroot = site.Webroot
				}
			}
			// 两个都有 SSL：保持已有条目（先出现的优先）
		} else {
			seen[site.ServerName] = len(result)
			result = append(result, site)
		}
	}

	return result
}

// createBinding 创建站点绑定
func createBinding(site *matcher.ScannedSiteInfo, cm *config.ConfigManager) config.SiteBinding {
	// 确定证书路径
	certPath := site.CertPath
	keyPath := site.KeyPath

	// 如果站点没有 SSL 配置，使用默认路径
	if certPath == "" {
		certDir, _ := cm.EnsureSiteCertsDir(site.ServerName)
		certPath = filepath.Join(certDir, "cert.pem")
		keyPath = filepath.Join(certDir, "key.pem")
	}

	binding := config.SiteBinding{
		ServerName: site.ServerName,
		ServerType: site.ServerType,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ConfigFile:  site.ConfigFile,
			Webroot:     site.Webroot,
		},
	}

	// Apache：保留扫描到的 ChainFile 路径（已有 SSLCertificateChainFile 的站点）
	// 新安装 SSL 的站点 ChainPath 为空，使用 fullchain 模式
	if site.ChainPath != "" {
		binding.Paths.ChainFile = site.ChainPath
	}

	// 设置重载命令（根据系统环境动态检测）
	var cmds webserver.ServerCommands
	if site.ServerType == config.ServerTypeNginx {
		cmds = webserver.DetectNginxCommands()
	} else if site.ServerType == config.ServerTypeApache {
		cmds = webserver.DetectApacheCommands()
	}
	if cmds.TestCmd != "" {
		binding.Reload = config.ReloadConfig{
			TestCommand:   cmds.TestCmd,
			ReloadCommand: cmds.ReloadCmd,
		}
	}

	return binding
}

// processRestartServerName 检测是否需要进程重启，返回服务器名称（如 "Apache"/"Nginx"），无需则返回空
func processRestartServerName(bindings []config.SiteBinding) string {
	for _, b := range bindings {
		cmd := b.Reload.ReloadCommand
		if strings.Contains(cmd, "-k ") {
			return "Apache"
		}
		if strings.Contains(cmd, "-s reload") {
			return "Nginx"
		}
	}
	return ""
}

// deployToSiteBinding 部署证书到单个站点绑定
func deployToSiteBinding(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
	// 确保目录存在
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := util.EnsureDir(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 使用 webserver 抽象层创建部署器
	deployer, err := webserver.NewDeployer(
		webserver.ServerType(binding.ServerType),
		binding.Paths.Certificate,
		binding.Paths.PrivateKey,
		binding.Paths.ChainFile,
		binding.Reload.TestCommand,
		binding.Reload.ReloadCommand,
	)
	if err != nil {
		return fmt.Errorf("创建部署器失败: %w", err)
	}

	return deployer.Deploy(certData.Cert, certData.IntermediateCert, privateKey)
}

// installService 安装守护服务
func installService() error {
	svcMgr, err := service.New(nil)
	if err != nil {
		return err
	}

	// 停止现有服务（忽略错误，可能不存在）
	_ = svcMgr.Stop()

	// 安装服务（已存在时自动删除重建）
	if err := svcMgr.Install(); err != nil {
		return err
	}

	// 启用开机启动
	if err := svcMgr.Enable(); err != nil {
		return err
	}

	// 启动服务
	return svcMgr.Start()
}

// installSSLConfig 为未启用 SSL 的站点安装 HTTPS 配置
func installSSLConfig(site *matcher.ScannedSiteInfo, cm *config.ConfigManager) (*webserver.InstallResult, error) {
	// 确定证书路径
	certDir, err := cm.EnsureSiteCertsDir(site.ServerName)
	if err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")

	// Apache 新安装使用 fullchain 模式（cert.pem 包含 cert+intermediate），不生成 SSLCertificateChainFile
	// Nginx 本身就是 fullchain 模式，chainPath 无意义
	chainPath := ""

	// 确定 testCmd（根据站点类型动态检测）
	var testCmd string
	if site.ServerType == config.ServerTypeApache {
		testCmd = webserver.DetectApacheCommands().TestCmd
	} else {
		testCmd = webserver.DetectNginxCommands().TestCmd
	}

	// 创建安装器
	wsType := webserver.ServerType(site.ServerType)
	installer, err := webserver.NewInstaller(wsType, site.ConfigFile, certPath, keyPath, chainPath, site.ServerName, testCmd)
	if err != nil {
		return nil, fmt.Errorf("创建安装器失败: %w", err)
	}

	// 执行安装
	return installer.Install()
}

// updateSiteAfterInstall 安装 SSL 配置后更新站点信息
func updateSiteAfterInstall(site *matcher.ScannedSiteInfo, cm *config.ConfigManager) {
	certDir, err := cm.EnsureSiteCertsDir(site.ServerName)
	if err != nil {
		// EnsureSiteCertsDir 在 installSSLConfig 中已成功调用过，这里不应失败
		return
	}
	site.HasSSL = true
	site.CertPath = filepath.Join(certDir, "cert.pem")
	site.KeyPath = filepath.Join(certDir, "key.pem")
}

// errNeedPrivateKey 表示前 3 个来源均无可用私钥，需要用户提供
var errNeedPrivateKey = errors.New("需要用户提供私钥")

// getAndValidatePrivateKey 获取并验证私钥与证书匹配
// 优先级: 1. API 返回 → 2. --key 指定路径 → 3. 默认路径 → 4. 交互输入路径
// interactive=false 时跳过第 4 步，返回 errNeedPrivateKey
func getAndValidatePrivateKey(keyFile string, bindings []config.SiteBinding, certData *fetcher.CertData, v *validator.Validator, interactive bool) (string, error) {
	// 1. API 返回了私钥
	if certData.PrivateKey != "" {
		if err := v.ValidateCertKeyPair(certData.Cert, certData.PrivateKey); err != nil {
			return "", fmt.Errorf("API 返回的私钥与证书不匹配: %v", err)
		}
		return certData.PrivateKey, nil
	}

	fmt.Println("  API 未返回私钥，检查本地私钥...")

	// 2. --key 指定了私钥路径
	if keyFile != "" {
		privateKey, err := readAndValidateKeyFile(keyFile, certData.Cert, v)
		if err != nil {
			return "", fmt.Errorf("--key 指定的私钥无效: %v", err)
		}
		return privateKey, nil
	}

	// 获取默认私钥路径（从 binding）
	defaultKeyPath := ""
	for _, b := range bindings {
		if b.Enabled && b.Paths.PrivateKey != "" {
			defaultKeyPath = b.Paths.PrivateKey
			break
		}
	}
	if defaultKeyPath == "" && len(bindings) > 0 {
		defaultKeyPath = bindings[0].Paths.PrivateKey
	}

	// 3. 默认路径存在则读取验证
	if defaultKeyPath != "" {
		if _, err := os.Stat(defaultKeyPath); err == nil {
			fmt.Printf("  本地私钥: %s\n", defaultKeyPath)
			privateKey, err := readAndValidateKeyFile(defaultKeyPath, certData.Cert, v)
			if err != nil {
				fmt.Printf("  ⚠ 本地私钥不可用: %v\n", err)
			} else {
				return privateKey, nil
			}
		}
	}

	// 4. 交互终端：提示用户输入私钥文件路径
	if !interactive || !isInteractiveTerminal() {
		return "", errNeedPrivateKey
	}

	absKeyPath := defaultKeyPath
	if absKeyPath != "" {
		absKeyPath, _ = filepath.Abs(absKeyPath)
		fmt.Printf("  私钥文件不存在: %s\n", absKeyPath)
		fmt.Println("  请输入私钥文件绝对路径（或将私钥放到上述路径后直接按回车）:")
	} else {
		fmt.Println("  请输入私钥文件绝对路径:")
	}
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("读取输入失败: %v", err)
	}
	input = strings.TrimSpace(input)

	// 用户直接按回车：重新检查默认路径
	if input == "" {
		if defaultKeyPath == "" {
			return "", fmt.Errorf("缺少私钥路径")
		}
		privateKey, err := readAndValidateKeyFile(defaultKeyPath, certData.Cert, v)
		if err != nil {
			return "", fmt.Errorf("私钥文件仍不可用: %v", err)
		}
		return privateKey, nil
	}

	// 用户输入了路径
	privateKey, err := readAndValidateKeyFile(input, certData.Cert, v)
	if err != nil {
		return "", fmt.Errorf("私钥文件无效: %v", err)
	}
	return privateKey, nil
}

// readAndValidateKeyFile 读取私钥文件并验证与证书匹配
func readAndValidateKeyFile(keyPath, certPEM string, v *validator.Validator) (string, error) {
	keyData, err := util.SafeReadFile(keyPath, config.MaxPrivateKeySize)
	if err != nil {
		return "", fmt.Errorf("读取私钥失败: %v", err)
	}
	privateKey := string(keyData)
	clear(keyData)
	if err := v.ValidateCertKeyPair(certPEM, privateKey); err != nil {
		return "", fmt.Errorf("私钥与证书不匹配: %v", err)
	}
	return privateKey, nil
}

// isInteractiveTerminal 检查 stdin 是否为交互终端
func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// confirm 确认提示
// 非终端环境（如 CI）读取失败时返回 false，需使用 --yes 参数
func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [Y/n]: ", prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response != "n" && response != "no"
}

// buildCertName 根据域名和订单ID生成证书名称
// 通配符 *.example.com → WILDCARD.example.com-12345
func buildCertName(domain string, orderID int) string {
	name := strings.Replace(domain, "*.", "WILDCARD.", 1)
	return fmt.Sprintf("%s-%d", name, orderID)
}

// extractDomainsFromCert 从证书中提取所有域名：合并 CN + SAN（DNSNames + IPAddresses），去重
func extractDomainsFromCert(cert *x509.Certificate) []string {
	seen := make(map[string]bool)
	var domains []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	// SAN 优先
	for _, d := range cert.DNSNames {
		add(d)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	// CN 补充（可能不在 SAN 中）
	add(cert.Subject.CommonName)
	return domains
}

// notifyAutoReissue 通知服务端是否自动续签（非关键路径，失败仅记录警告）
// pull 模式 → autoReissue=true；local 模式 → autoReissue=false
func notifyAutoReissue(p *setupParams, f *fetcher.Fetcher, orderID int, renewMode string) {
	autoReissue := renewMode != config.RenewModeLocal
	if err := f.ToggleAutoReissue(p.ctx, p.apiURL, p.token, orderID, autoReissue); err != nil {
		p.log.Warn("toggleAutoReissue 失败 (order_id=%d, auto_reissue=%v): %v", orderID, autoReissue, err)
	}
}
