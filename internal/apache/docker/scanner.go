// Package docker 提供 Apache Docker 容器扫描支持
package docker

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	nginxDocker "github.com/zhuxbo/sslctl/internal/nginx/docker"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// Client Docker 客户端（复用 Nginx Docker 客户端）
type Client = nginxDocker.Client

// ContainerInfo 容器信息
type ContainerInfo = nginxDocker.ContainerInfo

// MountInfo 挂载信息
type MountInfo = nginxDocker.MountInfo

// NewClient 创建 Docker 客户端
func NewClient(containerID string) *Client {
	return nginxDocker.NewClient(containerID)
}

// NewComposeClient 创建 docker-compose 客户端
func NewComposeClient(composeFile, serviceName string) *Client {
	return nginxDocker.NewComposeClient(composeFile, serviceName)
}

// SSLSite Docker 容器内的 Apache SSL 站点
type SSLSite struct {
	ContainerID   string
	ContainerName string

	ConfigFile      string   // 容器内配置文件路径
	ServerName      string   // 主域名
	ServerAlias     []string // 域名别名
	CertificatePath string   // SSLCertificateFile
	PrivateKeyPath  string   // SSLCertificateKeyFile
	ChainPath       string   // SSLCertificateChainFile
	ListenPort      string   // VirtualHost 地址
	Webroot         string   // DocumentRoot

	HostCertPath  string
	HostKeyPath   string
	HostChainPath string
	HostWebroot   string
	VolumeMode    bool
}

const (
	maxScanDepth = 100
	maxScanFiles = 1000
)

// Scanner Apache Docker 扫描器
type Scanner struct {
	client       *Client
	scannedFiles map[string]bool
	mounts       []MountInfo
	serverRoot   string // Apache ServerRoot
}

// NewScanner 创建 Apache Docker 扫描器
func NewScanner(client *Client) *Scanner {
	return &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
	}
}

// Scan 扫描容器内的 Apache 站点
func (s *Scanner) Scan(ctx context.Context) ([]*SSLSite, error) {
	configPath, serverRoot, err := s.DetectApacheConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("detect apache config failed: %w", err)
	}
	s.serverRoot = serverRoot

	info, err := s.client.GetContainerInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("get container info failed: %w", err)
	}
	s.mounts = info.Mounts

	s.scannedFiles = make(map[string]bool)
	return s.scanConfigFile(ctx, configPath, info, 0)
}

// DetectApacheConfig 检测容器内 Apache 配置路径
func (s *Scanner) DetectApacheConfig(ctx context.Context) (configPath, serverRoot string, err error) {
	// 方法1: apache2ctl -V / apachectl -V / httpd -V
	for _, cmd := range []string{"apache2ctl", "apachectl", "httpd"} {
		output, execErr := s.client.Exec(ctx, fmt.Sprintf("%s -V 2>&1", cmd))
		if execErr != nil {
			continue
		}

		rootRe := regexp.MustCompile(`HTTPD_ROOT="([^"]+)"`)
		configRe := regexp.MustCompile(`SERVER_CONFIG_FILE="([^"]+)"`)

		if matches := rootRe.FindStringSubmatch(output); len(matches) > 1 {
			serverRoot = matches[1]
		}
		if matches := configRe.FindStringSubmatch(output); len(matches) > 1 {
			configFile := matches[1]
			if filepath.IsAbs(configFile) {
				configPath = configFile
			} else if serverRoot != "" {
				configPath = serverRoot + "/" + configFile
			}
		}

		if configPath != "" {
			return configPath, serverRoot, nil
		}
	}

	// 方法2: 常见路径
	commonPaths := []struct{ config, root string }{
		{"/etc/apache2/apache2.conf", "/etc/apache2"},
		{"/etc/httpd/conf/httpd.conf", "/etc/httpd"},
		{"/usr/local/apache2/conf/httpd.conf", "/usr/local/apache2"},
	}
	for _, p := range commonPaths {
		_, execErr := s.client.Exec(ctx, fmt.Sprintf("test -f %s && echo ok", util.ShellQuote(p.config)))
		if execErr == nil {
			return p.config, p.root, nil
		}
	}

	return "", "", fmt.Errorf("无法检测容器内 Apache 配置路径")
}

// scanConfigFile 扫描配置文件（递归处理 Include）
func (s *Scanner) scanConfigFile(ctx context.Context, configPath string, info *ContainerInfo, depth int) ([]*SSLSite, error) {
	if depth > maxScanDepth {
		return nil, nil
	}
	if len(s.scannedFiles) >= maxScanFiles {
		return nil, nil
	}
	if s.scannedFiles[configPath] {
		return nil, nil
	}
	s.scannedFiles[configPath] = true

	content, err := s.readContainerFile(ctx, configPath)
	if err != nil {
		return nil, nil
	}

	var sites []*SSLSite

	fileSites := s.parseConfig(content, configPath, info)
	sites = append(sites, fileSites...)

	includes := s.findIncludes(ctx, content, configPath)
	for _, inc := range includes {
		incSites, err := s.scanConfigFile(ctx, inc, info, depth+1)
		if err == nil {
			sites = append(sites, incSites...)
		}
	}

	return sites, nil
}

// readContainerFile 读取容器内文件
func (s *Scanner) readContainerFile(ctx context.Context, filePath string) (string, error) {
	return s.client.Exec(ctx, fmt.Sprintf("cat %s", util.ShellQuote(filePath)))
}

// findIncludes 查找 Include/IncludeOptional 指令
func (s *Scanner) findIncludes(ctx context.Context, content, configPath string) []string {
	configDir := filepath.Dir(configPath)
	var includes []string

	includeRe := regexp.MustCompile(`(?im)^\s*Include(?:Optional)?\s+(.+)$`)
	matches := includeRe.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		pattern := strings.TrimSpace(match[1])
		pattern = strings.Trim(pattern, `"'`)

		// 处理相对路径
		if !strings.HasPrefix(pattern, "/") {
			if s.serverRoot != "" {
				pattern = s.serverRoot + "/" + pattern
			} else {
				pattern = configDir + "/" + pattern
			}
		}

		// 处理 glob 模式
		if strings.Contains(pattern, "*") {
			dir := filepath.Dir(pattern)
			base := filepath.Base(pattern)
			// 用 ls 列出匹配文件
			output, err := s.client.Exec(ctx, fmt.Sprintf("ls -1 %s/%s 2>/dev/null", util.ShellQuote(dir), base))
			if err == nil && output != "" {
				for _, f := range strings.Split(output, "\n") {
					f = strings.TrimSpace(f)
					if f != "" {
						includes = append(includes, f)
					}
				}
			}
		} else {
			includes = append(includes, pattern)
		}
	}

	return includes
}

// parseConfig 解析 Apache 配置内容
func (s *Scanner) parseConfig(content, configPath string, info *ContainerInfo) []*SSLSite {
	var sites []*SSLSite
	var currentSite *SSLSite
	inVirtualHost := false

	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost\s+([^>]+)>`)
	vhostEndRe := regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	serverAliasRe := regexp.MustCompile(`(?i)^\s*ServerAlias\s+(.+)$`)
	sslCertRe := regexp.MustCompile(`(?i)^\s*SSLCertificateFile\s+(.+)$`)
	sslKeyRe := regexp.MustCompile(`(?i)^\s*SSLCertificateKeyFile\s+(.+)$`)
	sslChainRe := regexp.MustCompile(`(?i)^\s*SSLCertificateChainFile\s+(.+)$`)
	docRootRe := regexp.MustCompile(`(?i)^\s*DocumentRoot\s+(.+)$`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// VirtualHost 开始
		if matches := vhostStartRe.FindStringSubmatch(line); len(matches) > 1 {
			inVirtualHost = true
			currentSite = &SSLSite{
				ContainerID:   info.ID,
				ContainerName: info.Name,
				ConfigFile:    configPath,
				ListenPort:    strings.TrimSpace(matches[1]),
			}
			continue
		}

		if !inVirtualHost {
			continue
		}

		// VirtualHost 结束
		if vhostEndRe.MatchString(line) {
			if currentSite != nil && currentSite.ServerName != "" && currentSite.ServerName != "_" {
				if currentSite.CertificatePath != "" && currentSite.PrivateKeyPath != "" {
					s.resolveHostPaths(currentSite)
				}
				sites = append(sites, currentSite)
			}
			inVirtualHost = false
			currentSite = nil
			continue
		}

		// ServerName
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			currentSite.ServerName = strings.Trim(strings.TrimSpace(matches[1]), `"'`)
		}

		// ServerAlias
		if matches := serverAliasRe.FindStringSubmatch(line); len(matches) > 1 {
			for _, alias := range strings.Fields(matches[1]) {
				currentSite.ServerAlias = append(currentSite.ServerAlias, strings.Trim(alias, `"'`))
			}
		}

		// SSLCertificateFile
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			currentSite.CertificatePath = strings.Trim(strings.TrimSpace(matches[1]), `"'`)
		}

		// SSLCertificateKeyFile
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			currentSite.PrivateKeyPath = strings.Trim(strings.TrimSpace(matches[1]), `"'`)
		}

		// SSLCertificateChainFile
		if matches := sslChainRe.FindStringSubmatch(line); len(matches) > 1 {
			currentSite.ChainPath = strings.Trim(strings.TrimSpace(matches[1]), `"'`)
		}

		// DocumentRoot
		if matches := docRootRe.FindStringSubmatch(line); len(matches) > 1 {
			if currentSite.Webroot == "" {
				currentSite.Webroot = strings.Trim(strings.TrimSpace(matches[1]), `"'`)
			}
		}
	}

	// 处理最后一个 VirtualHost
	if currentSite != nil && currentSite.ServerName != "" && currentSite.ServerName != "_" {
		if currentSite.CertificatePath != "" && currentSite.PrivateKeyPath != "" {
			s.resolveHostPaths(currentSite)
		}
		sites = append(sites, currentSite)
	}

	return sites
}

// resolveHostPaths 解析宿主机路径
func (s *Scanner) resolveHostPaths(site *SSLSite) {
	if m := s.client.FindMountForPath(s.mounts, site.CertificatePath); m != nil {
		site.HostCertPath = s.client.ResolveHostPath(site.CertificatePath, m)
		site.VolumeMode = true
	}
	if m := s.client.FindMountForPath(s.mounts, site.PrivateKeyPath); m != nil {
		site.HostKeyPath = s.client.ResolveHostPath(site.PrivateKeyPath, m)
	}
	if site.ChainPath != "" {
		if m := s.client.FindMountForPath(s.mounts, site.ChainPath); m != nil {
			site.HostChainPath = s.client.ResolveHostPath(site.ChainPath, m)
		}
	}
	if site.Webroot != "" {
		if m := s.client.FindMountForPath(s.mounts, site.Webroot); m != nil {
			site.HostWebroot = s.client.ResolveHostPath(site.Webroot, m)
		}
	}
}
