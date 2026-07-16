// Package config 提供统一配置管理
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// Config 统一配置结构（config.json）
type Config struct {
	ReleaseURL    string         `json:"release_url,omitempty"`
	UpgradeChannel string        `json:"upgrade_channel,omitempty"` // 升级通道: main/dev，空值跟随当前版本号自动判断
	Schedule      ScheduleConfig `json:"schedule"`
	Certificates  []CertConfig   `json:"certificates"`
	Metadata      ConfigMetadata `json:"metadata,omitempty"`
}

// ConfigMetadata 配置元数据
type ConfigMetadata struct {
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	LastCheckAt time.Time `json:"last_check_at,omitempty"`
}

// CertConfig 证书配置
type CertConfig struct {
	CertName         string        `json:"cert_name"`                    // 证书名称（如 example.com-12345）
	OrderID          int           `json:"order_id"`                     // 订单 ID
	Enabled          bool          `json:"enabled"`                      // 是否启用
	Domains          []string      `json:"domains"`                      // 证书域名列表
	RenewMode        string        `json:"renew_mode,omitempty"`         // 续签模式: local | pull（优先于全局配置）
	ValidationMethod string        `json:"validation_method,omitempty"`  // 验证方法: file | delegation
	API              APIConfig     `json:"api"`                          // 证书级别的 API 配置
	Bindings         []SiteBinding `json:"bindings"`                     // 站点绑定
	Metadata         CertMetadata  `json:"metadata,omitempty"`
}

// GetAPI 获取 API 配置（环境变量优先覆盖所有证书）
// log 可为 nil，此时校验失败静默降级
func (c *CertConfig) GetAPI(log *logger.Logger) APIConfig {
	api := c.API

	if envToken := os.Getenv(EnvAPIToken); envToken != "" {
		if err := validateToken(envToken); err != nil {
			if log != nil {
				log.Warn("环境变量 %s 校验失败: %v，使用证书配置", EnvAPIToken, err)
			}
		} else {
			api.Token = envToken
		}
	}
	if envURL := os.Getenv(EnvAPIURL); envURL != "" {
		if err := validateAPIURL(envURL); err != nil {
			if log != nil {
				log.Warn("环境变量 %s 校验失败: %v，使用证书配置", EnvAPIURL, err)
			}
		} else {
			api.URL = envURL
		}
	}

	return api
}

// CertMetadata 证书元数据
type CertMetadata struct {
	LastDeployAt  time.Time `json:"last_deploy_at,omitempty"`
	CertExpiresAt time.Time `json:"cert_expires_at,omitempty"`
	CertSerial    string    `json:"cert_serial,omitempty"`
	// 本地私钥续签的状态信息
	CSRSubmittedAt  time.Time `json:"csr_submitted_at,omitempty"`
	LastCSRHash     string    `json:"last_csr_hash,omitempty"`
	LastIssueState  string    `json:"last_issue_state,omitempty"`
	IssueRetryCount int       `json:"issue_retry_count,omitempty"`
	// 部署失败的绑定列表（ServerName），下次检查时重试
	FailedBindings   []string  `json:"failed_bindings,omitempty"`
	FailedBindingsAt time.Time `json:"failed_bindings_at,omitempty"` // 首次记录失败绑定的时间
	// 文件验证相关
	ValidationFiles []string `json:"validation_files,omitempty"` // 已写入的验证文件路径（部署成功后清理）
}

// SiteBinding 站点绑定配置
type SiteBinding struct {
	ServerName string       `json:"server_name"`      // 站点名称（域名）
	ServerType string       `json:"server_type"`      // nginx, apache, docker-nginx, docker-apache
	Enabled    bool         `json:"enabled"`          // 是否启用
	Paths      BindingPaths `json:"paths"`            // 路径配置
	Reload     ReloadConfig `json:"reload,omitempty"` // 重载配置
	Docker     *DockerInfo  `json:"docker,omitempty"` // Docker 配置（仅 docker-* 类型）
}

// BindingPaths 绑定路径配置
type BindingPaths struct {
	Certificate string `json:"certificate"`           // 证书文件路径
	PrivateKey  string `json:"private_key"`           // 私钥文件路径
	ChainFile   string `json:"chain_file,omitempty"`  // 证书链文件路径（Apache）
	ConfigFile  string `json:"config_file,omitempty"` // 配置文件路径
	Webroot     string `json:"webroot,omitempty"`     // Web 根目录(用于文件验证)
}

// DockerInfo Docker 部署信息
type DockerInfo struct {
	ContainerName string `json:"container_name,omitempty"` // 容器名称
	DeployMode    string `json:"deploy_mode,omitempty"`    // volume | copy
}

// ServerType 常量
// 注意：这些值必须与 pkg/webserver/types.go 中的定义保持一致
const (
	ServerTypeNginx        = string(webserver.TypeNginx)
	ServerTypeApache       = string(webserver.TypeApache)
	ServerTypeDockerNginx  = string(webserver.TypeDockerNginx)
	ServerTypeDockerApache = string(webserver.TypeDockerApache)
)

// IsDockerType 判断服务器类型是否为 Docker 变体（docker-nginx / docker-apache）
func IsDockerType(serverType string) bool {
	return serverType == ServerTypeDockerNginx || serverType == ServerTypeDockerApache
}

// ValidateDockerBinding 校验 Docker 站点绑定能否通过通用部署路径安全部署。
// 通用部署器只能写宿主机文件并用 docker exec 重载，因此要求：
//   - 挂载卷模式（证书目录已映射到宿主机），否则写入会落到错误位置；
//   - 存在容器重载命令（能确定容器名），否则部署后无法在容器内生效；
//   - 待写的证书与私钥路径均非空（卷模式下应为扫描解析出的宿主机路径）。
//     路径为空意味着宿主机映射解析失败，写入会落到错误位置或失败，须计为失败而非静默"成功"。
// 不满足时返回错误，调用方应中止并如实计为失败，而非静默"部署成功"。
// 非 Docker 类型返回 nil。
func ValidateDockerBinding(binding *SiteBinding) error {
	if !IsDockerType(binding.ServerType) {
		return nil
	}
	if binding.Docker == nil || binding.Docker.DeployMode != "volume" {
		return fmt.Errorf("站点 %s 的 Docker 证书目录未挂载为宿主机卷（copy 模式），通用部署路径无法安全写入，跳过部署", binding.ServerName)
	}
	if binding.Reload.ReloadCommand == "" {
		return fmt.Errorf("站点 %s 缺少 Docker 容器重载命令（未能确定容器名），跳过部署", binding.ServerName)
	}
	if binding.Paths.Certificate == "" {
		return fmt.Errorf("站点 %s 的 Docker 证书宿主机路径为空（挂载映射解析失败），跳过部署", binding.ServerName)
	}
	if binding.Paths.PrivateKey == "" {
		return fmt.Errorf("站点 %s 的 Docker 私钥宿主机路径为空（挂载映射解析失败），跳过部署", binding.ServerName)
	}
	return nil
}

// MatchType 匹配类型
type MatchType string

const (
	MatchTypeFull    MatchType = "full"    // 完全匹配
	MatchTypePartial MatchType = "partial" // 部分匹配
	MatchTypeNone    MatchType = "none"    // 不匹配
)

// MatchResult 域名匹配结果
type MatchResult struct {
	Type           MatchType // 匹配类型
	MatchedDomains []string  // 匹配的域名
	MissedDomains  []string  // 未匹配的域名
}

// DaysUntilExpiry 计算证书到期剩余天数（展示用；判定请用 IsExpired/NeedsRenewal）
func (c *CertConfig) DaysUntilExpiry() int {
	if c.Metadata.CertExpiresAt.IsZero() {
		return 999
	}
	duration := time.Until(c.Metadata.CertExpiresAt)
	return int(duration.Hours() / 24)
}

// IsExpired 证书是否已过期（按时间点比较，避免整数天截断使"已过期"判定偏移约 24 小时）
// 到期时间未知（零值）不视为已过期，由调用方先回填元数据
func (c *CertConfig) IsExpired() bool {
	if c.Metadata.CertExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.Metadata.CertExpiresAt)
}

// GetRenewMode 获取续签模式（证书级别优先，否则使用全局配置）
func (c *CertConfig) GetRenewMode(schedule *ScheduleConfig) string {
	// 优先使用证书级别的配置
	if c.RenewMode != "" {
		return c.RenewMode
	}
	// 否则使用全局配置
	if schedule != nil && schedule.RenewMode != "" {
		return schedule.RenewMode
	}
	return RenewModePull
}

// NeedsRenewal 判断是否需要续期
// 到期时间未知（零值）返回 false：语义为"未知需处理"，由续签检查先查询 API 回填元数据后再判定
// 已过期证书不再触发续签（按时间点判定，过期不足 24 小时也算已过期）
func (c *CertConfig) NeedsRenewal(schedule *ScheduleConfig) bool {
	if c.Metadata.CertExpiresAt.IsZero() {
		return false
	}
	if c.IsExpired() {
		return false
	}
	renewDays := schedule.RenewBeforeDays
	if renewDays <= 0 {
		renewDays = DefaultRenewBeforeDays
	}
	return c.DaysUntilExpiry() <= renewDays
}

// GetCertDir 获取证书存储目录
func GetCertDir(siteName string) string {
	return "/opt/sslctl/certs/" + siteName
}

// GetDefaultCertPath 获取默认证书路径
func GetDefaultCertPath(siteName string) string {
	return GetCertDir(siteName) + "/cert.pem"
}

// GetDefaultKeyPath 获取默认私钥路径
func GetDefaultKeyPath(siteName string) string {
	return GetCertDir(siteName) + "/key.pem"
}

// GetDefaultChainPath 获取默认证书链路径（Apache）
func GetDefaultChainPath(siteName string) string {
	return GetCertDir(siteName) + "/chain.pem"
}
