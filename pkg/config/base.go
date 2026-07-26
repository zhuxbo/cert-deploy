// Package config 提供基础配置结构
package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/zhuxbo/sslctl/pkg/errors"
)

// KeyConfig 私钥配置
type KeyConfig struct {
	Type  string `json:"type"`            // rsa|ecdsa
	Size  int    `json:"size,omitempty"`  // RSA: 2048|4096
	Curve string `json:"curve,omitempty"` // ECDSA: prime256v1|secp384r1|secp521r1
}

// CSRConfig CSR 配置（支持 OV 字段）
type CSRConfig struct {
	CommonName   string `json:"common_name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	State        string `json:"state,omitempty"`
	Locality     string `json:"locality,omitempty"`
	Email        string `json:"email,omitempty"`
}

// APIConfig API 配置
type APIConfig struct {
	URL   string `json:"url"`   // 证书 API 基础地址
	Token string `json:"token"` // API 认证 Token (Bearer Token)
}

// PathsConfig 路径配置
type PathsConfig struct {
	Certificate string `json:"certificate"`          // 证书文件路径 (fullchain for nginx, cert for apache)
	PrivateKey  string `json:"private_key"`          // 私钥文件路径
	ChainFile   string `json:"chain_file,omitempty"` // 中间证书链文件路径 (apache only)
	ConfigFile  string `json:"config_file"`          // 配置文件路径
	Webroot     string `json:"webroot,omitempty"`    // Web 根目录(用于文件验证)
}

// ReloadConfig 重载配置
type ReloadConfig struct {
	TestCommand   string `json:"test_command"`   // 测试命令, 如 "nginx -t"
	ReloadCommand string `json:"reload_command"` // 重载命令, 如 "systemctl reload nginx"
}

// BackupConfig 备份配置
type BackupConfig struct {
	Enabled      bool `json:"enabled"`       // 是否启用备份
	KeepVersions int  `json:"keep_versions"` // 保留版本数
}

// ValidationConfig 验证配置
type ValidationConfig struct {
	VerifyDomain         bool   `json:"verify_domain"`          // 是否验证域名
	TestHTTPS            bool   `json:"test_https"`             // 是否测试 HTTPS 访问
	TestURL              string `json:"test_url"`               // 测试 URL
	IgnoreDomainMismatch bool   `json:"ignore_domain_mismatch"` // 忽略域名不匹配
	Method               string `json:"method,omitempty"`       // 验证方式: txt|file|admin|...
}

// RenewMode 续签模式常量
const (
	RenewModeLocal = "local" // 本机提交：本地生成私钥和 CSR，发起签发
	RenewModePull  = "pull"  // 自动签发：从服务端拉取已签发的证书
)

// UpgradeChannel 升级通道常量（白名单，防止路径遍历）
const (
	ChannelMain = "main" // 正式版通道
	ChannelDev  = "dev"  // 测试版通道
)

// ValidateChannel 校验升级通道是否合法
func ValidateChannel(ch string) error {
	if ch != ChannelMain && ch != ChannelDev {
		return fmt.Errorf("无效的升级通道 %q（仅允许 main/dev）", ch)
	}
	return nil
}

// ValidationMethod 验证方法常量
const (
	ValidationMethodFile       = "file"       // 文件验证 (HTTP-01)
	ValidationMethodDelegation = "delegation" // 委托验证 (DNS-01)
)

// 签发/生命周期状态常量（metadata.last_issue_state 取值，deploy-spec §1.5/§3.2）
const (
	IssueStateProcessing    = "processing"                 // 等待签发（只查询，不重复提交）
	IssueStateActive        = "active"                     // 秒签已签发、等待部署
	IssueStateCapped        = "CAPPED"                     // 触顶静默（阶段见 CappedPhase）
	IssueStateExpired       = "EXPIRED"                    // 已过期静默
	IssueStatePolicyBlocked = "policy_blocked_needs_setup" // 非法 IP 配置，等待重新 setup
)

// 触顶阶段常量（metadata.capped_phase 取值）
const (
	CappedPhaseIssue   = "issue"   // 签发计数触顶
	CappedPhaseDeploy  = "deploy"  // 部署计数触顶
	CappedPhaseStalled = "stalled" // 无进展时限触顶（停更，deploy-spec §3.2）
	CappedPhaseLegacy  = "legacy"  // 旧混合计数升级即触顶
)

// 服务端订单状态取值（CertData.status，deploy-spec §2.4）。
// 服务端枚举共 12 个，客户端必须显式分类——用 default 兜底会把
// unpaid / cancelling 这类可自愈的中间态误判为终态并停止推进。
const (
	OrderStatusUnpaid     = "unpaid"     // 未支付（服务端 update 会自动推进；孤儿单由服务端 60 分钟清理）
	OrderStatusPending    = "pending"    // 已收到 CSR，待提交上游
	OrderStatusProcessing = "processing" // 签发处理中
	OrderStatusApproving  = "approving"  // processing 与 active 之间的短暂中间态
	OrderStatusActive     = "active"     // 已签发
	OrderStatusFailed     = "failed"     // CA 拒签，终态
	OrderStatusCancelling = "cancelling" // 取消中（过渡态，将转 cancelled）
	OrderStatusCancelled  = "cancelled"  // 已取消，终态
	OrderStatusRevoked    = "revoked"    // 已吊销，终态
	OrderStatusRenewed    = "renewed"    // 已被续费替代（服务端自动跟链，收到即数据异常）
	OrderStatusReissued   = "reissued"   // 已被重签替代（同上）
	OrderStatusExpired    = "expired"    // 已过期，终态
)

// OrderStatusClass 订单状态的客户端处置类别
type OrderStatusClass int

const (
	// OrderClassActive 已签发，可部署
	OrderClassActive OrderStatusClass = iota
	// OrderClassWaiting 在途等待：只 GET 查询、不计数、不重复提交，计入无进展计时。
	// 含 unpaid / cancelling——它们不是终态，服务端会自行推进或清理，
	// 客户端**不主动 POST 推进**（update 会触发 pay 扣费，涉及资金的动作不由客户端自动发起）。
	OrderClassWaiting
	// OrderClassTerminal 真终态：持久化后停止自动动作，等待人工处理
	OrderClassTerminal
	// OrderClassChainAnomaly 链式状态：服务端 resolveRenewedOrder 会自动跟随续费/重签链，
	// 客户端收到即说明链数据异常（断链或成环），按终态处置并显式告警
	OrderClassChainAnomaly
	// OrderClassUnknown 服务端新增的未知状态：保守当等待，由无进展时限兜底。
	// 反向（当终态）会让一个新增的中间态把所有证书打进停机。
	OrderClassUnknown
)

// ClassifyOrderStatus 归类服务端订单状态（deploy-spec §2.4/§3.4/§3.5）
func ClassifyOrderStatus(status string) OrderStatusClass {
	switch status {
	case OrderStatusActive:
		return OrderClassActive
	case OrderStatusPending, OrderStatusProcessing, OrderStatusApproving,
		OrderStatusUnpaid, OrderStatusCancelling:
		return OrderClassWaiting
	case OrderStatusFailed, OrderStatusCancelled, OrderStatusRevoked, OrderStatusExpired:
		return OrderClassTerminal
	case OrderStatusRenewed, OrderStatusReissued:
		return OrderClassChainAnomaly
	default:
		return OrderClassUnknown
	}
}

// AttemptCap 签发/部署尝试上限（deploy-spec §3.2/§11）：分别计数，各自 >= 10 触顶。
const AttemptCap = 10

// ContainsIPDomain 判断域名列表是否包含 IP 地址（SAN 含 IP）。
// 复用 net.ParseIP 精确判断，IPv4/IPv6 均识别。
func ContainsIPDomain(domains []string) bool {
	for _, d := range domains {
		if net.ParseIP(d) != nil {
			return true
		}
	}
	return false
}

// ValidateValidationMethod 校验域名与验证方法的兼容性
// 返回错误信息，如果兼容则返回空字符串
func ValidateValidationMethod(domain string, method string) string {
	if method == "" {
		return ""
	}

	// 检查是否是 IP 地址（使用 net.ParseIP 准确判断）
	isIP := net.ParseIP(domain) != nil

	// 检查是否是通配符域名
	isWildcard := len(domain) > 2 && domain[0] == '*' && domain[1] == '.'

	if isIP && method == ValidationMethodDelegation {
		return "IP 地址不支持委托验证"
	}

	if isWildcard && method == ValidationMethodFile {
		return "通配符域名不支持文件验证"
	}

	return ""
}

const (
	// DefaultRenewBeforeDays 默认提前续签天数（由服务端控制，每次 API 交互后更新本地配置）
	DefaultRenewBeforeDays = 14
	// MaxRenewBeforeDays 服务端下发值上限（deploy-spec §2.9）
	MaxRenewBeforeDays = 30
)

// 文件大小限制常量
const (
	MaxPrivateKeySize = 16 * 1024 // 16KB - 足够 RSA-8192 私钥
	MaxCertFileSize   = 64 * 1024 // 64KB - 证书链大小限制（cert + intermediate）
)

// 环境变量常量
const (
	EnvAPIToken = "SSLCTL_API_TOKEN" // API Token 环境变量
	EnvAPIURL   = "SSLCTL_API_URL"   // API URL 环境变量
)

// ScheduleConfig 调度配置
type ScheduleConfig struct {
	RenewBeforeDays        int    `json:"renew_before_days"`                  // 提前续期天数，0 使用默认值 14，由服务端控制
	RenewMode              string `json:"renew_mode,omitempty"`               // 续签模式: local | pull，默认 pull
	ShutdownTimeoutSeconds int    `json:"shutdown_timeout_seconds,omitempty"` // 守护进程关闭超时(秒)，0 使用默认值 60
}

// DefaultShutdownTimeoutSeconds 默认关闭超时
const DefaultShutdownTimeoutSeconds = 60

// ValidateSchedule 验证调度配置
func ValidateSchedule(schedule *ScheduleConfig) error {
	mode := schedule.RenewMode
	if mode == "" {
		mode = RenewModePull // 默认自动签发
	}

	// 验证模式有效性
	if mode != RenewModeLocal && mode != RenewModePull {
		return errors.NewConfigError(
			"无效的 renew_mode: "+mode+"（必须是 local 或 pull）",
			nil,
		)
	}

	return nil
}

// DockerConfig Docker 部署配置
type DockerConfig struct {
	Enabled       bool   `json:"enabled"`                  // 是否启用 Docker 模式
	ContainerID   string `json:"container_id,omitempty"`   // 容器 ID
	ContainerName string `json:"container_name,omitempty"` // 容器名称

	// 自动发现配置
	AutoDiscover bool   `json:"auto_discover,omitempty"` // 自动发现 Nginx 容器
	ImageFilter  string `json:"image_filter,omitempty"`  // 镜像名过滤

	// 部署模式
	DeployMode string `json:"deploy_mode,omitempty"` // volume | copy | auto

	// Compose 配置
	ComposeFile string `json:"compose_file,omitempty"` // docker-compose.yml 路径
	ServiceName string `json:"service_name,omitempty"` // compose 服务名

	// 容器内路径
	ContainerPaths ContainerPathsConfig `json:"container_paths,omitempty"`
}

// ContainerPathsConfig 容器内路径配置
type ContainerPathsConfig struct {
	Certificate string `json:"certificate,omitempty"` // 容器内证书路径
	PrivateKey  string `json:"private_key,omitempty"` // 容器内私钥路径
	ConfigFile  string `json:"config_file,omitempty"` // 容器内配置文件路径
	Webroot     string `json:"webroot,omitempty"`     // 容器内 Web 根目录
}

// GetEnvWithDefault 获取环境变量，提供默认值
func GetEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ValidateLogLevel 验证日志级别
func ValidateLogLevel(level string) error {
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[strings.ToLower(level)] {
		return errors.NewConfigError(
			"invalid log level: "+level+" (must be debug|info|warn|error)",
			nil,
		)
	}
	return nil
}
