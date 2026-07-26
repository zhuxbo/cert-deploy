// Package certops 证书操作服务层
package certops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// Service 证书服务
type Service struct {
	cfgManager *config.ConfigManager
	fetcher    *fetcher.Fetcher
	backupMgr  *backup.Manager
	log        *logger.Logger
	// authGate 轮内 token 黑名单，仅由 CheckAndRenewAll 一轮的范围使用（每轮开头 reset）。
	// 含互斥锁，故 Service 只能按指针传递。
	authGate authGate
}

// NewService 创建证书服务
func NewService(cfgManager *config.ConfigManager, log *logger.Logger) *Service {
	return &Service{
		cfgManager: cfgManager,
		fetcher:    fetcher.New(),
		backupMgr:  backup.NewManager(cfgManager.GetBackupDir(), 5),
		log:        log,
	}
}

// callbackContext 返回发送回调用的上下文。
// 回调是部署结果的唯一出口：父 ctx 被取消（daemon 收到 SIGTERM、检查超时）时
// 直接沿用会让整轮部署结果凭空消失，服务端停留在上一次状态。
// 因此脱离取消传播，但仍保留一个有界预算，避免关停时无限期挂住。
func callbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	dl, hasDeadline := ctx.Deadline()
	switch {
	case ctx.Err() != nil:
		// 已取消：cancel() 不改变 deadline，此时父预算余量可能仍很大，
		// 必须先于余量判断，否则会落进"保留父预算"分支
		return context.WithTimeout(base, CallbackFallbackBudget)
	case hasDeadline && time.Until(dl) <= CallbackFallbackBudget:
		return context.WithTimeout(base, CallbackFallbackBudget)
	case hasDeadline:
		// 父预算充裕：不缩小，按原 deadline 走
		return context.WithDeadline(base, dl)
	default:
		// 无 deadline（CLI 场景）：由 fetcher 的单次请求超时与重试上限兜底
		return context.WithCancel(base)
	}
}

// queryOrder 查询订单，顺带把「整批共通」失败记入轮内 token 黑名单（deploy-spec §2.2）。
//
// 续签路径的每一次订单查询都经由此处，记录点因此不会漏。手动部署也走这里：record 对它
// 无副作用——单证书场景没有「本轮其余条目」可省，且黑名单只在续签主循环被查询。
func (s *Service) queryOrder(ctx context.Context, api config.APIConfig, orderID int) (*fetcher.CertData, int, error) {
	certData, renewBeforeDays, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, orderID)
	_ = s.authGate.record(api, err)
	return certData, renewBeforeDays, err
}

// sendCallback 统一发送回调
// 非关键路径，失败仅记录日志
// 返回服务端下发的 renewBeforeDays（失败时返回 0）
func (s *Service) sendCallback(ctx context.Context, api config.APIConfig, req *fetcher.CallbackRequest) int {
	if api.URL == "" || api.Token == "" {
		return 0
	}

	cbCtx, cancel := callbackContext(ctx)
	defer cancel()

	renewBeforeDays, err := s.fetcher.CallbackNew(cbCtx, api.URL, api.Token, req)

	if err != nil {
		s.log.Warn("回调发送失败（不影响结果）: %v", err)
		return 0
	}
	s.log.Debug("回调成功: order=%d status=%s", req.OrderID, req.Status)
	return renewBeforeDays
}

// syncOrderID 同步 API 返回的订单号到本地配置
// 订单续费后 API 会返回新的订单号，需要及时更新 order_id 和 cert_name
func (s *Service) syncOrderID(cert *config.CertConfig, certData *fetcher.CertData) {
	if certData.OrderID > 0 && certData.OrderID != cert.OrderID {
		s.log.Info("证书 %s 订单已续费，订单号更新: %d -> %d", cert.CertName, cert.OrderID, certData.OrderID)
		cert.OrderID = certData.OrderID
	}
	// 修正 cert_name 使其与 order_id 一致
	s.fixCertName(cert)
}

// fixCertName 修正 cert_name（Service 包装）
func (s *Service) fixCertName(cert *config.CertConfig) {
	FixCertName(s.cfgManager, cert, s.log)
}

// FixCertName 修正 cert_name 中的订单号后缀，使其与 order_id 一致，
// 并同步迁移 pending 私钥目录与重命名配置条目。
// cert_name 格式: {domain}-{order_id}
// 单一实现供续签链与 CLI 部署链（cmd/deploy）共用，避免双实现漂移。
func FixCertName(cfgManager *config.ConfigManager, cert *config.CertConfig, log *logger.Logger) {
	idx := strings.LastIndex(cert.CertName, "-")
	if idx < 0 {
		return
	}
	expectedName := fmt.Sprintf("%s-%d", cert.CertName[:idx], cert.OrderID)
	if expectedName == cert.CertName {
		return
	}
	oldName := cert.CertName
	workDir := cfgManager.GetWorkDir()

	// 两阶段提交：先复制 pending 私钥 → 再落盘改名 → 成功后才改内存名并清理旧目录。
	// 任一步失败都保持"配置名与 pending 目录一致"，否则 local 续签读不到在途私钥，
	// 会回退线上私钥 → 与新证书不配对 → 重置签发状态 → 下轮重新生成 CSR 覆盖 pending。
	if err := copyPendingKey(workDir, oldName, expectedName); err != nil {
		if log != nil {
			log.Error("证书 %s 改名中止：复制 pending 私钥到 %s 失败: %v", oldName, expectedName, err)
		}
		return
	}
	renamed := *cert
	renamed.CertName = expectedName
	if err := cfgManager.RenameCert(oldName, &renamed); err != nil {
		if cleanupErr := cleanupPendingKey(workDir, expectedName); cleanupErr != nil && log != nil {
			log.Error("回滚 pending 私钥副本失败，需人工清理 pending-keys/%s: %v", expectedName, cleanupErr)
		}
		if log != nil {
			log.Error("证书 %s 改名为 %s 失败，保留旧名（order_id 已更新）: %v", oldName, expectedName, err)
		}
		return
	}
	cert.CertName = expectedName
	if err := cleanupPendingKey(workDir, oldName); err != nil && log != nil {
		log.Warn("清理旧 pending 私钥目录失败（新目录已生效，不影响功能）: %v", err)
	}
	if log != nil {
		log.Info("证书名称修正: %s -> %s", oldName, expectedName)
	}
}

// fillCertMetadata 填充回调请求中的证书元数据（预留扩展）
func fillCertMetadata(_ *fetcher.CallbackRequest, _ *config.CertConfig) {
}

// formatStaleSince 格式化 stale 起始时间；缺失时给出明确占位而非空串
func formatStaleSince(t time.Time) string {
	if t.IsZero() {
		return "时间未知"
	}
	return t.Format("2006-01-02")
}

// CheckExpiry 检查证书过期时间并输出告警日志
// 距过期不足 7 天 → Error 级别
// 距过期不足 13 天 → Warn 级别
func (s *Service) CheckExpiry() {
	cfg, err := s.cfgManager.Load()
	if err != nil {
		s.log.Warn("加载配置失败，跳过过期检查: %v", err)
		return
	}

	now := time.Now()
	for _, cert := range cfg.Certificates {
		if !cert.Enabled {
			continue
		}
		// 长期未部署成功的绑定必须持续告警：证书级到期日只反映"最新签发的证书"，
		// 这些站点仍挂着旧证书，按证书级判断永远看不出风险，会一路静默到真实过期。
		if len(cert.Metadata.StaleBindings) > 0 {
			s.log.Error("证书 %s 的站点 %v 长期未部署成功（自 %s），仍在使用旧证书，需人工处理",
				cert.CertName, cert.Metadata.StaleBindings, formatStaleSince(cert.Metadata.StaleSince))
		}
		// 到期时间未知不再静默跳过（告警盲区），下轮续签检查会自动回填。
		// 零启用绑定的证书例外：闸门在回填之前拦截，不会有人去回填，不能给出假承诺。
		if cert.Metadata.CertExpiresAt.IsZero() {
			if !cert.HasEnabledBinding() {
				s.log.Error("证书 %s 到期时间未知且没有启用的站点绑定，已阻断自动续签，需人工处理", cert.CertName)
			} else {
				s.log.Warn("证书 %s 到期时间未知（元数据缺失），无法判断过期风险，续签检查将自动回填", cert.CertName)
			}
			continue
		}

		remaining := cert.Metadata.CertExpiresAt.Sub(now)

		if remaining < 0 {
			days := int(-remaining.Hours() / 24)
			s.log.Error("证书 %s 已过期 %d 天! (过期时间: %s)",
				cert.CertName, days, cert.Metadata.CertExpiresAt.Format("2006-01-02"))
		} else if remaining < 7*24*time.Hour {
			s.log.Error("证书 %s 即将过期! 剩余 %d 天 (过期时间: %s)",
				cert.CertName, int(remaining.Hours()/24), cert.Metadata.CertExpiresAt.Format("2006-01-02"))
		} else if remaining < 13*24*time.Hour {
			s.log.Warn("证书 %s 即将过期，剩余 %d 天 (过期时间: %s)",
				cert.CertName, int(remaining.Hours()/24), cert.Metadata.CertExpiresAt.Format("2006-01-02"))
		}
	}
}
