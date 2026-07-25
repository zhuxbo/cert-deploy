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
}

// NewService 创建证书服务
func NewService(cfgManager *config.ConfigManager, log *logger.Logger) *Service {
	return &Service{
		cfgManager: cfgManager,
		fetcher:    fetcher.New(30 * time.Second),
		backupMgr:  backup.NewManager(cfgManager.GetBackupDir(), 5),
		log:        log,
	}
}

// sendCallback 统一发送回调
// 非关键路径，失败仅记录日志
// 返回服务端下发的 renewBeforeDays（失败时返回 0）
func (s *Service) sendCallback(ctx context.Context, api config.APIConfig, req *fetcher.CallbackRequest) int {
	if api.URL == "" || api.Token == "" {
		return 0
	}

	renewBeforeDays, err := s.fetcher.CallbackNew(ctx, api.URL, api.Token, req)

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
