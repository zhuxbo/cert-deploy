// Package certops 证书部署逻辑
package certops

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// DeployOne 部署指定证书
// 注意：部分绑定失败时返回 nil error，调用方必须检查 result.Success 和 result.Error。
// 仅当所有启用的绑定均部署失败时，才同时返回非 nil error。
func (s *Service) DeployOne(ctx context.Context, certName string) (*DeployResult, error) {
	cert, err := s.cfgManager.GetCert(certName)
	if err != nil {
		return nil, fmt.Errorf("获取证书配置失败: %w", err)
	}

	api := cert.GetAPI(s.log)
	if api.URL == "" || api.Token == "" {
		return nil, fmt.Errorf("证书 %s 的 API 配置不完整", certName)
	}

	// 从 API 获取证书
	certData, renewBeforeDays, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return nil, fmt.Errorf("获取证书失败: %w", err)
	}
	s.tryUpdateRenewBeforeDays(renewBeforeDays)

	// 订单续费后 API 返回新订单号，同步更新
	s.syncOrderID(cert, certData)

	if certData.Status != config.OrderStatusActive || certData.Cert == "" {
		return nil, fmt.Errorf("证书未就绪 (status=%s)", certData.Status)
	}

	if certData.IntermediateCert == "" {
		return nil, fmt.Errorf("中间证书为空，等待下一周期重试")
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取（pending 感知，配对校验）
	privateKey, err := GetPrivateKeyForCert(s.cfgManager.GetWorkDir(), cert, certData.Cert, certData.PrivateKey, s.log)
	if err != nil {
		return nil, err
	}

	// 部署到所有绑定
	result := &DeployResult{
		CertName: certName,
		Success:  true,
	}

	enabledCount := 0
	successCount := 0
	for i := range cert.Bindings {
		// 使用值拷贝而非指针，确保深拷贝保护有效
		binding := cert.Bindings[i]
		if !binding.Enabled {
			continue
		}
		enabledCount++

		err := s.deployToBinding(ctx, &binding, certData, privateKey)
		if err != nil {
			s.log.Error("部署到 %s 失败: %v", binding.ServerName, err)
			result.Success = false
			result.Error = err
		} else {
			s.log.Info("证书已部署到 %s", binding.ServerName)
			successCount++
		}
	}

	// 部署成功后补转正 pending 私钥（若本次使用的正是 pending 私钥）
	if successCount > 0 {
		s.commitPendingKeyAfterDeploy(cert, privateKey)
	}

	// 持久化配置变更（订单号更新等）
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("更新证书配置失败: %v", err)
	}

	// 发送部署回调（非关键路径，失败仅记录日志）
	s.sendDeployCallback(ctx, cert, result)

	// 如果所有绑定都部署失败，返回错误
	if enabledCount > 0 && successCount == 0 && result.Error != nil {
		return result, result.Error
	}

	return result, nil
}

// DeployAllCerts 部署所有启用的证书
func (s *Service) DeployAllCerts(ctx context.Context) ([]*DeployResult, error) {
	certs, err := s.cfgManager.ListEnabledCerts()
	if err != nil {
		return nil, fmt.Errorf("获取证书列表失败: %w", err)
	}

	var results []*DeployResult
	for _, cert := range certs {
		result, err := s.DeployOne(ctx, cert.CertName)
		if err != nil {
			results = append(results, &DeployResult{
				CertName: cert.CertName,
				Success:  false,
				Error:    err,
			})
		} else {
			results = append(results, result)
		}
	}

	return results, nil
}

// sendDeployCallback 向 API 发送部署结果回调
// 非关键路径，失败仅记录日志不影响部署结果
func (s *Service) sendDeployCallback(ctx context.Context, cert *config.CertConfig, result *DeployResult) {
	status := "success"
	if !result.Success {
		status = "failure"
	}

	callbackReq := &fetcher.CallbackRequest{
		OrderID:    cert.OrderID,
		Status:     status,
		DeployedAt: time.Now().Format(time.RFC3339),
	}
	if !result.Success {
		callbackReq.Message = callbackMessage(result.Error)
		s.log.Error("证书 %s 部署失败（已上报 failure 回调）: %s", cert.CertName, callbackReq.Message)
	}

	fillCertMetadata(callbackReq, cert)
	s.sendCallback(ctx, cert.GetAPI(s.log), callbackReq)
}

// DeployToBinding 将已获取的证书部署到单个绑定（含证书校验、现有证书备份、失败回滚）。
// 供 setup 等已在外部取得 certData/privateKey 的调用方复用，避免重复实现部署路径。
func (s *Service) DeployToBinding(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string) error {
	return s.deployToBinding(ctx, binding, certData, privateKey)
}

// deployToBinding 部署证书到绑定（带备份和回滚）
func (s *Service) deployToBinding(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string) error {
	// Docker 站点：校验可安全部署（挂载卷模式 + 容器重载命令），否则如实报错而非静默成功
	if config.IsDockerType(binding.ServerType) {
		if err := config.ValidateDockerBinding(binding); err != nil {
			return errors.NewStructuredDeployError(errors.DeployErrorConfig, errors.PhaseWriteCert, err.Error(), nil)
		}
	} else if binding.Reload.ReloadCommand == "" {
		// 非 Docker 站点无重载命令：保留原有跳过行为，但记录告警提示部署后未重载
		s.log.Warn("站点 %s 无重载命令，部署后不会自动重载服务", binding.ServerName)
	}

	// 验证证书与私钥
	v := validator.New("")
	if _, err := v.ValidateCert(certData.Cert); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorValidation, errors.PhaseValidate, "证书验证失败", err)
	}
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorValidation, errors.PhaseValidate, "私钥不匹配", err)
	}

	// 确保目录存在
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := util.EnsureDir(certDir, 0700); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorPermission, errors.PhaseWriteCert, "创建证书目录失败", err)
	}

	// 1. 备份现有证书（如果存在）
	var backupPath string
	existingCert := util.FileExists(binding.Paths.Certificate) && util.FileExists(binding.Paths.PrivateKey)
	if existingCert {
		result, err := s.backupMgr.Backup(binding.ServerName, binding.Paths.Certificate, binding.Paths.PrivateKey, nil, binding.Paths.ChainFile)
		if err != nil {
			// 更新部署（已有证书文件）备份失败时中止，防止部署失败后无法回滚
			return errors.NewStructuredDeployError(errors.DeployErrorPermission, errors.PhaseBackup,
				fmt.Sprintf("备份现有证书失败，中止部署（请检查备份目录权限）: %v", err), err)
		} else if result != nil {
			backupPath = result.BackupPath
			s.log.Debug("已备份证书到: %s", backupPath)
		}
	}

	// 2. 部署（使用 webserver 抽象层）
	deployer, err := webserver.NewDeployer(
		webserver.ServerType(binding.ServerType),
		binding.Paths.Certificate,
		binding.Paths.PrivateKey,
		binding.Paths.ChainFile,
		binding.Reload.TestCommand,
		binding.Reload.ReloadCommand,
	)
	if err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorConfig, errors.PhaseWriteCert, "创建部署器失败", err)
	}
	deployErr := deployer.Deploy(ctx, certData.Cert, certData.IntermediateCert, privateKey)

	// 3. 部署失败时回滚
	if deployErr != nil && backupPath != "" {
		s.log.Warn("部署失败，尝试回滚: %v", deployErr)
		if rollbackErr := s.rollbackFromBackup(ctx, binding, backupPath); rollbackErr != nil {
			s.log.Error("回滚失败: %v", rollbackErr)
			// 构造手动恢复指引
			recoveryCmd := fmt.Sprintf("cp %s %s && cp %s %s",
				util.ShellQuote(backupPath+"/cert.pem"), util.ShellQuote(binding.Paths.Certificate),
				util.ShellQuote(backupPath+"/key.pem"), util.ShellQuote(binding.Paths.PrivateKey))
			if binding.Reload.TestCommand != "" {
				recoveryCmd += " && " + binding.Reload.TestCommand
			}
			if binding.Reload.ReloadCommand != "" {
				recoveryCmd += " && " + binding.Reload.ReloadCommand
			}
			return errors.NewStructuredDeployError(errors.DeployErrorUnknown, errors.PhaseRollback,
				fmt.Sprintf("部署失败且回滚失败（服务可能不可用）: deploy=%v, rollback=%v\n手动恢复: %s", deployErr, rollbackErr, recoveryCmd), nil)
		}
		s.log.Info("已回滚到备份: %s", backupPath)
		// 包裹而非重造错误码：同一根因（如 nginx -t 失败 = Config@test_config）
		// 此前"有备份"被重包成 Reload@reload、"首次部署无备份"原样返回，
		// 相同问题得到相反的错误分类。%w 保留根因，与 cmd/deploy 的写法一致。
		return fmt.Errorf("部署失败（已回滚）: %w", deployErr)
	}

	return deployErr
}

// RollbackBudget 回滚的独立预算。
// 回滚要恢复旧证书并重新 test + reload，就地放弃比慢一点糟得多。
const RollbackBudget = 90 * time.Second

// rollbackFromBackup 从备份回滚证书
// 直接调用 Deployer.Rollback()，包含完整回滚逻辑（文件恢复 + 测试 + 重载）
//
// 回滚必须脱离父 ctx 的取消传播：部署失败往往正是因为 ctx 被取消（关停/检查超时），
// 沿用同一个 ctx 会让兜底回滚当场失败，直接落进"部署失败且回滚失败（服务可能不可用）"
// ——比不贯通 ctx 更糟。改为 WithoutCancel + 独立预算，仍然有界。
func (s *Service) rollbackFromBackup(ctx context.Context, binding *config.SiteBinding, backupPath string) error {
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RollbackBudget)
	defer cancel()

	certPath, keyPath, chainPath := s.backupMgr.GetBackupPathsWithChain(backupPath)

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
		return errors.NewStructuredDeployError(errors.DeployErrorConfig, errors.PhaseRollback, "创建部署器失败", err)
	}

	// 直接调用 Deployer.Rollback，包含完整回滚逻辑
	if err := deployer.Rollback(rbCtx, certPath, keyPath, chainPath); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorPermission, errors.PhaseRollback, "回滚失败", err)
	}
	return nil
}

// pickKeyPath 选择一个可用的私钥路径（优先启用的绑定）
func pickKeyPath(cert *config.CertConfig) string {
	for i := range cert.Bindings {
		// 使用值拷贝而非指针，与 DeployOne 保持一致
		binding := cert.Bindings[i]
		if binding.Enabled && binding.Paths.PrivateKey != "" {
			return binding.Paths.PrivateKey
		}
	}
	if len(cert.Bindings) > 0 {
		return cert.Bindings[0].Paths.PrivateKey
	}
	return ""
}
