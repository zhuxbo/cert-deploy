// Package certops 证书续签逻辑
package certops

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/csr"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// pendingKeyDir 待确认私钥目录
const pendingKeyDir = "pending-keys"

// MaxIssueRetryCount 最大重试次数
const MaxIssueRetryCount = 10

// MaxRenewBatch 单次续签批量上限（借鉴 sslbt）
const MaxRenewBatch = 100

// 多证书分散延迟常量（借鉴 sslbt _calc_spread_delay 策略）
const (
	SpreadTotalMax = 600 // 总分散延迟上限（秒）
	SpreadMin      = 5   // 最小延迟（秒）
	SpreadMax      = 120 // 最大延迟（秒）
)

// MaxRenewBeforeDays renew_before_days 的合理上限（deploy-spec 2.9）。
// 无论续费还是重签，续签动作都应发生在到期前 30 天以内；
// 异常大值会把全部证书拉入"需要续签"状态、触发每日全量续签风暴，视为服务端异常值拒绝。
const MaxRenewBeforeDays = 30

// tryUpdateRenewBeforeDays 如果 API 返回了有效的 renew_before_days，更新本地配置
// 非关键路径，失败仅记录日志；超出合理上限时拒绝并保留旧值
func (s *Service) tryUpdateRenewBeforeDays(renewBeforeDays int) {
	if renewBeforeDays <= 0 {
		return
	}
	if renewBeforeDays > MaxRenewBeforeDays {
		s.log.Warn("服务端返回的 renew_before_days=%d 超过上限 %d（续签应在到期前 30 天内），保留本地配置", renewBeforeDays, MaxRenewBeforeDays)
		return
	}
	if err := s.cfgManager.UpdateSchedule(func(sc *config.ScheduleConfig) {
		sc.RenewBeforeDays = renewBeforeDays
	}); err != nil {
		s.log.Warn("更新 renew_before_days 失败: %v", err)
	} else {
		s.log.Debug("renew_before_days 已更新为 %d（来自服务端）", renewBeforeDays)
	}
}

// calcSpreadDelay 根据待处理证书数量动态计算延迟范围
// 少量证书使用较长间隔，大量证书自动缩短以控制总时长
func calcSpreadDelay(count int) (int, int) {
	if count <= 1 {
		return SpreadMin, SpreadMax
	}
	sMax := SpreadTotalMax / count
	if sMax > SpreadMax {
		sMax = SpreadMax
	}
	if sMax < SpreadMin {
		sMax = SpreadMin
	}
	sMin := sMax / 4
	if sMin < SpreadMin {
		sMin = SpreadMin
	}
	return sMin, sMax
}

// CheckAndRenewAll 检查并续签所有证书
func (s *Service) CheckAndRenewAll(ctx context.Context) ([]*RenewResult, error) {
	cfg, err := s.cfgManager.Load()
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	var results []*RenewResult
	var needsDelay bool // 上一轮是否发起了 API 请求，需要延迟

	// 收集需要处理的证书（续签 + 失败重试 + 触顶上报），计算动态延迟
	pendingCount := 0
	for i := range cfg.Certificates {
		cert := cfg.Certificates[i]
		if !cert.Enabled {
			continue
		}
		// 到期时间未知的证书会发起一次 API 查询回填，计入延迟统计
		if cert.Metadata.CertExpiresAt.IsZero() {
			pendingCount++
			continue
		}
		// 规范 3.2：local 模式 retry_count 超限时前置过滤
		// 临期触顶或已过期触顶都会发一次 failure 回调（可见性），计入延迟统计
		if cert.GetRenewMode(&cfg.Schedule) == config.RenewModeLocal &&
			cert.Metadata.IssueRetryCount >= MaxIssueRetryCount {
			if cert.NeedsRenewal(&cfg.Schedule) || cert.IsExpired() {
				pendingCount++
			}
			continue
		}
		if cert.NeedsRenewal(&cfg.Schedule) || len(cert.Metadata.FailedBindings) > 0 {
			pendingCount++
		}
	}
	if pendingCount > MaxRenewBatch {
		s.log.Warn("待处理证书数 %d 超过批量上限 %d，本次仅处理前 %d 个", pendingCount, MaxRenewBatch, MaxRenewBatch)
		pendingCount = MaxRenewBatch
	}
	spreadMin, spreadMax := calcSpreadDelay(pendingCount)

	processedCount := 0
	for i := range cfg.Certificates {
		// 上一轮处理了证书（发起过 API 请求），随机延迟后再继续
		if needsDelay {
			delay := time.Duration(spreadMin+rand.IntN(spreadMax-spreadMin+1)) * time.Second
			s.log.Debug("等待 %d 秒后处理下一个证书...", int(delay.Seconds()))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return results, ctx.Err()
			case <-timer.C:
			}
		}

		// 使用值拷贝而非指针，确保深拷贝保护有效
		result, madeAPICall := s.processCertRenewal(ctx, cfg, cfg.Certificates[i], &processedCount)
		needsDelay = madeAPICall
		if result != nil {
			results = append(results, result)
		}
	}

	// 更新检查时间（使用原子更新避免覆盖其他并发修改）
	_ = s.cfgManager.UpdateMetadata(func(m *config.ConfigMetadata) {
		m.LastCheckAt = time.Now()
	})

	return results, nil
}

// processCertRenewal 处理单个证书的续签检查。
// 含 panic 隔离：单证书处理 panic 记为该证书失败并计入统计，不拖垮整轮续签。
// 返回 result（nil 表示本证书无需处理）与是否发起过 API 请求（用于证书间分散延迟）。
func (s *Service) processCertRenewal(ctx context.Context, cfg *config.Config, cert config.CertConfig, processedCount *int) (result *RenewResult, madeAPICall bool) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("证书 %s 续签处理 panic（已隔离，继续处理其余证书）: %v", cert.CertName, r)
			result = &RenewResult{
				CertName: cert.CertName,
				Mode:     cert.GetRenewMode(&cfg.Schedule),
				Status:   "failure",
				Error:    fmt.Errorf("续签处理 panic: %v", r),
			}
			// panic 恢复路径同样上报 failure 回调（与其他失败路径的可见性一致）
			s.sendRenewCallback(ctx, &cert, result)
		}
	}()

	if !cert.Enabled {
		return nil, false
	}

	// 逐证书检查 API 配置
	api := cert.GetAPI(s.log)
	if api.URL == "" || api.Token == "" {
		s.log.Warn("证书 %s 的 API 配置不完整，跳过续签", cert.CertName)
		return nil, false
	}

	// 到期时间未知（部署成功但元数据保存失败、带外换证等）：
	// 语义为"未知需处理"，先查询 API 回填元数据再按正常逻辑判定，
	// 避免"永不续签 + 告警盲区"双盲
	if cert.Metadata.CertExpiresAt.IsZero() {
		madeAPICall = true
		if !s.refreshExpiryFromAPI(ctx, &cert, api) {
			return nil, madeAPICall
		}
	}

	// 前置过滤：local 模式重试超限（规范 3.2 停止自动操作）
	// 但需保证可见性：Error 日志 + 计入本轮统计 + 上报 failure 带原因，避免静默永久死锁
	if cert.GetRenewMode(&cfg.Schedule) == config.RenewModeLocal &&
		cert.Metadata.IssueRetryCount >= MaxIssueRetryCount {
		if !cert.NeedsRenewal(&cfg.Schedule) {
			// 既过期又触顶：证书已死且自动续签已停，与下方"临期触顶"路径对齐上报可见性，
			// 不再静默（否则 Error 日志 / failure 回调 / 统计三缺，运维无从感知需人工处理）。
			// 未过期、只是尚未进入续签窗口的触顶证书仍静默跳过（无需处理，避免每日噪声）。
			if cert.IsExpired() {
				s.log.Error("证书 %s 已过期且重试次数达上限 (%d)，已停止自动续签，需人工处理", cert.CertName, MaxIssueRetryCount)
				madeAPICall = true
				result = &RenewResult{
					CertName: cert.CertName,
					Mode:     config.RenewModeLocal,
					Status:   "failure",
					Error:    fmt.Errorf("证书已过期且重试超限，需人工处理"),
				}
				s.sendRenewCallback(ctx, &cert, result)
				return result, madeAPICall
			}
			return nil, madeAPICall
		}
		s.log.Error("证书 %s 重试次数已达上限 (%d)，已停止自动续签，需人工处理", cert.CertName, MaxIssueRetryCount)
		madeAPICall = true
		result = &RenewResult{
			CertName: cert.CertName,
			Mode:     config.RenewModeLocal,
			Status:   "failure",
			Error:    fmt.Errorf("重试次数已达上限 (%d)，已停止自动续签，需人工处理", MaxIssueRetryCount),
		}
		s.sendRenewCallback(ctx, &cert, result)
		return result, madeAPICall
	}

	// 重试失败的绑定（证书有效但部分绑定上次部署失败）
	if !cert.NeedsRenewal(&cfg.Schedule) && len(cert.Metadata.FailedBindings) > 0 {
		if *processedCount >= MaxRenewBatch {
			return nil, madeAPICall
		}
		*processedCount++
		madeAPICall = true
		s.log.Info("证书 %s 重试 %d 个失败绑定...", cert.CertName, len(cert.Metadata.FailedBindings))
		result = s.retryFailedBindings(ctx, &cert, api)
		// 与主路径一致：有明确结果时发送回调（pending 不发）
		if result.Status == "success" || result.Status == "failure" {
			s.sendRenewCallback(ctx, &cert, result)
		}
		return result, madeAPICall
	}

	// 检查是否需要续期
	if !cert.NeedsRenewal(&cfg.Schedule) {
		s.log.Debug("证书 %s 有效期充足，跳过", cert.CertName)
		return nil, madeAPICall
	}

	if *processedCount >= MaxRenewBatch {
		return nil, madeAPICall
	}
	*processedCount++

	// 将发起 API 请求：提前置位，panic 恢复路径也保留证书间延迟语义
	madeAPICall = true

	s.log.Info("证书 %s 需要续期，开始处理...", cert.CertName)

	mode := cert.GetRenewMode(&cfg.Schedule)
	result = &RenewResult{
		CertName: cert.CertName,
		Mode:     mode,
	}

	var (
		certData   *fetcher.CertData
		privateKey string
		err        error
	)

	if mode == config.RenewModeLocal {
		certData, privateKey, err = s.prepareLocalRenew(ctx, &cert, api)
	} else {
		certData, privateKey, err = s.preparePullRenew(ctx, &cert, api)
	}

	if err != nil {
		result.Status = "failure"
		result.Error = err
		s.log.Warn("证书 %s 续签失败: %v", cert.CertName, err)
		// prepare 阶段失败同样上报回调（原实现跳过了后面的回调块，服务端无法感知失败）
		s.sendRenewCallback(ctx, &cert, result)
		return result, madeAPICall
	}

	if certData == nil {
		result.Status = "pending"
		return result, madeAPICall
	}

	// 部署证书
	deployCount, _, deployErr := s.deployCertToBindings(ctx, &cert, certData, privateKey)
	result.DeployCount = deployCount
	if deployErr != nil {
		result.Status = "failure"
		result.Error = deployErr
	} else {
		result.Status = "success"
	}

	// 始终持久化元数据（deployCertToBindings 内部已更新 CertExpiresAt、FailedBindings 等）
	if err := s.cfgManager.UpdateCert(&cert); err != nil {
		s.log.Warn("更新证书元数据失败: %v", err)
	}

	// 发送续签回调（仅在有明确结果时）
	if result.Status == "success" || result.Status == "failure" {
		s.sendRenewCallback(ctx, &cert, result)
	}

	return result, madeAPICall
}

// resetIssueStateForResubmit 本轮 local 签发流程失效（pending 私钥丢失等）时重置签发状态，
// 使下一轮续签检查走重新提交 CSR 路径（提交时递增 issue_retry_count，受 10 次上限约束，
// 触顶后停止并上报，符合规范 3.5 生命周期），避免 processing 状态永久卡死
func (s *Service) resetIssueStateForResubmit(cert *config.CertConfig, cause error) error {
	cert.Metadata.LastIssueState = ""
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("重置证书 %s 签发状态失败: %v", cert.CertName, err)
	}
	return fmt.Errorf("%w（已重置签发状态，下轮将重新提交 CSR）", cause)
}

// refreshExpiryFromAPI 到期时间未知时查询 API 回填证书元数据，返回是否回填成功
// 查询失败或服务端无证书内容时记录告警并返回 false（下轮续签检查会再次尝试）
func (s *Service) refreshExpiryFromAPI(ctx context.Context, cert *config.CertConfig, api config.APIConfig) bool {
	certData, renewBeforeDays, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		s.log.Warn("证书 %s 到期时间未知且查询失败，跳过本轮: %v", cert.CertName, err)
		return false
	}
	s.tryUpdateRenewBeforeDays(renewBeforeDays)
	s.syncOrderID(cert, certData)
	if certData.Cert == "" {
		s.log.Warn("证书 %s 到期时间未知且服务端未返回证书内容 (status=%s)，跳过本轮", cert.CertName, certData.Status)
		return false
	}
	parsed, err := validator.New("").ValidateCert(certData.Cert)
	if err != nil || parsed == nil {
		s.log.Warn("证书 %s 回填到期时间失败（证书解析错误）: %v", cert.CertName, err)
		return false
	}
	cert.Metadata.CertExpiresAt = parsed.NotAfter
	cert.Metadata.CertSerial = fmt.Sprintf("%X", parsed.SerialNumber)
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("证书 %s 回填元数据保存失败: %v", cert.CertName, err)
	}
	s.log.Info("证书 %s 到期时间已从服务端回填: %s", cert.CertName, parsed.NotAfter.Format("2006-01-02"))
	return true
}

// retryMaxDays 失败绑定重试的最大天数，超过后放弃重试
const retryMaxDays = 7

// retryFailedBindings 重试上次部署失败的绑定
// 返回 RenewResult 供上层统计
func (s *Service) retryFailedBindings(ctx context.Context, cert *config.CertConfig, api config.APIConfig) *RenewResult {
	result := &RenewResult{
		CertName: cert.CertName,
		Mode:     "retry",
	}

	// 超过重试期限，放弃重试并清空
	if !cert.Metadata.FailedBindingsAt.IsZero() &&
		time.Since(cert.Metadata.FailedBindingsAt) > retryMaxDays*24*time.Hour {
		s.log.Warn("证书 %s 失败绑定重试已超过 %d 天，放弃重试", cert.CertName, retryMaxDays)
		cert.Metadata.FailedBindings = nil
		cert.Metadata.FailedBindingsAt = time.Time{}
		_ = s.cfgManager.UpdateCert(cert)
		result.Status = "failure"
		result.Error = fmt.Errorf("failed bindings retry expired after %d days", retryMaxDays)
		return result
	}

	certData, _, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		s.log.Warn("重试失败绑定: 查询证书 %s 失败: %v", cert.CertName, err)
		result.Status = "failure"
		result.Error = err
		return result
	}
	s.syncOrderID(cert, certData)
	if certData.Status != "active" || certData.Cert == "" || certData.IntermediateCert == "" {
		s.log.Warn("重试失败绑定: 证书 %s 未就绪 (status=%s)", cert.CertName, certData.Status)
		result.Status = "pending"
		return result
	}

	// pending 感知：续签部署全失败后 pending 私钥尚未转正，重试须能读到它，
	// 否则旧私钥与新证书配对必败，重试期满后站点走向真实过期
	privateKey, err := GetPrivateKeyForCert(s.cfgManager.GetWorkDir(), cert, certData.Cert, certData.PrivateKey, s.log)
	if err != nil {
		s.log.Warn("重试失败绑定: 获取私钥失败: %v", err)
		result.Status = "failure"
		result.Error = err
		return result
	}

	// 构建失败绑定集合用于快速查找
	failedSet := make(map[string]bool, len(cert.Metadata.FailedBindings))
	for _, name := range cert.Metadata.FailedBindings {
		failedSet[name] = true
	}

	var stillFailed []string
	for j := range cert.Bindings {
		binding := cert.Bindings[j]
		if !binding.Enabled || !failedSet[binding.ServerName] {
			continue
		}
		if err := s.deployToBinding(ctx, &binding, certData, privateKey); err != nil {
			s.log.Error("重试部署到 %s 失败: %v", binding.ServerName, err)
			stillFailed = append(stillFailed, binding.ServerName)
			continue
		}
		s.log.Info("重试部署到 %s 成功", binding.ServerName)
		result.DeployCount++
	}

	cert.Metadata.FailedBindings = stillFailed
	if len(stillFailed) == 0 {
		cert.Metadata.LastDeployAt = time.Now()
		cert.Metadata.FailedBindingsAt = time.Time{}
		result.Status = "success"
	} else {
		result.Status = "failure"
		result.Error = fmt.Errorf("%d 个绑定仍然失败", len(stillFailed))
	}
	// 重试部署成功后补转正 pending 私钥（若本次使用的正是 pending 私钥）
	if result.DeployCount > 0 {
		s.commitPendingKeyAfterDeploy(cert, privateKey)
	}
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("更新证书元数据失败: %v", err)
	}
	return result
}

// callbackMessageMaxLen 回调 message 字段最大长度（按 rune 计）。
// 服务端上限为 500，客户端取更严格的 256，超长整条会被服务端拒收。
const callbackMessageMaxLen = 256

// callbackMessage 从失败错误生成回调 message：先脱敏（复用 logger 过滤规则）再按 rune 截断，
// 确保 Bearer token / 私钥块 / URL token 参数不会随失败原因泄漏进回调请求体。
func callbackMessage(err error) string {
	if err == nil {
		return ""
	}
	return truncateRunes(logger.Sanitize(err.Error()), callbackMessageMaxLen)
}

// truncateRunes 按 rune 截断字符串，不劈开多字节字符
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

// sendRenewCallback 向 API 发送续签结果回调
// 非关键路径，失败仅记录日志（传输层已含网络错误/5xx 的指数退避重试）
// 失败回调携带脱敏后的原因摘要（message，仅 failure），同时记本地 Error 日志（spec 2.8）
func (s *Service) sendRenewCallback(ctx context.Context, cert *config.CertConfig, result *RenewResult) {
	callbackReq := &fetcher.CallbackRequest{
		OrderID:    cert.OrderID,
		Status:     result.Status,
		DeployedAt: time.Now().Format(time.RFC3339),
	}
	if result.Status == "failure" {
		callbackReq.Message = callbackMessage(result.Error)
		s.log.Error("证书 %s 续签失败（已上报 failure 回调）: %s", cert.CertName, callbackReq.Message)
	}

	fillCertMetadata(callbackReq, cert)
	renewBeforeDays := s.sendCallback(ctx, cert.GetAPI(s.log), callbackReq)
	s.tryUpdateRenewBeforeDays(renewBeforeDays)
}

// getRenewMode 获取续签模式（带默认值）
func getRenewMode(schedule *config.ScheduleConfig) string {
	mode := schedule.RenewMode
	if mode == "" {
		return config.RenewModePull
	}
	return mode
}

// preparePullRenew 自动签发：等待服务端续签完成后拉取证书
func (s *Service) preparePullRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig) (*fetcher.CertData, string, error) {
	certData, renewBeforeDays, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return nil, "", err
	}
	s.tryUpdateRenewBeforeDays(renewBeforeDays)
	s.syncOrderID(cert, certData)
	if certData.Status != "active" || certData.Cert == "" {
		// processing + 文件验证：放置验证文件（全部放置失败按失败处理，避免静默永远 pending）
		if certData.Status == "processing" {
			if err := s.applyValidationFiles(cert, certData.File, true); err != nil {
				return nil, "", err
			}
		}
		s.log.Debug("证书 %s 状态: %s，跳过", cert.CertName, certData.Status)
		return nil, "", nil
	}

	if certData.IntermediateCert == "" {
		return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取（pending 感知，配对校验）
	privateKey, err := GetPrivateKeyForCert(s.cfgManager.GetWorkDir(), cert, certData.Cert, certData.PrivateKey, s.log)
	if err != nil {
		return nil, "", err
	}
	return certData, privateKey, nil
}

// prepareLocalRenew 本机提交：生成 CSR 并通过 API 触发续签
func (s *Service) prepareLocalRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig) (*fetcher.CertData, string, error) {
	// 检查重试次数是否超限
	if cert.Metadata.IssueRetryCount >= MaxIssueRetryCount {
		s.log.Error("证书 %s 重试次数已达上限 (%d)，等待人工处理", cert.CertName, MaxIssueRetryCount)
		return nil, "", fmt.Errorf("exceeded max retry count (%d)", MaxIssueRetryCount)
	}

	workDir := s.cfgManager.GetWorkDir()
	keyPath := pickKeyPath(cert)
	if keyPath == "" {
		return nil, "", fmt.Errorf("missing local private key path")
	}

	// 上次提交仍在处理中（processing），或已秒签为 active 但尚未部署成功：
	// 两者都先查询当前订单状态，据结果读取 pending 私钥复用部署路径，
	// 避免重新生成 CSR 覆盖与已签发证书配对的 pending 私钥（秒签全失败续跑关键分支）。
	entryState := cert.Metadata.LastIssueState
	if entryState == "processing" || entryState == "active" {
		// 规范 3.5：证书已过期则停止，等待人工处理
		// 按时间点判定，避免整数天截断使过期不足 24 小时的证书仍被继续处理
		if cert.IsExpired() {
			s.log.Error("证书 %s 已过期且签发未完成部署（状态 %s），等待人工处理", cert.CertName, entryState)
			return nil, "", fmt.Errorf("证书已过期，等待人工处理")
		}
		certData, renewBeforeDays, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
		if err != nil {
			return nil, "", fmt.Errorf("查询订单失败: %w", err)
		}
		s.tryUpdateRenewBeforeDays(renewBeforeDays)
		s.syncOrderID(cert, certData)

		switch certData.Status {
		case "active":
			if certData.Cert == "" {
				// active 但证书内容为空，继续等待
				s.log.Debug("证书 %s 状态 active 但内容为空，跳过", cert.CertName)
				return nil, "", nil
			}
			if certData.IntermediateCert == "" {
				return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
			}
			// 签发成功，尝试读取待确认私钥（仅读取内容，不动线上私钥；
			// 转正在部署成功后由 deployCertToBindings 执行，遵循规范 3.8）
			privateKey, err := readPendingKey(workDir, cert.CertName)
			usedFallbackKey := false
			if err != nil {
				// pending 私钥缺失（历史 order_id 变更未迁移、被误删等）：回退到正式私钥
				keyData, readErr := util.SafeReadFile(keyPath, config.MaxPrivateKeySize)
				if readErr != nil {
					// pending 与正式私钥都不可用：本轮签发流程已失效，重置状态走重新提交 CSR
					return nil, "", s.resetIssueStateForResubmit(cert,
						fmt.Errorf("pending 私钥缺失且正式私钥不可读: %w", readErr))
				}
				privateKey = string(keyData)
				usedFallbackKey = true
			}
			// 部署前先校验服务端返回的证书与私钥配对，
			// 不配对时按失败处理（pending 私钥保留、线上私钥不受影响）
			if err := validator.New("").ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
				if usedFallbackKey {
					// pending 缺失且正式私钥也不配对：无法完成本轮签发，
					// 若不重置状态会每天走到这里且 retry 不递增，永久卡死。
					// 重置后下轮重新提交 CSR（提交时递增 retry，受上限约束）
					return nil, "", s.resetIssueStateForResubmit(cert,
						fmt.Errorf("pending 私钥缺失且正式私钥与服务端证书不配对: %w", err))
				}
				return nil, "", fmt.Errorf("服务端返回的证书与本地私钥不配对（pending 私钥已保留，线上私钥未改动）: %w", err)
			}
			// active 自愈（秒签已签发、等待部署）：每次进入即一次部署尝试，递增 issue_retry_count，
			// 使"证书已签发但全部绑定部署失败"的续跑循环受 MaxIssueRetryCount 约束并最终触顶停机上报，
			// 而非无限次重试部署已签发证书。计数持久化交由上层 deployCertToBindings 后的 UpdateCert
			// （部署成功复位为 0、失败保留递增值，与既有路径一致）。
			// processing 首签路径不在此计数，保持既有语义（其计数在提交 CSR 时已递增）。
			if entryState == "active" {
				cert.Metadata.IssueRetryCount++
			}
			return certData, privateKey, nil

		case "processing":
			// 放置验证文件（如果有新的；全部放置失败按失败处理，避免静默永远 pending）
			if err := s.applyValidationFiles(cert, certData.File, true); err != nil {
				return nil, "", err
			}
			s.log.Debug("证书 %s CSR 正在处理，跳过", cert.CertName)
			return nil, "", nil

		default:
			// 其他状态（包括证书已过期或异常）：更新状态后停止，等待人工处理
			// 持久化实际状态，避免下次仍进入 processing 分支反复触发回调
			cert.Metadata.LastIssueState = certData.Status
			_ = s.cfgManager.UpdateCert(cert)
			s.log.Error("证书 %s 订单状态异常: %s，等待人工处理", cert.CertName, certData.Status)
			return nil, "", fmt.Errorf("订单状态异常: %s，等待人工处理", certData.Status)
		}
	}

	// 生成新的私钥与 CSR
	commonName := ""
	if len(cert.Domains) > 0 {
		commonName = cert.Domains[0]
	}
	if commonName == "" {
		return nil, "", fmt.Errorf("缺少域名，无法生成 CSR")
	}

	privateKey, csrPEM, csrHash, err := csr.GenerateKeyAndCSR(csr.KeyOptions{}, csr.CSROptions{
		CommonName: commonName,
	})
	if err != nil {
		return nil, "", fmt.Errorf("生成 CSR 失败: %w", err)
	}

	// 新私钥保存到待确认目录（不覆盖正式私钥）
	if err := savePendingKey(workDir, cert.CertName, privateKey); err != nil {
		return nil, "", fmt.Errorf("保存待确认私钥失败: %w", err)
	}

	// CSR 成功提交前先递增并持久化重试计数（确保计数不会丢失）
	cert.Metadata.IssueRetryCount++
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		// 持久化失败时回滚内存中的计数，避免不一致
		cert.Metadata.IssueRetryCount--
		if cleanupErr := cleanupPendingKey(workDir, cert.CertName); cleanupErr != nil {
			s.log.Warn("清理待确认私钥失败: %v", cleanupErr)
		}
		return nil, "", fmt.Errorf("持久化重试计数失败: %w", err)
	}

	certData, renewBeforeDaysFromUpdate, err := s.fetcher.Update(ctx, api.URL, api.Token, cert.OrderID, csrPEM, strings.Join(cert.Domains, ","), cert.ValidationMethod)
	if err != nil {
		// 提交失败，清理待确认私钥（重试计数已持久化，下次重试会使用）
		if cleanupErr := cleanupPendingKey(workDir, cert.CertName); cleanupErr != nil {
			s.log.Warn("清理待确认私钥失败: %v", cleanupErr)
		}
		return nil, "", fmt.Errorf("提交 CSR 失败: %w", err)
	}
	s.tryUpdateRenewBeforeDays(renewBeforeDaysFromUpdate)

	s.syncOrderID(cert, certData)

	cert.Metadata.CSRSubmittedAt = time.Now()
	cert.Metadata.LastCSRHash = csrHash
	cert.Metadata.LastIssueState = certData.Status

	if certData.Status != "active" || certData.Cert == "" {
		// 放置验证文件（如果有；全部放置失败按失败处理，但先保存元数据，
		// LastIssueState=processing 已持久化，下轮走 processing 分支重试放置）
		placeErr := s.applyValidationFiles(cert, certData.File, false)
		// 保存元数据变更（OrderID、CSRSubmittedAt、ValidationFiles 等）
		if err := s.cfgManager.UpdateCert(cert); err != nil {
			s.log.Warn("保存证书元数据失败: %v", err)
		}
		if placeErr != nil {
			return nil, "", placeErr
		}
		s.log.Info("证书 %s CSR 已提交，等待签发 (status=%s)", cert.CertName, certData.Status)
		return nil, "", nil
	}

	if certData.IntermediateCert == "" {
		return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
	}

	// 部署前先校验服务端返回的证书与本次生成的私钥配对，
	// 不配对（如服务端返回旧订单证书）时按失败处理，pending 私钥保留、线上私钥不受影响。
	// 注意：私钥转正在部署成功后由 deployCertToBindings 执行，遵循规范 3.8。
	if err := validator.New("").ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return nil, "", fmt.Errorf("服务端返回的证书与本次 CSR 私钥不配对（pending 私钥已保留，线上私钥未改动）: %w", err)
	}

	// 秒签：服务端在提交 CSR 后立即返回 active 证书。此处不清零签发状态——
	// 部署可能全部失败，一旦清零，下轮 NeedsRenewal 仍为 true 却因状态为空重新生成 CSR，
	// 覆盖与本次已签发证书配对的 pending 私钥，且 IssueRetryCount 复位旁路 MaxIssueRetryCount 停机保护，
	// 每个续签周期重签一次直到旧证书过期。
	// 保留 CSRSubmittedAt/LastCSRHash/IssueRetryCount，持久化 LastIssueState="active" 作为崩溃安全网，
	// 使部署失败后下轮走 active 自愈分支：查询订单→读 pending→配对→复用部署路径。
	// 部署成功由 deployCertToBindings 统一清零状态并转正 pending（规范 3.8）。
	cert.Metadata.LastIssueState = "active"
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("保存证书元数据失败: %v", err)
	}

	return certData, privateKey, nil
}

// deployCertToBindings 部署证书到所有绑定
// 返回：成功部署数、失败的绑定 ServerName 列表、最后一个错误
func (s *Service) deployCertToBindings(ctx context.Context, cert *config.CertConfig, certData *fetcher.CertData, privateKey string) (int, []string, error) {
	// 验证证书与私钥
	v := validator.New("")
	parsedCert, err := v.ValidateCert(certData.Cert)
	if err != nil || parsedCert == nil {
		return 0, nil, fmt.Errorf("证书验证失败: %w", err)
	}
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return 0, nil, fmt.Errorf("私钥不匹配: %w", err)
	}

	// 部署到所有绑定
	deployCount := 0
	var lastErr error
	var failedBindings []string
	for j := range cert.Bindings {
		// 使用值拷贝而非指针，确保深拷贝保护有效
		binding := cert.Bindings[j]
		if !binding.Enabled {
			continue
		}

		if err := s.deployToBinding(ctx, &binding, certData, privateKey); err != nil {
			s.log.Error("部署到 %s 失败: %v", binding.ServerName, err)
			lastErr = err
			failedBindings = append(failedBindings, binding.ServerName)
			continue
		}
		s.log.Info("证书已部署到 %s", binding.ServerName)
		deployCount++
	}

	cert.Metadata.FailedBindings = failedBindings
	if len(failedBindings) > 0 && cert.Metadata.FailedBindingsAt.IsZero() {
		cert.Metadata.FailedBindingsAt = time.Now()
	} else if len(failedBindings) == 0 {
		cert.Metadata.FailedBindingsAt = time.Time{}
	}

	// 元数据不变式：仅至少一个绑定部署成功后才更新证书元数据与 CSR 状态。
	// 全部失败时保持旧 CertExpiresAt/Domains 与 pending 状态，下轮 NeedsRenewal 仍为 true，
	// 走完整 prepare→读 pending→部署 的自愈循环；若提前更新 CertExpiresAt，
	// 下轮只会走 retryFailedBindings，而未转正的 pending 私钥读不到，
	// 旧私钥与新证书配对必败，站点将挂着旧证书走向真实过期。
	if deployCount > 0 {
		// 从证书 PEM 提取域名更新配置（规范 5.5：确保 domains 反映实际部署的证书内容）
		if domains := extractDomainsFromParsedCert(parsedCert); len(domains) > 0 {
			cert.Domains = domains
		}
		cert.Metadata.CertExpiresAt = parsedCert.NotAfter
		cert.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)
		cert.Metadata.LastDeployAt = time.Now()
		// 部署成功后才将 pending 私钥转正（规范 3.8：部署成功后清理 pending key）。
		// 部署路径（deployToBinding）已在覆盖前备份各绑定的旧证书与私钥。
		s.commitPendingKeyAfterDeploy(cert, privateKey)
		// 成功后清理本地续签状态
		cert.Metadata.CSRSubmittedAt = time.Time{}
		cert.Metadata.LastCSRHash = ""
		cert.Metadata.LastIssueState = ""
		cert.Metadata.IssueRetryCount = 0
	}

	// 清理验证文件：签发已完成（拿到证书）后验证文件用途已尽，
	// 无论部署成败都清理，避免部署全失败时验证文件残留在 webroot
	if len(cert.Metadata.ValidationFiles) > 0 {
		cleanupValidationFiles(cert.Metadata.ValidationFiles, s.log)
		cert.Metadata.ValidationFiles = nil
	}

	return deployCount, failedBindings, lastErr
}

// commitPendingKeyAfterDeploy 部署成功后将 pending 私钥转正（Service 包装）
func (s *Service) commitPendingKeyAfterDeploy(cert *config.CertConfig, deployedKey string) {
	CommitPendingKeyIfMatches(s.cfgManager.GetWorkDir(), cert, deployedKey, s.log)
}

// CommitPendingKeyIfMatches 部署成功后将与已部署私钥一致的 pending 私钥转正并清理 pending 文件。
// 供续签、失败绑定重试与 CLI 手动部署链共用（规范 3.8：部署成功后清理 pending key）。
// 仅当 pending 内容与本次部署使用的私钥一致才转正，防止误转不相关的残留文件
// （pull 模式或已清理时无 pending 文件，直接跳过）。
// 转正失败不影响部署结果：各绑定已通过部署路径写入新私钥，仅记录告警。
func CommitPendingKeyIfMatches(workDir string, cert *config.CertConfig, deployedKey string, log *logger.Logger) {
	pendingKey, err := readPendingKey(workDir, cert.CertName)
	if err != nil {
		return // 无 pending 私钥（pull 模式或已清理）
	}
	if pendingKey != deployedKey {
		if log != nil {
			log.Warn("证书 %s 的 pending 私钥与本次部署私钥不一致，保留 pending 文件待人工确认", cert.CertName)
		}
		return
	}
	keyPath := pickKeyPath(cert)
	if keyPath == "" {
		return
	}
	if err := commitPendingKey(workDir, cert.CertName, keyPath); err != nil && log != nil {
		log.Warn("转正 pending 私钥失败（部署已成功，不影响本次结果）: %v", err)
	}
}

// getPendingKeyPath 获取待确认私钥路径
func getPendingKeyPath(workDir, certName string) string {
	return filepath.Join(workDir, pendingKeyDir, certName, "pending-key.pem")
}

// savePendingKey 保存待确认私钥到临时位置
func savePendingKey(workDir, certName, keyPEM string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	pendingDir := filepath.Dir(pendingPath)
	if err := util.EnsureDir(pendingDir, 0700); err != nil {
		return err
	}
	return util.AtomicWrite(pendingPath, []byte(keyPEM), 0600)
}

// readPendingKey 读取待确认私钥
// 使用 SafeReadFile 进行安全读取：大小限制 + 符号链接防护 + TOCTOU 保护
func readPendingKey(workDir, certName string) (string, error) {
	pendingPath := getPendingKeyPath(workDir, certName)
	data, err := util.SafeReadFile(pendingPath, config.MaxPrivateKeySize)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// commitPendingKey 签发成功后将待确认私钥移动到正式位置
// 失败时错误信息包含相对路径（脱敏），便于手动恢复
func commitPendingKey(workDir, certName, targetPath string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Lstat(pendingPath); os.IsNotExist(err) {
		return nil // 不存在则跳过
	}
	// 相对路径用于错误消息（脱敏）
	pendingRelPath := filepath.Join(pendingKeyDir, certName, "pending-key.pem")

	// 确保目标目录存在
	targetDir := filepath.Dir(targetPath)
	if err := util.EnsureDir(targetDir, 0700); err != nil {
		return fmt.Errorf("创建目标目录失败: %w (pending 私钥保留在: %s，请手动恢复)", err, pendingRelPath)
	}
	// 移动文件
	if err := os.Rename(pendingPath, targetPath); err != nil {
		// 如果跨文件系统，使用原子写入：先写临时文件，再重命名
		data, readErr := os.ReadFile(pendingPath)
		if readErr != nil {
			// 读取失败，保留 pending 私钥以便手动恢复
			return fmt.Errorf("读取待确认私钥失败: %w (pending 私钥保留在: %s，请手动恢复)", readErr, pendingRelPath)
		}
		// 使用 AtomicWrite 安全写入（带符号链接防护）
		if writeErr := util.AtomicWrite(targetPath, data, 0600); writeErr != nil {
			// 清零内存中的私钥材料
			for i := range data {
				data[i] = 0
			}
			return fmt.Errorf("写入目标私钥失败: %w (pending 私钥保留在: %s，请手动恢复)", writeErr, pendingRelPath)
		}
		// 清零内存中的私钥材料
		for i := range data {
			data[i] = 0
		}
		// 成功后才清理 pending 私钥
		_ = os.Remove(pendingPath)
	}
	// 清理待确认目录
	_ = os.Remove(filepath.Dir(pendingPath))
	return nil
}

// extractDomainsFromParsedCert 从已解析的证书中提取域名：SAN（DNSNames + IPAddresses）优先，CN 补充
func extractDomainsFromParsedCert(cert *x509.Certificate) []string {
	seen := make(map[string]bool)
	var domains []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	for _, d := range cert.DNSNames {
		add(d)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	add(cert.Subject.CommonName)
	return domains
}

// renamePendingKey 证书改名（order_id 变更）时迁移 pending 私钥（不存在则跳过）
// pending 私钥按 certName 组织，不迁移会导致 local 模式续签读不到 pending key
func renamePendingKey(workDir, oldName, newName string) error {
	oldPath := getPendingKeyPath(workDir, oldName)
	if _, err := os.Lstat(oldPath); os.IsNotExist(err) {
		return nil
	}
	newPath := getPendingKeyPath(workDir, newName)
	if err := util.EnsureDir(filepath.Dir(newPath), 0700); err != nil {
		return err
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	// 清理旧的空目录
	_ = os.Remove(filepath.Dir(oldPath))
	return nil
}

// cleanupPendingKey 清理待确认私钥，返回清理过程中遇到的第一个错误
func cleanupPendingKey(workDir, certName string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	var firstErr error
	if err := os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
		firstErr = err
	}
	if err := os.Remove(filepath.Dir(pendingPath)); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

