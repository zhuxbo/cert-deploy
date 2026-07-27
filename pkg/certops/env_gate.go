package certops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// blockReasonMaxLen 阻断原因的截断长度（按 rune）。
// 原因会进入回调 message（服务端上限 500）与面板展示，nginx -t 的多行输出需压平限长。
const blockReasonMaxLen = 256

// runConfigTestFunc 执行配置测试命令，包一层方便测试替换（与 deployer 包同风格）。
// 默认走 executor.RunWithin：白名单校验 + 单命令 30s 上限 + 上游 ctx 取二者更早者。
var runConfigTestFunc = executor.RunWithin

// probeWebConfig 探测本证书涉及的 Web 服务配置是否健康。
// 返回空串表示健康，非空为压平后的失败原因。
//
// 按 TestCommand 去重后逐条执行：`nginx -t` 这类检查天然全局——任何一个无关站点的
// 坏配置都会让它失败，因此一张证书绑 10 个 nginx 站点也只需执行一次。
// 无 TestCommand 的绑定跳过（无从判断，不能凭空报阻断）。
func (s *Service) probeWebConfig(ctx context.Context, cert *config.CertConfig) string {
	seen := make(map[string]bool)
	for i := range cert.Bindings {
		b := &cert.Bindings[i]
		if !b.Enabled {
			continue
		}
		cmd := strings.TrimSpace(b.Reload.TestCommand)
		if cmd == "" || seen[cmd] {
			continue
		}
		seen[cmd] = true

		if err := runConfigTestFunc(ctx, cmd); err != nil {
			return compactBlockReason(fmt.Sprintf("%s: %v", cmd, err))
		}
	}
	return ""
}

// compactBlockReason 压平多行输出并限长（nginx -t 输出常含换行与长路径）
func compactBlockReason(reason string) string {
	compact := strings.Join(strings.Fields(reason), " ")
	compact = logger.Sanitize(compact)
	return truncateRunes(compact, blockReasonMaxLen)
}

// checkDeployEnvironment 部署前环境闸门：Web 配置本就损坏时放弃本轮部署。
// 返回空串表示可以继续部署，非空为阻断原因（调用方据此按失败收敛）。
//
// 为什么做成部署**前**的闸门，而不是部署失败后的事后分类：坏配置下 reload 必然失败，
// 而那时证书文件已被改写、还要触发回滚——写进去既不生效又多一次改写风险。
//
// 计数语义：阻断不递增 DeployAttemptCount。否则一个无关站点的坏配置会在 10 轮后把
// 所有证书静默推入 CAPPED，且配置修好后还需人工解除；不计数则修好即自动恢复。
// 边界由 BlockReportCount 封顶提供（见 §2.8）。
//
// 回调语义：仍按「明确部署失败」上报（spec §2.8 排除的只有触顶/过期/停更/policy 阻断）。
// 服务端以「订单最新一条上报仍为 failure」做状态判定并按 TTL 提醒，不上报会让该订单
// 从服务端的失败视图里消失，那才是真正的静默过期。
func (s *Service) checkDeployEnvironment(ctx context.Context, cert *config.CertConfig, api config.APIConfig) string {
	reason := s.probeWebConfig(ctx, cert)
	if reason == "" {
		s.clearDeployBlock(cert)
		return ""
	}

	message := "Web 服务配置校验失败（非本次部署导致）: " + reason
	s.log.Error("证书 %s 环境阻断，本轮跳过部署且不计数: %s", cert.CertName, reason)

	prevReason := cert.Metadata.LastDeployBlockReason
	cert.Metadata.LastDeployBlockReason = message
	cert.Metadata.LastDeployBlockAt = time.Now()
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("持久化证书 %s 环境阻断标记失败: %v", cert.CertName, err)
	}

	s.reportBlockOnce(ctx, cert, api, message, prevReason)
	return message
}

// clearDeployBlock 环境恢复后清除阻断标记，避免面板一直显示已消失的旧原因。
// 同时清零上报计数：环境真的恢复过，下次再坏是新一轮故障，应当重新获得完整额度。
func (s *Service) clearDeployBlock(cert *config.CertConfig) {
	if cert.Metadata.LastDeployBlockReason == "" &&
		cert.Metadata.LastDeployBlockAt.IsZero() &&
		cert.Metadata.BlockReportCount == 0 {
		return
	}
	cert.Metadata.LastDeployBlockReason = ""
	cert.Metadata.LastDeployBlockAt = time.Time{}
	cert.Metadata.BlockReportCount = 0
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("清除证书 %s 环境阻断标记失败: %v", cert.CertName, err)
	}
	s.log.Info("证书 %s 的 Web 服务配置已恢复，解除环境阻断（上报额度重置）", cert.CertName)
}

// reportBlockOnce 阻断上报的统一闸门：原因变化才发，且总次数封顶。
//
// 「原因相等就不发」这一道抑制不足以构成边界——原因串由命令输出与异常文本拼成，
// 含 PID / 路径 / 时间等可变内容时每轮都算"变化"；环境好坏抖动时每次复发也重新触发。
// 因此必须叠加次数封顶，由 clearDeployBlock 在环境恢复时清零：
// 长期坏 → 转静默，坏后修好 → 额度重置。
func (s *Service) reportBlockOnce(ctx context.Context, cert *config.CertConfig, api config.APIConfig, message, prevReason string) {
	if message == prevReason {
		return
	}
	if cert.Metadata.BlockReportCount >= config.MaxBlockReportCount {
		s.log.Warn("证书 %s 环境阻断上报已达上限 %d 次，转为静默（仅保留本地记录与状态展示）",
			cert.CertName, config.MaxBlockReportCount)
		return
	}
	cert.Metadata.BlockReportCount++
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("持久化证书 %s 阻断上报计数失败: %v", cert.CertName, err)
	}

	req := &fetcher.CallbackRequest{
		OrderID:    cert.OrderID,
		Status:     "failure",
		DeployedAt: time.Now().Format(time.RFC3339),
		Message:    callbackMessage(fmt.Errorf("%s", message)),
	}
	renewBeforeDays := s.sendCallback(ctx, api, req)
	s.tryUpdateRenewBeforeDays(renewBeforeDays)
}
