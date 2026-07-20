// Package daemon 守护进程模式
package daemon

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// Run 运行守护进程
// parentCtx 用于外部通知停止（Windows 服务通过 context 取消，命令行通过信号）
func Run(parentCtx context.Context, args []string, version, buildTime string, debug bool) {
	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(logDir, "debug")
	}

	log, err := logger.New(logDir, "daemon")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	log.Info("sslctl daemon 启动 (version: %s)", version)

	// 加载配置
	cfg, err := cfgManager.Load()
	if err != nil {
		log.Error("加载配置失败: %v", err)
		os.Exit(1)
	}

	log.Info("检查频率: 每天一次（随机时间）")

	// 关闭超时
	shutdownTimeout := time.Duration(cfg.Schedule.ShutdownTimeoutSeconds) * time.Second
	if shutdownTimeout == 0 {
		shutdownTimeout = time.Duration(config.DefaultShutdownTimeoutSeconds) * time.Second
	}

	// 创建证书服务
	svc := certops.NewService(cfgManager, log)

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// 用于等待正在运行的任务完成
	var wg sync.WaitGroup
	taskRunning := make(chan struct{}, 1) // 防止任务重叠

	// 启动时立即检查一次（占用 taskRunning 防止与 ticker 重叠）
	taskRunning <- struct{}{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-taskRunning }()
		checkAndDeploy(ctx, svc, cfgManager, log)
	}()

	firstRound := true
	for {
		// 首轮跳过补偿判定：启动时已无条件立即检查一次（异步进行中，LastCheckAt 尚未更新），
		// 若首轮也按 overdue 排短延迟会与启动轮双跑
		delay := nextCheckDelay(cfgManager, log, firstRound)
		firstRound = false
		log.Info("下次检查: %v 后", delay.Round(time.Minute))
		timer := time.NewTimer(delay)

		select {
		case <-timer.C:
			// 检查是否有任务正在运行，防止重叠
			select {
			case taskRunning <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-taskRunning }()
					checkAndDeploy(ctx, svc, cfgManager, log)
				}()
			default:
				log.Debug("上一次检查任务仍在运行，跳过本次检查")
			}
		case sig := <-sigCh:
			timer.Stop()
			log.Info("收到信号 %v，正在退出...", sig)
			cancel()
			gracefulShutdown(&wg, shutdownTimeout, log)
			return
		case <-parentCtx.Done():
			timer.Stop()
			log.Info("收到停止通知，正在退出...")
			cancel()
			gracefulShutdown(&wg, shutdownTimeout, log)
			return
		}
	}
}

// gracefulShutdown 等待正在运行的任务完成
func gracefulShutdown(wg *sync.WaitGroup, timeout time.Duration, log *logger.Logger) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Info("所有任务已完成，退出")
	case <-time.After(timeout):
		log.Warn("等待任务完成超时（%v），强制退出", timeout)
	}
}

// overdueCheckThreshold 补偿检查阈值：上次成功检查距今超过该时长视为已错过
// （正常节奏为每天一次，留 1 小时余量）
const overdueCheckThreshold = 25 * time.Hour

// isCheckOverdue 判断续签检查是否已错过（从未检查或距上次检查超过阈值）
// 配置读取失败时按未错过处理（checkAndDeploy 执行时会再报错）
func isCheckOverdue(cfgManager *config.ConfigManager) (bool, time.Time) {
	cfg, err := cfgManager.Load()
	if err != nil {
		return false, time.Time{}
	}
	last := cfg.Metadata.LastCheckAt
	if last.IsZero() || time.Since(last) > overdueCheckThreshold {
		return true, last
	}
	return false, last
}

// nextCheckDelay 计算下次检查延迟：
// 常规为明天随机时刻；已错过（daemon 停摆、系统睡眠、上一任务超时跳过等）时
// 30~60 分钟内补偿一轮，而非等到明天，消除调度错过后的自愈盲区。
// 补偿延迟不取过短值：若检查因配置损坏等持续失败（LastCheckAt 不更新），重试频率可控。
// skipOverdue 为 true 时跳过补偿判定（首轮：启动检查已覆盖）。
func nextCheckDelay(cfgManager *config.ConfigManager, log *logger.Logger, skipOverdue bool) time.Duration {
	if skipOverdue {
		return nextRandomDaily()
	}
	overdue, last := isCheckOverdue(cfgManager)
	if !overdue {
		return nextRandomDaily()
	}
	delay := time.Duration(30+rand.IntN(31)) * time.Minute
	if last.IsZero() {
		log.Info("尚无续签检查完成记录，%v 后执行补偿检查", delay.Round(time.Minute))
	} else {
		log.Warn("上次续签检查在 %s（已超过 %v），%v 后执行补偿检查",
			last.Format("2006-01-02 15:04"), overdueCheckThreshold, delay.Round(time.Minute))
	}
	return delay
}

// nextRandomDaily 计算到明天随机时刻的延迟
// 在明天 09:00~23:59 之间随机选择一个时间点，最短不低于 1 小时
// 避开 0:00~8:59：服务端 0:00~7:59 执行续签，预留 1 小时签发时间
func nextRandomDaily() time.Duration {
	now := time.Now()
	hour := 9 + rand.IntN(15) // 9~23
	tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1,
		hour, rand.IntN(60), 0, 0, now.Location())
	delay := tomorrow.Sub(now)
	if delay < time.Hour {
		delay += 24 * time.Hour
	}
	return delay
}

// calcCheckTimeout 根据证书数量动态计算检查超时
// 最小 30 分钟，每个证书 2 分钟，上限 4 小时
func calcCheckTimeout(certCount int) time.Duration {
	count := certCount
	if count > 100 {
		count = 100
	}
	timeout := time.Duration(count) * 2 * time.Minute
	if timeout < 30*time.Minute {
		timeout = 30 * time.Minute
	}
	if timeout > 4*time.Hour {
		timeout = 4 * time.Hour
	}
	return timeout
}

// checkAndDeploy 检查并部署证书
// 使用文件锁防止多进程同时执行续签
func checkAndDeploy(parentCtx context.Context, svc *certops.Service, cfgManager *config.ConfigManager, log *logger.Logger) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("检查任务 panic: %v", r)
		}
	}()

	// 进程级文件锁：防止 cron 重叠、手动 deploy/setup 与 daemon 并发（共享同一把锁）
	release, acquired, lockErr := config.AcquireRenewalLock(cfgManager.GetWorkDir())
	if lockErr != nil {
		log.Warn("%v，继续执行", lockErr)
	} else if !acquired {
		log.Info("另一个续签/部署进程正在运行，跳过本次检查")
		return
	} else {
		defer release()
	}

	// 动态计算超时：根据证书数量调整，防止大量证书场景超时
	certCount := 0
	if cfg, err := cfgManager.Load(); err == nil {
		certCount = len(cfg.Certificates)
	}
	timeout := calcCheckTimeout(certCount)
	log.Debug("检查超时: %v（证书数: %d）", timeout.Round(time.Minute), certCount)
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	log.Info("开始检查证书...")

	results, err := svc.CheckAndRenewAll(ctx)
	if err != nil {
		log.Error("检查证书失败: %v", err)
		return
	}

	// 输出结果统计
	var successCount, failedCount, pendingCount int
	for _, r := range results {
		switch r.Status {
		case "success":
			successCount++
			log.Info("证书 %s 续签成功，部署到 %d 个站点", r.CertName, r.DeployCount)
		case "failure":
			failedCount++
			log.Warn("证书 %s 续签失败: %v", r.CertName, r.Error)
		case "pending":
			pendingCount++
			log.Debug("证书 %s 等待签发中", r.CertName)
		}
	}

	if len(results) > 0 {
		log.Info("检查完成: 成功 %d, 失败 %d, 等待中 %d", successCount, failedCount, pendingCount)
	} else {
		log.Info("检查完成: 无需续签的证书")
	}

	// 检查证书过期告警
	svc.CheckExpiry()
}
