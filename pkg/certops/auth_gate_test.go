// Package certops 轮内 token 黑名单（deploy-spec §2.2「整批共通」组）测试
package certops

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// businessErrWithCode 构造带指定 error_code 的业务错误；空串表示未分类失败
func businessErrWithCode(code string) error {
	if code == "" {
		return sslerrors.NewBusinessError("boom", nil)
	}
	return sslerrors.NewBusinessErrorWithCode("boom", code, 0)
}

// authBlockServer 恒返回指定 error_code 的服务端，并统计收到的请求数
func authBlockServer(t *testing.T, errorsField string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"code":0,"msg":"boom","errors":%s}`, errorsField)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

// pullCertNeedingRenewal 构造一张临期、有启用绑定的 pull 模式证书
func pullCertNeedingRenewal(t *testing.T, tmpDir, name string, orderID int, url, token string) *config.CertConfig {
	t.Helper()
	return &config.CertConfig{
		CertName:  fmt.Sprintf("%s-%d", name, orderID),
		OrderID:   orderID,
		Enabled:   true,
		RenewMode: config.RenewModePull,
		Domains:   []string{name},
		API:       config.APIConfig{URL: url, Token: token},
		Metadata:  config.CertMetadata{CertExpiresAt: time.Now().Add(3 * 24 * time.Hour)},
		Bindings: []config.SiteBinding{{
			ServerName: name,
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths: config.BindingPaths{
				Certificate: filepath.Join(tmpDir, name, "cert.pem"),
				PrivateKey:  filepath.Join(tmpDir, name, "key.pem"),
			},
		}},
	}
}

// TestAuthBlockSkipsRemainingCertsInRound 整批共通失败必须让本轮其余同 token 证书直接跳过。
//
// 这类失败由认证与限流中间件下发、与订单无关，同一 token 的后续调用必然同样失败：
// 逐张重试零收益，且限流场景下 spec §2.2 明确要求「等待期间不再发请求」——继续打会重新
// 累积计数、让 retry_after 不再成立，把恢复时间往后推。
func TestAuthBlockSkipsRemainingCertsInRound(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	server, calls := authBlockServer(t, `{"error_code":"rate_limited","retry_after":100}`)

	certs := make([]*config.CertConfig, 3)
	for i := range certs {
		certs[i] = pullCertNeedingRenewal(t, tmpDir, fmt.Sprintf("blocked-%d.example.com", i), 900+i, server.URL, "same-token")
		if err := cm.AddCert(certs[i]); err != nil {
			t.Fatalf("添加证书失败: %v", err)
		}
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 逐张走编排入口，模拟 CheckAndRenewAll 的循环（绕开证书间分散延迟）
	processed := 0
	for i, cert := range certs {
		_, madeAPICall := svc.processCertRenewal(t.Context(), cfg, *cert, &processed)
		if i > 0 && madeAPICall {
			t.Errorf("第 %d 张证书应被黑名单拦截、不发请求", i+1)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("请求次数 = %d, 期望 1（首张探明结果后其余应直接跳过）", got)
	}

	tokens, codes, skipped := svc.authGate.summary()
	if tokens != 1 {
		t.Errorf("被拒 token 数 = %d, 期望 1", tokens)
	}
	if skipped != 2 {
		t.Errorf("跳过证书数 = %d, 期望 2", skipped)
	}
	// error_code 必须能进汇总文案：被跳过的证书只记 debug，汇总是唯一的原因出口
	if len(codes) != 1 || codes[0] != fetcher.ErrorCodeRateLimited {
		t.Errorf("汇总 error_code = %v, 期望 [%s]", codes, fetcher.ErrorCodeRateLimited)
	}
}

// TestAuthBlockIsPerToken 黑名单按 (url, token) 而非全局：一台机器可能混用多个 token，
// 别人的 token 必须照常跑完本轮。
func TestAuthBlockIsPerToken(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	blockedSrv, blockedCalls := authBlockServer(t, `{"error_code":"token_disabled"}`)
	// 另一个 token 落在同一地址上：区分必须看 token，不能只看 URL
	otherToken := pullCertNeedingRenewal(t, tmpDir, "other-token.example.com", 911, blockedSrv.URL, "other-token")
	first := pullCertNeedingRenewal(t, tmpDir, "blocked-token.example.com", 910, blockedSrv.URL, "blocked-token")
	second := pullCertNeedingRenewal(t, tmpDir, "blocked-token-2.example.com", 912, blockedSrv.URL, "blocked-token")

	for _, cert := range []*config.CertConfig{first, otherToken, second} {
		if err := cm.AddCert(cert); err != nil {
			t.Fatalf("添加证书失败: %v", err)
		}
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	processed := 0

	// 第一张：探明该 token 被拒，入黑名单
	svc.processCertRenewal(t.Context(), cfg, *first, &processed)
	if _, blocked := svc.authGate.blockedBy(first.API); !blocked {
		t.Fatal("被服务端拒绝的 token 应进入黑名单")
	}
	if _, blocked := svc.authGate.blockedBy(otherToken.API); blocked {
		t.Error("同一地址上的另一个 token 不应被连带拉黑（键含 token，不只看 URL）")
	}

	// 另一 token：不受上一条阻断影响，照常发出自己的请求
	callsBefore := blockedCalls.Load()
	svc.processCertRenewal(t.Context(), cfg, *otherToken, &processed)
	if blockedCalls.Load() != callsBefore+1 {
		t.Errorf("另一 token 的证书应照常请求，请求数 %d → %d", callsBefore, blockedCalls.Load())
	}

	// 同 token 的第二张：被拦截，零请求
	callsBefore = blockedCalls.Load()
	svc.processCertRenewal(t.Context(), cfg, *second, &processed)
	if blockedCalls.Load() != callsBefore {
		t.Errorf("同 token 的后续证书应被拦截，请求数 %d → %d", callsBefore, blockedCalls.Load())
	}
}

// TestAuthGateResetsEachRound 黑名单每轮清空。
// 不重置等于把 spec §2.2 的「本轮停止」升级成永久停止——token 换发后再也不会被重试。
func TestAuthGateResetsEachRound(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	server, calls := authBlockServer(t, `{"error_code":"ip_not_allowed"}`)
	// 单张证书：每轮只处理一个，不触发证书间分散延迟
	cert := pullCertNeedingRenewal(t, tmpDir, "reset.example.com", 920, server.URL, "t")
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	for round := 1; round <= 2; round++ {
		if _, err := svc.CheckAndRenewAll(t.Context()); err != nil {
			t.Fatalf("第 %d 轮 CheckAndRenewAll 失败: %v", round, err)
		}
		if got := calls.Load(); got != int32(round) {
			t.Fatalf("第 %d 轮后请求次数 = %d, 期望 %d（每轮都应重新尝试）", round, got, round)
		}
	}
}

// TestAuthBlockOnCSRSubmitRollsBackIssueCount 提交 CSR 撞上整批共通失败时必须回滚签发计数。
//
// 请求被认证/限流中间件拦下，服务端根本没收到这次提交，不该占用签发额度。不回滚的话
// token 持续失效满 MaxIssueRetryCount 轮就把额度烧光，人工换发 token 后证书已是 CAPPED、
// 还要再人工解除一次——与环境闸门「阻断不占配额、修好即自动恢复」同一纪律。
func TestAuthBlockOnCSRSubmitRollsBackIssueCount(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			posts.Add(1)
			_, _ = fmt.Fprint(w, `{"code":0,"msg":"Deploy token rate limit exceeded","errors":{"error_code":"rate_limited","retry_after":90}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"code":1,"msg":"ok","data":{"order_id":930,"status":"active","cert":"","private_key":""}}`)
	}))
	defer server.Close()

	cert := newLocalCert(t, tmpDir, "csr-blocked.example.com", 930, server.URL)
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	_, _, perr := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if perr == nil {
		t.Fatal("整批共通失败应作为错误返回")
	}
	if posts.Load() != 1 {
		t.Fatalf("应恰好提交一次，实际 %d 次", posts.Load())
	}

	stored, err := cm.GetCert(cert.CertName)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	if stored.Metadata.IssueRetryCount != 0 {
		t.Errorf("issue_retry_count = %d, 期望 0（中间件拦截不占签发额度）", stored.Metadata.IssueRetryCount)
	}
	if stored.Metadata.LastCSRHash != "" || !stored.Metadata.CSRSubmittedAt.IsZero() || stored.Metadata.LastIssueState != "" {
		t.Errorf("认证阻断应完整回滚 CSR 提交意图: hash=%q at=%v state=%q",
			stored.Metadata.LastCSRHash, stored.Metadata.CSRSubmittedAt, stored.Metadata.LastIssueState)
	}
	// 服务端没收到 CSR，这把私钥永远配不上证书，必须清理
	if _, e := readPendingKey(cm.GetWorkDir(), cert.CertName); e == nil {
		t.Error("提交未被服务端接收时应清理待确认私钥")
	}
	if _, blocked := svc.authGate.blockedBy(cert.API); !blocked {
		t.Error("提交路径的整批共通失败也应记入黑名单")
	}
}

// TestAuthGateRecordIgnoresPerCertAndUnclassified 只有整批共通组进黑名单。
// 单条目失败与未分类失败若也拉黑 token，一张配错 order_id 的证书就能停掉整轮。
func TestAuthGateRecordIgnoresPerCertAndUnclassified(t *testing.T) {
	api := config.APIConfig{URL: "https://api.example.com", Token: "t"}
	var gate authGate

	for _, code := range []string{
		fetcher.ErrorCodeOrderNotFound,
		fetcher.ErrorCodeInvalidOrder,
		fetcher.ErrorCodeOrderInProgress,
		fetcher.ErrorCodeInsufficientBalance,
	} {
		if gate.record(api, businessErrWithCode(code)) {
			t.Errorf("record(%q) = true, 期望 false（单条目组不拉黑 token）", code)
		}
	}
	if gate.record(api, businessErrWithCode("")) {
		t.Error("未分类失败不应拉黑 token")
	}
	if gate.record(api, nil) {
		t.Error("nil 错误不应拉黑 token")
	}
	if _, blocked := gate.blockedBy(api); blocked {
		t.Error("以上任一情形都不该产生黑名单条目")
	}

	// 首次原因优先保留：后续调用拿到的可能是同一问题的另一种表述
	if !gate.record(api, businessErrWithCode(fetcher.ErrorCodeTokenInvalid)) {
		t.Fatal("整批共通失败应被记入")
	}
	_ = gate.record(api, businessErrWithCode(fetcher.ErrorCodeRateLimited))
	blk, _ := gate.blockedBy(api)
	if blk.code != fetcher.ErrorCodeTokenInvalid {
		t.Errorf("黑名单原因 = %q, 期望保留首次的 %q", blk.code, fetcher.ErrorCodeTokenInvalid)
	}
}
