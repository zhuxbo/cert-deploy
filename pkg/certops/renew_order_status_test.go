// Package certops 订单状态归一（approving）、业务拒绝与订单终态自愈测试
package certops

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// countingStatusServer GET 返回指定状态并统计 POST 次数（POST 返回 processing）
type countingStatusServer struct {
	server *httptest.Server
	posts  atomic.Int64
	status atomic.Value // string：当前 GET 返回的订单状态
}

func newCountingStatusServer(t *testing.T, orderID int, status string) *countingStatusServer {
	t.Helper()
	cs := &countingStatusServer{}
	cs.status.Store(status)
	cs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			cs.posts.Add(1)
			fmt.Fprintf(w, `{"code":1,"msg":"ok","data":{"order_id":%d,"status":"processing"}}`, orderID)
			return
		}
		fmt.Fprintf(w, `{"code":1,"msg":"ok","data":{"order_id":%d,"status":%q}}`, orderID, cs.status.Load())
	}))
	t.Cleanup(cs.server.Close)
	return cs
}

func newLocalCert(t *testing.T, tmpDir, name string, orderID int, url string) *config.CertConfig {
	t.Helper()
	keyPath := filepath.Join(tmpDir, name, "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	return &config.CertConfig{
		CertName:  fmt.Sprintf("%s-%d", name, orderID),
		OrderID:   orderID,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{name},
		API:       config.APIConfig{URL: url, Token: "test-token"},
		Metadata:  config.CertMetadata{CertExpiresAt: time.Now().Add(5 * 24 * time.Hour)},
		Bindings: []config.SiteBinding{{
			ServerName: name,
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: filepath.Join(tmpDir, name, "cert.pem"), PrivateKey: keyPath},
		}},
	}
}

// TestPrepareLocalRenew_ApprovingNormalized 验证 approving 中间态归一（spec 2.4/3.5）：
// 在途 processing 查询返回 approving → 视同 processing 继续等待，不重复 POST、不增计数；
// 本地已存 approving 状态（历史残留）同样归一进入查询路径。
func TestPrepareLocalRenew_ApprovingNormalized(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	cs := newCountingStatusServer(t, 980, "approving")
	cert := newLocalCert(t, tmpDir, "approving.example.com", 980, cs.server.URL)
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	cert.Metadata.IssueRetryCount = 1
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	cd, _, perr := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if perr != nil {
		t.Fatalf("approving 应视同 processing 继续等待，不应报错: %v", perr)
	}
	if cd != nil {
		t.Fatal("approving 应返回 nil 证书数据（继续等待）")
	}
	if n := cs.posts.Load(); n != 0 {
		t.Errorf("approving 等待期间不应重复 POST，实际 %d 次", n)
	}
	if cert.Metadata.IssueRetryCount != 1 {
		t.Errorf("approving 等待不应递增签发计数（应仍为 1），实际 %d", cert.Metadata.IssueRetryCount)
	}

	// 本地状态为 approving（历史残留）：归一进入查询路径，不重新提交 CSR
	cert.Metadata.LastIssueState = "approving"
	cd2, _, perr2 := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if perr2 != nil || cd2 != nil {
		t.Fatalf("本地 approving 状态应归一查询等待: cd=%v err=%v", cd2, perr2)
	}
	if n := cs.posts.Load(); n != 0 {
		t.Errorf("本地 approving 状态不应触发 POST，实际 %d 次", n)
	}
}

// TestPrepareLocalRenew_BusinessRejectCleansPending 验证明确业务拒绝（spec 2.6）：
// 提交 CSR 时服务端成功响应但 code != 1（校验失败、订单状态不允许等）属确定结果——
// 清理在途 pending key 后停止，不归一 processing；签发计数保留递增值（受上限约束）。
func TestPrepareLocalRenew_BusinessRejectCleansPending(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"code":0,"msg":"订单状态不允许重签"}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok","data":{"order_id":990,"status":"processing"}}`))
	}))
	defer server.Close()

	cert := newLocalCert(t, tmpDir, "reject.example.com", 990, server.URL)
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	cd, _, perr := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if perr == nil {
		t.Fatal("业务拒绝应返回错误（本轮停止）")
	}
	if cd != nil {
		t.Fatal("业务拒绝不应返回证书数据")
	}
	// 确定结果：清理在途 pending key（区别于不确定结果的保留）
	if _, e := readPendingKey(cm.GetWorkDir(), "reject.example.com-990"); e == nil {
		t.Error("业务拒绝后 pending key 应被清理")
	}
	// 不归一 processing：下轮可重新提交（受签发计数上限约束）
	if cert.Metadata.LastIssueState == config.IssueStateProcessing {
		t.Errorf("业务拒绝不应归一为 processing，实际 %q", cert.Metadata.LastIssueState)
	}
	// 提交意图已递增签发计数
	if cert.Metadata.IssueRetryCount != 1 {
		t.Errorf("提交意图应递增签发计数一次，实际 %d", cert.Metadata.IssueRetryCount)
	}
}

// TestPrepareLocalRenew_TerminalStateQueryHeals 验证订单终态自愈（spec 3.5）：
// 本地已记录订单终态（如 cancelled）时后续轮次只 GET 查询、绝不重新提交 CSR；
// 状态未变化时静默等待（不重复记录/落盘），状态恢复 active 后正常推进部署。
func TestPrepareLocalRenew_TerminalStateQueryHeals(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	pair, err := certs.GenerateValidCert("term.example.com", []string{"term.example.com"})
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	cs := &countingStatusServer{}
	cs.status.Store("cancelled")
	cs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			cs.posts.Add(1)
			fmt.Fprintf(w, `{"code":1,"msg":"ok","data":{"order_id":995,"status":"processing"}}`)
			return
		}
		status := cs.status.Load().(string)
		if status == "active" {
			fmt.Fprintf(w, `{"code":1,"msg":"ok","data":{"order_id":995,"status":"active","certificate":%q,"ca_certificate":%q}}`,
				pair.CertPEM, intermediate.CertPEM)
			return
		}
		fmt.Fprintf(w, `{"code":1,"msg":"ok","data":{"order_id":995,"status":%q}}`, status)
	}))
	t.Cleanup(cs.server.Close)

	cert := newLocalCert(t, tmpDir, "term.example.com", 995, cs.server.URL)
	cert.Metadata.LastIssueState = "cancelled" // 上轮已持久化的订单终态
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}
	// pending key 与服务端 active 证书配对（自愈部署路径需要）
	if err := savePendingKey(cm.GetWorkDir(), "term.example.com-995", pair.KeyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	// 状态未变化：静默等待，不报错、不重新提交
	cd, _, perr := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if perr != nil {
		t.Fatalf("终态未变化应静默等待，不应报错: %v", perr)
	}
	if cd != nil {
		t.Fatal("终态未变化不应返回证书数据")
	}
	if n := cs.posts.Load(); n != 0 {
		t.Errorf("终态证书绝不应重新提交 CSR，实际 POST %d 次", n)
	}
	if cert.Metadata.LastIssueState != "cancelled" {
		t.Errorf("终态未变化不应改写状态，实际 %q", cert.Metadata.LastIssueState)
	}

	// 服务端状态恢复 active：查询自愈，返回待部署证书数据
	cs.status.Store("active")
	cd2, pk2, perr2 := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if perr2 != nil {
		t.Fatalf("终态自愈为 active 应正常推进: %v", perr2)
	}
	if cd2 == nil || pk2 == "" {
		t.Fatal("自愈后应返回待部署证书数据与私钥")
	}
	if n := cs.posts.Load(); n != 0 {
		t.Errorf("自愈全程不应 POST，实际 %d 次", n)
	}
}
