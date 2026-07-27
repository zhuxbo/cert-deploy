package certops

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/csr"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

func TestPrepareLocalRenew_PreflightRejectsIncompleteResponse(t *testing.T) {
	for _, response := range []string{
		`{"code":1,"msg":"ok","data":{"order_id":0,"status":"active"}}`,
		`{"code":1,"msg":"ok","data":{"order_id":3000,"status":""}}`,
	} {
		t.Run(response, func(t *testing.T) {
			tmpDir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(tmpDir)
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(cm, logger.NewNopLogger())
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, response)
			}))
			t.Cleanup(server.Close)
			cert := newLocalCert(t, tmpDir, "incomplete.example.com", 3000, server.URL)
			if err := cm.AddCert(cert); err != nil {
				t.Fatal(err)
			}

			if _, _, err := svc.prepareLocalRenew(t.Context(), cert, cert.API); err == nil {
				t.Fatal("incomplete preflight response should stop with error")
			}
			if posts.Load() != 0 || cert.Metadata.IssueRetryCount != 0 {
				t.Fatalf("incomplete preflight must not submit: posts=%d count=%d", posts.Load(), cert.Metadata.IssueRetryCount)
			}
		})
	}
}

func TestSafetyMarginAllowsInFlightQuery(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"code":1,"msg":"ok","data":{"order_id":3008,"status":"processing"}}`)
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "safety-inflight.example.com", 3008, server.URL)
	cert.Metadata.CertExpiresAt = time.Now().Add(12 * time.Hour)
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	cfg, err := cm.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !svc.willMakeAPICall(cert, &cfg.Schedule) {
		t.Fatal("in-flight issue inside safety margin should still be predicted as an API call")
	}
	processed := 0
	if _, madeAPICall := svc.processCertRenewal(t.Context(), cfg, *cert, &processed); !madeAPICall {
		t.Fatal("in-flight issue inside safety margin should continue query-first")
	}
	if gets.Load() != 1 {
		t.Fatalf("GET count = %d, want 1", gets.Load())
	}
}

func TestInFlightQueryContinuesOutsideRenewWindow(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"code":1,"msg":"ok","data":{"order_id":3010,"status":"processing"}}`)
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "window-inflight.example.com", 3010, server.URL)
	cert.Metadata.CertExpiresAt = time.Now().Add(60 * 24 * time.Hour)
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	cfg, err := cm.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cert.NeedsRenewal(&cfg.Schedule) {
		t.Fatal("test setup must be outside renewal window")
	}
	if !svc.willMakeAPICall(cert, &cfg.Schedule) {
		t.Fatal("in-flight issue outside renewal window should still be predicted as an API call")
	}
	processed := 0
	if _, madeAPICall := svc.processCertRenewal(t.Context(), cfg, *cert, &processed); !madeAPICall {
		t.Fatal("in-flight issue outside renewal window should continue query-first")
	}
	if gets.Load() != 1 {
		t.Fatalf("GET count = %d, want 1", gets.Load())
	}
}

func TestPrepareLocalRenew_PreflightRequiresActive(t *testing.T) {
	for _, status := range []string{
		config.OrderStatusProcessing,
		config.OrderStatusUnpaid,
		config.OrderStatusFailed,
		"future_server_state",
	} {
		t.Run(status, func(t *testing.T) {
			tmpDir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(tmpDir)
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(cm, logger.NewNopLogger())

			var gets atomic.Int32
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost {
					posts.Add(1)
					_, _ = fmt.Fprint(w, `{"code":1,"msg":"ok","data":{"order_id":3001,"status":"processing"}}`)
					return
				}
				gets.Add(1)
				_, _ = fmt.Fprintf(w, `{"code":1,"msg":"ok","data":{"order_id":3001,"status":%q}}`, status)
			}))
			t.Cleanup(server.Close)

			cert := newLocalCert(t, tmpDir, status+".example.com", 3001, server.URL)
			if err := cm.AddCert(cert); err != nil {
				t.Fatal(err)
			}

			_, _, _ = svc.prepareLocalRenew(t.Context(), cert, cert.API)
			if gets.Load() != 1 {
				t.Fatalf("GET count = %d, want 1", gets.Load())
			}
			if posts.Load() != 0 {
				t.Fatalf("POST count = %d, want 0", posts.Load())
			}
			if cert.Metadata.IssueRetryCount != 0 {
				t.Fatalf("issue_retry_count = %d, want 0", cert.Metadata.IssueRetryCount)
			}
			if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); err == nil {
				t.Fatal("non-active preflight must not create pending key")
			}
			if status == "future_server_state" && cert.Metadata.LastIssueState != config.IssueStateProcessing {
				t.Fatalf("unknown status should enter query-only processing, got %q", cert.Metadata.LastIssueState)
			}
		})
	}
}

func TestPrepareLocalRenew_SafetyMarginBlocksNewAttempt(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		_, _ = fmt.Fprint(w, `{"code":1,"msg":"ok","data":{"order_id":3009,"status":"active"}}`)
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "safety-new.example.com", 3009, server.URL)
	cert.Metadata.CertExpiresAt = time.Now().Add(12 * time.Hour)
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.prepareLocalRenew(t.Context(), cert, cert.API); err == nil {
		t.Fatal("new CSR attempt inside safety margin should stop")
	}
	if posts.Load() != 0 || cert.Metadata.IssueRetryCount != 0 {
		t.Fatalf("safety margin must block POST/count: posts=%d count=%d", posts.Load(), cert.Metadata.IssueRetryCount)
	}
	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); err == nil {
		t.Fatal("safety margin must not create pending key")
	}
}

func TestPrepareLocalRenew_PersistsIntentBeforePost(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	type observedIntent struct {
		count int
		hash  string
		at    time.Time
		state string
	}
	observed := make(chan observedIntent, 1)
	var mu sync.Mutex
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, `{"code":1,"msg":"ok","data":{"order_id":3002,"status":"active"}}`)
			return
		}
		stored, getErr := cm.GetCert("intent.example.com-3002")
		if getErr != nil {
			observed <- observedIntent{}
		} else {
			observed <- observedIntent{
				count: stored.Metadata.IssueRetryCount,
				hash:  stored.Metadata.LastCSRHash,
				at:    stored.Metadata.CSRSubmittedAt,
				state: stored.Metadata.LastIssueState,
			}
		}
		_, _ = fmt.Fprint(w, `not-json`)
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "intent.example.com", 3002, server.URL)
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.prepareLocalRenew(t.Context(), cert, cert.API); err != nil {
		t.Fatalf("response loss should enter query-first without returning error: %v", err)
	}
	got := <-observed
	if got.count != 1 || got.hash == "" || got.at.IsZero() || got.state != config.IssueStateProcessing {
		t.Fatalf("intent at POST = %+v, want count=1 hash/time set state=processing", got)
	}
	mu.Lock()
	gotMethods := append([]string(nil), methods...)
	mu.Unlock()
	if fmt.Sprint(gotMethods) != "[GET POST]" {
		t.Fatalf("request order = %v, want [GET POST]", gotMethods)
	}
}

func TestPrepareLocalRenew_MissingServerCSRPreservesPending(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	pair, err := certs.GenerateValidCert("missing-csr.example.com", []string{"missing-csr.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			w,
			`{"code":1,"msg":"ok","data":{"order_id":3003,"status":"active","csr":"","certificate":%q,"ca_certificate":%q}}`,
			pair.CertPEM,
			intermediate.CertPEM,
		)
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "missing-csr.example.com", 3003, server.URL)
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	cert.Metadata.IssueRetryCount = 1
	cert.Metadata.LastCSRHash = "unknown"
	cert.Metadata.CSRSubmittedAt = time.Now()
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	if err := savePendingKey(cm.GetWorkDir(), cert.CertName, pair.KeyPEM); err != nil {
		t.Fatal(err)
	}

	data, key, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err != nil {
		t.Fatalf("missing server CSR should stop this round without discarding pending: %v", err)
	}
	if data != nil || key != "" {
		t.Fatal("missing server CSR must not deploy")
	}
	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); err != nil {
		t.Fatalf("pending key should be preserved: %v", err)
	}
}

func TestPrepareLocalRenew_UnverifiablePendingPreservesIntent(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	_, serverCSR, serverHash, err := csr.GenerateKeyAndCSR(
		csr.KeyOptions{},
		csr.CSROptions{CommonName: "unverifiable.example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1,
			"msg":  "ok",
			"data": map[string]any{"order_id": 3006, "status": "processing", "csr": serverCSR},
		})
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "unverifiable.example.com", 3006, server.URL)
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	cert.Metadata.IssueRetryCount = 1
	cert.Metadata.LastCSRHash = serverHash
	cert.Metadata.CSRSubmittedAt = time.Now()
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	if err := savePendingKey(cm.GetWorkDir(), cert.CertName, "not-a-private-key"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.prepareLocalRenew(t.Context(), cert, cert.API); err != nil {
		t.Fatalf("unverifiable pending should stop without discarding intent: %v", err)
	}
	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); err != nil {
		t.Fatalf("unverifiable pending should be preserved: %v", err)
	}
	if cert.Metadata.LastCSRHash != serverHash || cert.Metadata.CSRSubmittedAt.IsZero() {
		t.Fatal("unverifiable pending must preserve CSR metadata")
	}
}

func TestPrepareLocalRenew_LegacyPEMHashNormalizesToDER(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	pendingKey, serverCSR, derHash, err := csr.GenerateKeyAndCSR(
		csr.KeyOptions{},
		csr.CSROptions{CommonName: "legacy-hash.example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(serverCSR)))
	serviceCSR := strings.ReplaceAll(serverCSR, "\n", "\r\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1,
			"msg":  "ok",
			"data": map[string]any{"order_id": 3007, "status": "processing", "csr": serviceCSR},
		})
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "legacy-hash.example.com", 3007, server.URL)
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	cert.Metadata.IssueRetryCount = 1
	cert.Metadata.LastCSRHash = legacyHash
	cert.Metadata.CSRSubmittedAt = time.Now()
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	if err := savePendingKey(cm.GetWorkDir(), cert.CertName, pendingKey); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.prepareLocalRenew(t.Context(), cert, cert.API); err != nil {
		t.Fatalf("legacy PEM hash should recover: %v", err)
	}
	if cert.Metadata.LastCSRHash != derHash {
		t.Fatalf("last_csr_hash = %q, want normalized DER hash %q", cert.Metadata.LastCSRHash, derHash)
	}
	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); err != nil {
		t.Fatalf("matching legacy pending should be preserved: %v", err)
	}
}

func TestPrepareLocalRenew_WaitingCSRMismatchFollowsServerAction(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	pendingKey, _, pendingHash, err := csr.GenerateKeyAndCSR(
		csr.KeyOptions{},
		csr.CSROptions{CommonName: "waiting-mismatch.example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, serverCSR, _, err := csr.GenerateKeyAndCSR(
		csr.KeyOptions{},
		csr.CSROptions{CommonName: "waiting-mismatch.example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1,
			"msg":  "ok",
			"data": map[string]any{"order_id": 3004, "status": "processing", "csr": serverCSR},
		})
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "waiting-mismatch.example.com", 3004, server.URL)
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	cert.Metadata.IssueRetryCount = 1
	cert.Metadata.LastCSRHash = pendingHash
	cert.Metadata.CSRSubmittedAt = time.Now()
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	if err := savePendingKey(cm.GetWorkDir(), cert.CertName, pendingKey); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.prepareLocalRenew(t.Context(), cert, cert.API); err != nil {
		t.Fatalf("waiting mismatch should follow server action: %v", err)
	}
	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); err == nil {
		t.Fatal("mismatched local pending key should be removed")
	}
	if cert.Metadata.LastCSRHash != "" || !cert.Metadata.CSRSubmittedAt.IsZero() {
		t.Fatalf("CSR metadata not cleared: hash=%q at=%v", cert.Metadata.LastCSRHash, cert.Metadata.CSRSubmittedAt)
	}
	if cert.Metadata.IssueRetryCount != 1 {
		t.Fatalf("issue_retry_count = %d, want preserved 1", cert.Metadata.IssueRetryCount)
	}
	if cert.Metadata.LastIssueState != config.IssueStateProcessing {
		t.Fatalf("last_issue_state = %q, want processing", cert.Metadata.LastIssueState)
	}
}

func TestPrepareLocalRenew_ActiveCSRMismatchUsesAPIKey(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	pendingKey, _, pendingHash, err := csr.GenerateKeyAndCSR(
		csr.KeyOptions{},
		csr.CSROptions{CommonName: "active-mismatch.example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	apiKey, serverCSR, _, err := csr.GenerateKeyAndCSR(
		csr.KeyOptions{},
		csr.CSROptions{CommonName: "active-mismatch.example.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	signer := newSigningAPI(t, 3005)
	serverCert := signer.signCSR(serverCSR)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1,
			"msg":  "ok",
			"data": map[string]any{
				"order_id":       3005,
				"status":         "active",
				"csr":            serverCSR,
				"certificate":    serverCert,
				"ca_certificate": signer.caPEM,
				"private_key":    apiKey,
			},
		})
	}))
	t.Cleanup(server.Close)

	cert := newLocalCert(t, tmpDir, "active-mismatch.example.com", 3005, server.URL)
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	cert.Metadata.IssueRetryCount = 1
	cert.Metadata.LastCSRHash = pendingHash
	cert.Metadata.CSRSubmittedAt = time.Now()
	if err := cm.AddCert(cert); err != nil {
		t.Fatal(err)
	}
	if err := savePendingKey(cm.GetWorkDir(), cert.CertName, pendingKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pickKeyPath(cert), []byte(pendingKey), 0600); err != nil {
		t.Fatal(err)
	}

	data, key, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err != nil {
		t.Fatalf("active mismatch should deploy with matching API key: %v", err)
	}
	if data == nil || key != apiKey {
		t.Fatal("active mismatch did not select matching API key")
	}
	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); err == nil {
		t.Fatal("old pending key should be removed")
	}
	if cert.Metadata.LastCSRHash != "" || !cert.Metadata.CSRSubmittedAt.IsZero() {
		t.Fatal("old CSR metadata should be cleared")
	}
	if cert.Metadata.LastIssueState != config.IssueStateActive {
		t.Fatalf("last_issue_state = %q, want active", cert.Metadata.LastIssueState)
	}
}
