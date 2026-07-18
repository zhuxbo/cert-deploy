package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssueCertificateForCSRUsesCSRPublicKey(t *testing.T) {
	generateCACertPair("test.example.com")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "local.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	data, err := issueCertificateForCSR(string(csrPEM), 2001, "local.example.com")
	if err != nil {
		t.Fatalf("issueCertificateForCSR() error = %v", err)
	}
	if data.Status != "active" {
		t.Fatalf("status = %q, want active", data.Status)
	}
	if data.PrivateKey != "" {
		t.Fatal("local CSR response must not return a private key")
	}

	block, _ := pem.Decode([]byte(data.Cert))
	if block == nil {
		t.Fatal("issued certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuedKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("issued public key type = %T, want *rsa.PublicKey", cert.PublicKey)
	}
	if issuedKey.N.Cmp(key.N) != 0 || issuedKey.E != key.E {
		t.Fatal("issued certificate public key does not match CSR public key")
	}
}

func TestCallbackRequestPreservesFailureMessage(t *testing.T) {
	raw := []byte(`{"order_id":1001,"status":"failure","deployed_at":"2026-07-18T00:00:00Z","message":"reload failed"}`)
	var req CallbackRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if req.Message != "reload failed" {
		t.Fatalf("message = %q, want reload failed", req.Message)
	}
}

func TestHandleCallbackRejectsMessageOver500Characters(t *testing.T) {
	callbacksMutex.Lock()
	callbacks = nil
	callbacksMutex.Unlock()

	body := `{"order_id":1001,"status":"failure","deployed_at":"2026-07-18T00:00:00Z","message":"` + strings.Repeat("x", 501) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/deploy/callback", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	recorder := httptest.NewRecorder()

	handleCallback(recorder, req)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnprocessableEntity)
	}
	callbacksMutex.Lock()
	defer callbacksMutex.Unlock()
	if len(callbacks) != 0 {
		t.Fatalf("callbacks recorded = %d, want 0", len(callbacks))
	}
}
