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

	key, csrPEM := generateTestCSR(t, "local.example.com")

	data, err := issueCertificateForCSR(csrPEM, 2001, "local.example.com")
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

func TestHandleRenewRequestRejectsSecondCSRWhileProcessing(t *testing.T) {
	generateCACertPair("test.example.com")
	initTestOrders()
	t.Cleanup(initTestOrders)

	_, firstCSR := generateTestCSR(t, "test.example.com")
	firstResponse := postRenewRequest(t, RenewRequest{
		OrderID:          1001,
		CSR:              firstCSR,
		Domains:          "test.example.com",
		ValidationMethod: "file",
	})
	if firstResponse.Code != 1 {
		t.Fatalf("first response code = %d, want 1: %+v", firstResponse.Code, firstResponse)
	}

	ordersMutex.RLock()
	firstStoredCSR := orders[1001].CertData.CSR
	firstStoredCert := orders[1001].CertData.Cert
	firstStatus := orders[1001].Status
	ordersMutex.RUnlock()
	if firstStatus != "processing" {
		t.Fatalf("status after first POST = %q, want processing", firstStatus)
	}
	if firstStoredCSR != firstCSR || firstStoredCert == "" {
		t.Fatal("first POST did not persist the accepted CSR and issued certificate")
	}

	_, secondCSR := generateTestCSR(t, "test.example.com")
	secondResponse := postRenewRequest(t, RenewRequest{
		OrderID:          1001,
		CSR:              secondCSR,
		Domains:          "test.example.com",
		ValidationMethod: "file",
	})
	if secondResponse.Code != 0 {
		t.Fatalf("second response code = %d, want 0: %+v", secondResponse.Code, secondResponse)
	}
	if secondResponse.Errors == nil || secondResponse.Errors.ErrorCode != "order_in_progress" {
		t.Fatalf("second response errors = %+v, want order_in_progress", secondResponse.Errors)
	}

	ordersMutex.RLock()
	defer ordersMutex.RUnlock()
	if orders[1001].Status != "processing" {
		t.Fatalf("status after rejected POST = %q, want processing", orders[1001].Status)
	}
	if orders[1001].CertData.CSR != firstStoredCSR {
		t.Fatal("rejected POST replaced the current action CSR")
	}
	if orders[1001].CertData.Cert != firstStoredCert {
		t.Fatal("rejected POST replaced the current issued certificate")
	}
}

func TestHandleGetOrdersPromotesIssuedActionBeforeNextCSR(t *testing.T) {
	generateCACertPair("test.example.com")
	initTestOrders()
	t.Cleanup(initTestOrders)

	_, firstCSR := generateTestCSR(t, "test.example.com")
	if response := postRenewRequest(t, RenewRequest{
		OrderID:          1001,
		CSR:              firstCSR,
		Domains:          "test.example.com",
		ValidationMethod: "file",
	}); response.Code != 1 {
		t.Fatalf("first response code = %d, want 1: %+v", response.Code, response)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/deploy?order=1001", nil)
	recorder := httptest.NewRecorder()
	handleGetOrders(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	ordersMutex.RLock()
	status := orders[1001].Status
	ordersMutex.RUnlock()
	if status != "active" {
		t.Fatalf("status after issued action GET = %q, want active", status)
	}

	_, successorCSR := generateTestCSR(t, "test.example.com")
	if response := postRenewRequest(t, RenewRequest{
		OrderID:          1001,
		CSR:              successorCSR,
		Domains:          "test.example.com",
		ValidationMethod: "file",
	}); response.Code != 1 {
		t.Fatalf("successor response code = %d, want 1: %+v", response.Code, response)
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

func generateTestCSR(t *testing.T, commonName string) (*rsa.PrivateKey, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return key, string(csrPEM)
}

func postRenewRequest(t *testing.T, body RenewRequest) APIResponse {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/deploy", strings.NewReader(string(raw)))
	recorder := httptest.NewRecorder()
	handleRenewRequest(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response APIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, recorder.Body.String())
	}
	return response
}
