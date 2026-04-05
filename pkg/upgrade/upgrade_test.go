package upgrade

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecute_AlreadyLatest(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "1.0.0",
			Versions: []VersionInfo{
				{Version: "1.0.0", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:abc"}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NeedUpgrade {
		t.Error("expected NeedUpgrade=false for same version")
	}
}

func TestExecute_CheckOnly(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{Version: "2.0.0", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:abc"}},
			},
		},
		"dev": &ChannelInfo{
			Latest: "2.1.0-beta",
			Versions: []VersionInfo{
				{Version: "2.1.0-beta", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:def"}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true")
	}
	if result.ToVersion != "v2.0.0" {
		t.Errorf("ToVersion = %q, want v2.0.0", result.ToVersion)
	}
}

func TestExecute_Force(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "1.0.0",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
		CheckOnly:      true,
		Force:          true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true with Force=true")
	}
}

func TestExecute_NoDowngrade(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "0.1.0",
			Versions: []VersionInfo{
				{Version: "0.1.0"},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v0.1.1-beta",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NeedUpgrade {
		t.Error("expected NeedUpgrade=false: should not downgrade from v0.1.1-beta to v0.1.0")
	}
}

func TestExecute_PreReleaseUpgrade(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "0.1.1",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v0.1.1-beta",
		Channel:        "main",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true: v0.1.1-beta should upgrade to v0.1.1")
	}
}

func TestExecute_FetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Error("expected error for server error")
	}
}

// signAndChecksum 为 gzData 生成签名和校验和
func signAndChecksum(t *testing.T, priv ed25519.PrivateKey, keyID string, gzData []byte) (string, string) {
	t.Helper()
	sig := ed25519.Sign(priv, gzData)
	sigStr := fmt.Sprintf("ed25519:%s:%s", keyID, base64.StdEncoding.EncodeToString(sig))
	hash := sha256.Sum256(gzData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])
	return sigStr, checksum
}

func TestExecute_SignatureKeyNotFound_ReinstallHint(t *testing.T) {
	saveAndRestoreKeys(t)
	pub1, _ := generateTestKeyPair(t)
	_, priv2 := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub1})

	gzData := makeGzipData(t, []byte("new binary"))
	// 用 key-2 签名（不在密钥环中）
	sig := ed25519.Sign(priv2, gzData)
	sigStr := "ed25519:key-2:" + base64.StdEncoding.EncodeToString(sig)
	hash := sha256.Sum256(gzData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{Version: "2.0.0", Checksums: map[string]string{filename: checksum}, Signatures: map[string]string{filename: sigStr}},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(index)
			return
		}
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "签名密钥已更新") {
		t.Errorf("error should mention key rotation, got: %v", err)
	}
	if !strings.Contains(err.Error(), "install.sh") {
		t.Errorf("error should suggest reinstall, got: %v", err)
	}
}

func TestDownloadVerifyInstall_ErrNoPublicKeys_ReinstallHint(t *testing.T) {
	saveAndRestoreKeys(t)
	releasePublicKeys = map[string]ed25519.PublicKey{}

	_, priv := generateTestKeyPair(t)
	gzData := makeGzipData(t, []byte("new binary"))
	sigStr, checksum := signAndChecksum(t, priv, "key-1", gzData)

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{Version: "2.0.0", Checksums: map[string]string{filename: checksum}, Signatures: map[string]string{filename: sigStr}},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(index)
			return
		}
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for no public keys")
	}
	if !strings.Contains(err.Error(), "签名密钥已更新") {
		t.Errorf("error should mention key update, got: %v", err)
	}
	if !strings.Contains(err.Error(), "install.sh") {
		t.Errorf("error should suggest reinstall, got: %v", err)
	}
}

func TestExecuteWithClient_ResolveTargetError(t *testing.T) {
	// 空 index 会导致 ResolveTarget 返回 "通道不存在" 错误
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ReleaseIndex{})
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for missing channel in empty index")
	}
	if !strings.Contains(err.Error(), "不存在") {
		t.Errorf("error = %q, want containing '不存在'", err.Error())
	}
}

func TestDownloadVerifyInstall_FullFlow(t *testing.T) {
	// 通过替换 installFunc 测试 downloadVerifyInstall 的完整流程
	saveAndRestoreKeys(t)
	pub, priv := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	gzData := makeGzipData(t, []byte("new binary"))
	sigStr, checksum := signAndChecksum(t, priv, "key-1", gzData)

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{
					Version:    "2.0.0",
					Checksums:  map[string]string{filename: checksum},
					Signatures: map[string]string{filename: sigStr},
				},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(index)
			return
		}
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	// 替换 installFunc 避免写入真实路径
	origInstall := installFunc
	installFunc = func(data []byte) (string, error) {
		return "/tmp/sslctl-test", nil
	}
	t.Cleanup(func() { installFunc = origInstall })

	var logs []string
	logFunc := func(format string, args ...interface{}) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	err := downloadVerifyInstall("2.0.0", "main", index, logFunc, server.Client(), server.URL, "curl install.sh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 验证日志包含关键步骤
	logText := strings.Join(logs, "\n")
	for _, keyword := range []string{"开始升级", "下载", "下载完成", "验证数字签名", "签名验证通过", "验证文件完整性", "校验通过", "安装完成"} {
		if !strings.Contains(logText, keyword) {
			t.Errorf("logs should contain %q, got:\n%s", keyword, logText)
		}
	}
}

func TestDownloadVerifyInstall_NoChecksum(t *testing.T) {
	// 校验和为空时跳过校验和验证（只验证签名）
	saveAndRestoreKeys(t)
	pub, priv := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	gzData := makeGzipData(t, []byte("new binary"))
	sig := ed25519.Sign(priv, gzData)
	sigStr := fmt.Sprintf("ed25519:key-1:%s", base64.StdEncoding.EncodeToString(sig))

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{
					Version:    "2.0.0",
					Checksums:  map[string]string{},                       // 没有校验和
					Signatures: map[string]string{filename: sigStr},
				},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	origInstall := installFunc
	installFunc = func(data []byte) (string, error) {
		return "/tmp/sslctl-test", nil
	}
	t.Cleanup(func() { installFunc = origInstall })

	var logs []string
	logFunc := func(format string, args ...interface{}) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	err := downloadVerifyInstall("2.0.0", "main", index, logFunc, server.Client(), server.URL, "curl install.sh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 应该没有 "验证文件完整性" 日志（因为没有校验和）
	logText := strings.Join(logs, "\n")
	if strings.Contains(logText, "验证文件完整性") {
		t.Error("should skip checksum verification when no checksum provided")
	}
}

func TestDownloadVerifyInstall_InstallFailure(t *testing.T) {
	saveAndRestoreKeys(t)
	pub, priv := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	gzData := makeGzipData(t, []byte("new binary"))
	sigStr, checksum := signAndChecksum(t, priv, "key-1", gzData)

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{
					Version:    "2.0.0",
					Checksums:  map[string]string{filename: checksum},
					Signatures: map[string]string{filename: sigStr},
				},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	origInstall := installFunc
	installFunc = func(data []byte) (string, error) {
		return "", fmt.Errorf("install failed: permission denied")
	}
	t.Cleanup(func() { installFunc = origInstall })

	noop := func(format string, args ...interface{}) {}
	err := downloadVerifyInstall("2.0.0", "main", index, noop, server.Client(), server.URL, "curl install.sh")
	if err == nil {
		t.Fatal("expected error from install failure")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %q, want containing 'permission denied'", err.Error())
	}
}

func TestDownloadVerifyInstall_NilClient(t *testing.T) {
	// client == nil 时使用 DownloadBinary（但会因为 HTTPS 校验失败）
	saveAndRestoreKeys(t)
	pub, priv := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	gzData := makeGzipData(t, []byte("binary"))
	sigStr, checksum := signAndChecksum(t, priv, "key-1", gzData)

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{
					Version:    "2.0.0",
					Checksums:  map[string]string{filename: checksum},
					Signatures: map[string]string{filename: sigStr},
				},
			},
		},
	}

	// 使用 http:// URL 调用 downloadVerifyInstall（client=nil），
	// 将触发 DownloadBinary 的 HTTPS 校验失败
	logFunc := func(format string, args ...interface{}) {}
	err := downloadVerifyInstall("2.0.0", "main", index, logFunc, nil, "http://localhost:9999", "curl install.sh")
	if err == nil {
		t.Fatal("expected error for non-HTTPS URL with nil client")
	}
}

func TestExecuteWithClient_FullUpgradeFlow(t *testing.T) {
	// 测试 executeWithClient 走到 upgradeWithRestartAfter 的完整流程
	saveAndRestoreKeys(t)
	pub, priv := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	gzData := makeGzipData(t, []byte("new binary v2"))
	sigStr, checksum := signAndChecksum(t, priv, "key-1", gzData)

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{
					Version:    "2.0.0",
					Checksums:  map[string]string{filename: checksum},
					Signatures: map[string]string{filename: sigStr},
				},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(index)
			return
		}
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	// 替换 installFunc
	origInstall := installFunc
	installFunc = func(data []byte) (string, error) {
		return "/tmp/sslctl-test", nil
	}
	t.Cleanup(func() { installFunc = origInstall })

	var logs []string
	logFunc := func(format string, args ...interface{}) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, logFunc, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true")
	}
	if result.ToVersion != "v2.0.0" {
		t.Errorf("ToVersion = %q, want v2.0.0", result.ToVersion)
	}
	if result.FromVersion != "v1.0.0" {
		t.Errorf("FromVersion = %q, want v1.0.0", result.FromVersion)
	}

	logText := strings.Join(logs, "\n")
	if !strings.Contains(logText, "升级完成") {
		t.Errorf("logs should contain '升级完成', got:\n%s", logText)
	}
}

func TestDownloadVerifyInstall_ChecksumMismatch(t *testing.T) {
	// 签名验证通过但校验和不匹配
	saveAndRestoreKeys(t)
	pub, priv := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	gzData := makeGzipData(t, []byte("binary"))
	sig := ed25519.Sign(priv, gzData)
	sigStr := fmt.Sprintf("ed25519:key-1:%s", base64.StdEncoding.EncodeToString(sig))

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{
					Version:    "2.0.0",
					Checksums:  map[string]string{filename: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
					Signatures: map[string]string{filename: sigStr},
				},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	logFunc := func(format string, args ...interface{}) {}
	err := downloadVerifyInstall("2.0.0", "main", index, logFunc, server.Client(), server.URL, "curl install.sh")
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}
	if !strings.Contains(err.Error(), "完整性验证失败") {
		t.Errorf("error = %q, want containing '完整性验证失败'", err.Error())
	}
}

func TestDownloadVerifyInstall_SignatureVerifyFailed(t *testing.T) {
	// 签名验证失败（数据被篡改，不是密钥找不到）
	saveAndRestoreKeys(t)
	pub, priv := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	gzData := makeGzipData(t, []byte("original"))
	tamperedData := makeGzipData(t, []byte("tampered"))
	sig := ed25519.Sign(priv, gzData) // 签的是原始数据
	sigStr := fmt.Sprintf("ed25519:key-1:%s", base64.StdEncoding.EncodeToString(sig))

	hash := sha256.Sum256(tamperedData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{
					Version:    "2.0.0",
					Checksums:  map[string]string{filename: checksum},
					Signatures: map[string]string{filename: sigStr},
				},
			},
		},
	}

	// 服务器返回篡改后的数据
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tamperedData)
	}))
	defer server.Close()

	logFunc := func(format string, args ...interface{}) {}
	err := downloadVerifyInstall("2.0.0", "main", index, logFunc, server.Client(), server.URL, "curl install.sh")
	if err == nil {
		t.Fatal("expected error for signature verification failure")
	}
	if !strings.Contains(err.Error(), "数字签名验证失败") {
		t.Errorf("error = %q, want containing '数字签名验证失败'", err.Error())
	}
}

func TestExecuteWithClient_DownloadFailed(t *testing.T) {
	// 测试 executeWithClient 中下载失败的错误路径
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{Version: "2.0.0"},
			},
		},
	}

	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(index)
			return
		}
		// 下载二进制文件时返回 500
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, func(format string, args ...interface{}) {}, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for download failure")
	}
}

func TestExecute_HTTPSURLUnreachable(t *testing.T) {
	// 合法 HTTPS URL 但不可达——覆盖 Execute 第 49 行正常路径
	_, err := Execute(Options{
		ReleaseURL:     "https://127.0.0.1:1/sslctl",
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, func(format string, args ...interface{}) {})
	if err == nil {
		t.Fatal("expected error for unreachable HTTPS URL")
	}
}

func TestExecute_URLTrimming(t *testing.T) {
	// URL 末尾有斜杠和空格被正确清理
	_, err := Execute(Options{
		ReleaseURL:     "  https://127.0.0.1:1/sslctl///  ",
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, func(format string, args ...interface{}) {})
	// 应该通过 URL 校验但网络连接失败
	if err == nil {
		t.Fatal("expected error for unreachable URL")
	}
	// 不应该是 URL 校验错误
	var releaseErr *ErrReleaseSource
	if errors.As(err, &releaseErr) && strings.Contains(err.Error(), "未配置") {
		t.Error("URL should have been cleaned up, not rejected as empty")
	}
}

func TestExecute_EntryValidation(t *testing.T) {
	noop := func(format string, args ...interface{}) {}

	tests := []struct {
		name       string
		releaseURL string
		wantErr    string
	}{
		{
			name:       "空 URL",
			releaseURL: "",
			wantErr:    "未配置升级地址",
		},
		{
			name:       "仅空格的 URL",
			releaseURL: "   ",
			wantErr:    "未配置升级地址",
		},
		{
			name:       "仅斜杠的 URL",
			releaseURL: "///",
			wantErr:    "未配置升级地址",
		},
		{
			name:       "HTTP 非 HTTPS",
			releaseURL: "http://example.com/sslctl",
			wantErr:    "必须使用 HTTPS",
		},
		{
			name:       "FTP 协议",
			releaseURL: "ftp://example.com/sslctl",
			wantErr:    "必须使用 HTTPS",
		},
		{
			name:       "无协议前缀",
			releaseURL: "example.com/sslctl",
			wantErr:    "必须使用 HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Execute(Options{
				ReleaseURL:     tt.releaseURL,
				CurrentVersion: "v1.0.0",
				Channel:        "main",
			}, noop)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var releaseErr *ErrReleaseSource
			if !errors.As(err, &releaseErr) {
				t.Errorf("expected *ErrReleaseSource, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}
