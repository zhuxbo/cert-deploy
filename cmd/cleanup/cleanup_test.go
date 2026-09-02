package cleanup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRun_RequiresExactlyOneTarget(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing", args: nil},
		{name: "both", args: []string{"--site", "a.example.com", "--cert", "cert-a"}},
		{name: "positional", args: []string{"--site", "a.example.com", "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(tt.args, strings.NewReader(""), &output, &output, cm); err == nil {
				t.Fatal("run() error = nil, want target validation error")
			}
		})
	}
}

func TestRun_HelpIsSuccessful(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	var output bytes.Buffer
	if err := run([]string{"--help"}, strings.NewReader(""), &output, &output, cm); err != nil {
		t.Fatalf("run(--help) error = %v", err)
	}
	if !strings.Contains(output.String(), "sslctl cleanup --site") {
		t.Fatalf("help output = %q", output.String())
	}
}

func TestRun_ListShowsAllCertificatesAndSiteBindings(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.Save(&config.Config{Certificates: []config.CertConfig{
		{
			CertName: "enabled-cert",
			Enabled:  true,
			Bindings: []config.SiteBinding{
				{ServerName: "enabled.example.com", Enabled: true},
				{ServerName: "disabled.example.com", Enabled: false},
			},
		},
		{CertName: "disabled-cert", Enabled: false},
		{CertName: "enabled-cert", Enabled: true, Bindings: []config.SiteBinding{{ServerName: "duplicate.example.com", Enabled: true}}},
	}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	var output bytes.Buffer
	if err := run([]string{"--list"}, strings.NewReader(""), &output, &output, cm); err != nil {
		t.Fatalf("run(--list) error = %v", err)
	}
	for _, want := range []string{
		"受管证书：3 条记录",
		"enabled-cert [启用]",
		"disabled-cert [禁用]",
		"受管站点绑定：3 条",
		"enabled.example.com -> enabled-cert [启用]",
		"disabled.example.com -> enabled-cert [禁用]",
		"duplicate.example.com -> enabled-cert [启用]",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output = %q, want %q", output.String(), want)
		}
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Certificates) != 3 {
		t.Fatalf("--list changed config: %+v", cfg.Certificates)
	}
}

func TestRun_ListMustBeUsedAlone(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	for _, args := range [][]string{
		{"--list", "--site", "a.example.com"},
		{"--list", "--cert", "cert-a"},
		{"--list", "--yes"},
	} {
		var output bytes.Buffer
		err := run(args, strings.NewReader(""), &output, &output, cm)
		if err == nil || !strings.Contains(err.Error(), "--list 必须单独使用") {
			t.Fatalf("run(%v) error = %v, want standalone list error", args, err)
		}
	}
}

func TestRun_DeclinedConfirmationPreservesManagementState(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&config.CertConfig{
		CertName: "keep-cert",
		Bindings: []config.SiteBinding{{ServerName: "keep.example.com", Enabled: true}},
	}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	var output bytes.Buffer
	if err := run([]string{"--site", "keep.example.com"}, strings.NewReader("n\n"), &output, &output, cm); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if _, err := cm.GetCert("keep-cert"); err != nil {
		t.Fatalf("declined cleanup changed config: %v", err)
	}
	if !strings.Contains(output.String(), "已取消") {
		t.Fatalf("output = %q, want cancellation message", output.String())
	}
}

func TestRun_OutputFailureDoesNotStartCleanup(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&config.CertConfig{CertName: "keep-cert"}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	err = run([]string{"--cert", "keep-cert"}, strings.NewReader("y\n"), failingWriter{}, &bytes.Buffer{}, cm)
	if err == nil || !strings.Contains(err.Error(), "输出") {
		t.Fatalf("run() error = %v, want output failure", err)
	}
	if _, err := cm.GetCert("keep-cert"); err != nil {
		t.Fatalf("output failure changed config: %v", err)
	}
}

func TestRun_YesRemovesCertificateAndReportsPreservedFiles(t *testing.T) {
	workDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(workDir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&config.CertConfig{
		CertName: "remove-cert",
		Bindings: []config.SiteBinding{{ServerName: "remove.example.com", Enabled: true}},
	}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}
	deployed := filepath.Join(cm.GetCertsDir(), "remove.example.com", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(deployed), 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(deployed, []byte("live"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var output bytes.Buffer
	if err := run([]string{"--cert", "remove-cert", "--yes"}, strings.NewReader(""), &output, &output, cm); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if _, err := cm.GetCert("remove-cert"); err == nil {
		t.Fatal("certificate config still exists")
	}
	if _, err := os.Stat(deployed); err != nil {
		t.Fatalf("deployed file was removed: %v", err)
	}
	for _, want := range []string{"已解除", "1 个站点绑定", "在线证书文件和 Web 配置已保留"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output = %q, want %q", output.String(), want)
		}
	}
}

func TestRun_RefusesCleanupWhileRenewalLockIsHeld(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&config.CertConfig{CertName: "keep-cert"}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}
	release, acquired, err := config.AcquireRenewalLock(cm.GetWorkDir())
	if err != nil || !acquired {
		t.Fatalf("AcquireRenewalLock() = acquired %v, err %v", acquired, err)
	}
	defer release()

	var output bytes.Buffer
	err = run([]string{"--cert", "keep-cert", "--yes"}, strings.NewReader(""), &output, &output, cm)
	if err == nil || !strings.Contains(err.Error(), "正在执行") {
		t.Fatalf("run() error = %v, want lock conflict", err)
	}
	if _, err := cm.GetCert("keep-cert"); err != nil {
		t.Fatalf("lock conflict changed config: %v", err)
	}
}
