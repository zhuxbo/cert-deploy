// Package certops 回滚脱离取消传播的测试（P2-1）
package certops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// TestRollbackFromBackup_SurvivesCanceledContext 回滚不得随父 ctx 取消而失败。
//
// 部署失败往往正是因为 ctx 被取消（daemon 关停、检查超时）。若回滚沿用同一个 ctx，
// 兜底回滚会当场失败，直接落进"部署失败且回滚失败（服务可能不可用）"——
// 比根本不贯通 ctx 更糟。
func TestRollbackFromBackup_SurvivesCanceledContext(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	backupDir := filepath.Join(tmpDir, "backup", "site", "20240101-120000")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatalf("创建备份目录失败: %v", err)
	}
	backupCert := "-----BEGIN CERTIFICATE-----\nbackup-cert\n-----END CERTIFICATE-----"
	backupKey := "-----BEGIN RSA PRIVATE KEY-----\nbackup-key\n-----END RSA PRIVATE KEY-----"
	if err := os.WriteFile(filepath.Join(backupDir, "cert.pem"), []byte(backupCert), 0644); err != nil {
		t.Fatalf("写入备份证书失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "key.pem"), []byte(backupKey), 0600); err != nil {
		t.Fatalf("写入备份私钥失败: %v", err)
	}

	targetDir := filepath.Join(tmpDir, "certs", "site")
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		t.Fatalf("创建目标目录失败: %v", err)
	}
	certPath := filepath.Join(targetDir, "cert.pem")
	keyPath := filepath.Join(targetDir, "key.pem")
	if err := os.WriteFile(certPath, []byte("broken-cert"), 0644); err != nil {
		t.Fatalf("写入当前证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("broken-key"), 0600); err != nil {
		t.Fatalf("写入当前私钥失败: %v", err)
	}

	binding := &config.SiteBinding{
		ServerName: "site",
		ServerType: config.ServerTypeNginx,
		Paths:      config.BindingPaths{Certificate: certPath, PrivateKey: keyPath},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := svc.rollbackFromBackup(ctx, binding, backupDir); err != nil {
		t.Fatalf("已取消的 ctx 下回滚应照常执行: %v", err)
	}

	got, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取回滚后证书失败: %v", err)
	}
	if string(got) != backupCert {
		t.Errorf("证书未回滚，内容 = %q", string(got))
	}
}

// TestRollbackFromBackup_CtxErrNotPropagated 交给部署器的 ctx 本身必须是未取消的，
// 而不只是"文件恰好复制成功了"。这里直接断言错误链里不含 context.Canceled。
func TestRollbackFromBackup_CtxErrNotPropagated(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	backupDir := filepath.Join(tmpDir, "backup", "site", "20240101-120000")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatalf("创建备份目录失败: %v", err)
	}
	for name, mode := range map[string]os.FileMode{"cert.pem": 0644, "key.pem": 0600} {
		if err := os.WriteFile(filepath.Join(backupDir, name), []byte("backup"), mode); err != nil {
			t.Fatalf("写入备份文件失败: %v", err)
		}
	}

	targetDir := filepath.Join(tmpDir, "certs", "site")
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		t.Fatalf("创建目标目录失败: %v", err)
	}
	binding := &config.SiteBinding{
		ServerName: "site",
		ServerType: config.ServerTypeNginx,
		Paths: config.BindingPaths{
			Certificate: filepath.Join(targetDir, "cert.pem"),
			PrivateKey:  filepath.Join(targetDir, "key.pem"),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = svc.rollbackFromBackup(ctx, binding, backupDir)
	if errors.Is(err, context.Canceled) {
		t.Fatalf("回滚命令不应因父 ctx 取消而失败: %v", err)
	}
}
