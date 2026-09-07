package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainerBackupDoesNotRestoreIntoHostPaths(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for name, content := range map[string]string{certPath: "old-cert", keyPath: "old-key"} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mgr := NewManager(filepath.Join(dir, "backups"), 5)
	result, err := mgr.BackupContainer("site", "web", "/etc/nginx/cert.pem", "/etc/nginx/key.pem", certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := mgr.LoadMetadata(result.BackupPath)
	if err != nil || meta.ContainerName != "web" || meta.CertPath != "/etc/nginx/cert.pem" || meta.KeyPath != "/etc/nginx/key.pem" {
		t.Fatalf("未记录容器备份的目标: %v, %v", meta, err)
	}
	if _, err := mgr.Restore("site"); err == nil {
		t.Fatal("宿主机恢复入口不得处理容器内目标")
	}
	firstPath := result.BackupPath
	result, err = mgr.BackupContainer("site", "web", "/etc/nginx/cert.pem", "/etc/nginx/key.pem", certPath, keyPath)
	if err != nil || result.BackupPath == firstPath {
		t.Fatalf("连续容器部署必须保留独立备份: %v, %v", result, err)
	}
}
