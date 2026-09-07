package certops

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/testdata/certs"
	"github.com/zhuxbo/sslctl/testdata/testutil"
)

func copyBinding(f *testutil.DockerCLI) *config.SiteBinding {
	return &config.SiteBinding{
		ServerName: "test.example.com", ServerType: config.ServerTypeDockerNginx, Enabled: true,
		Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"},
		Paths:  config.BindingPaths{Certificate: f.CertPath, PrivateKey: f.KeyPath},
		Reload: config.ReloadConfig{TestCommand: "docker exec web nginx -t", ReloadCommand: "docker exec web nginx -s reload"},
	}
}

func TestDeployDockerCopyUsesContainerAndPersistsBackup(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	oldCert, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	newCert, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, oldCert.CertPEM, oldCert.KeyPEM)
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	if err := svc.DeployToBinding(t.Context(), copyBinding(f), &fetcher.CertData{Cert: newCert.CertPEM}, newCert.KeyPEM); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, newCert.CertPEM, newCert.KeyPEM)
	loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
	if err != nil || string(loaded) != newCert.CertPEM {
		t.Fatal("未在目标容器中重载新证书")
	}
	backupPath, err := svc.backupMgr.GetLatestBackup("test.example.com")
	if err != nil {
		t.Fatal(err)
	}
	backupKey, err := os.ReadFile(filepath.Join(backupPath, "key.pem"))
	if err != nil || string(backupKey) != oldCert.KeyPEM {
		t.Fatal("未持久备份容器原私钥")
	}
	trace, err := os.ReadFile(f.Trace)
	if err != nil || !strings.Contains(string(trace), "exec fixture-id sh -c nginx -s reload") || strings.Contains(string(trace), "exec web ") {
		t.Fatal("单次部署未固定到解析后的容器 ID")
	}
}

func TestDeployDockerCopyFailuresRestoreOriginalFiles(t *testing.T) {
	for _, failure := range []string{"TEST_DOCKER_FAIL_CP", "TEST_DOCKER_FAIL_TEST", "TEST_DOCKER_FAIL_RELOAD"} {
		t.Run(failure, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			oldCert, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			newCert, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.WritePair(t, oldCert.CertPEM, oldCert.KeyPEM)
			value := "1"
			if failure == "TEST_DOCKER_FAIL_CP" {
				value = "2"
			}
			t.Setenv(failure, value)
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(cm, logger.NewNopLogger())
			if err := svc.DeployToBinding(t.Context(), copyBinding(f), &fetcher.CertData{Cert: newCert.CertPEM}, newCert.KeyPEM); err == nil {
				t.Fatal("失败不能被报为部署成功")
			}
			f.AssertPair(t, oldCert.CertPEM, oldCert.KeyPEM)
			loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
			if err != nil || string(loaded) != oldCert.CertPEM {
				t.Fatal("回滚后应重新加载旧证书")
			}
		})
	}
}

func TestDeployDockerCopyReadOnlyFailsBeforeWriting(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	t.Setenv("TEST_DOCKER_INFO", f.ReadOnlyMountJSON())
	newCert, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	if err := svc.DeployToBinding(t.Context(), copyBinding(f), &fetcher.CertData{Cert: newCert.CertPEM}, newCert.KeyPEM); err == nil {
		t.Fatal("只读挂载不能写入")
	}
	f.AssertPair(t, "old-cert", "old-key")
}

func TestDockerCopyPrivateKeyAndManualRollback(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	oldPair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	newPair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, oldPair.CertPEM, oldPair.KeyPEM)
	if err := os.Chmod(f.KeyPath, 0640); err != nil {
		t.Fatal(err)
	}
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binding := copyBinding(f)
	cert := &config.CertConfig{CertName: "copy-test", Bindings: []config.SiteBinding{*binding}}
	key, err := GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, oldPair.CertPEM, "", nil)
	if err != nil || key != oldPair.KeyPEM {
		t.Fatalf("读取容器私钥失败: %v", err)
	}
	if err := savePendingKey(cm.GetWorkDir(), cert.CertName, newPair.KeyPEM); err != nil {
		t.Fatal(err)
	}
	key, err = GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, newPair.CertPEM, "", nil)
	if err != nil || key != newPair.KeyPEM {
		t.Fatalf("pending 私钥匹配失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	if err := svc.DeployToBinding(t.Context(), binding, &fetcher.CertData{Cert: newPair.CertPEM}, key); err != nil {
		t.Fatal(err)
	}
	CommitPendingKeyIfMatches(cm.GetWorkDir(), cert, key, nil)
	if _, err := readPendingKey(cm.GetWorkDir(), cert.CertName); !stderrors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending 未清理: %v", err)
	}
	backupPath, err := svc.backupMgr.GetLatestBackup(binding.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := svc.backupMgr.LoadMetadata(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreDockerBackup(t.Context(), svc.backupMgr, backupPath, meta); err != nil {
		t.Fatal(err)
	}
	f.AssertPair(t, oldPair.CertPEM, oldPair.KeyPEM)
	info, err := os.Stat(f.KeyPath)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("回滚未恢复私钥权限: %v, %v", info, err)
	}
	loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
	if err != nil || string(loaded) != oldPair.CertPEM {
		t.Fatal("手动回滚未加载旧证书")
	}
}

func TestDockerCopyDoesNotUseHostWebroot(t *testing.T) {
	binding := copyBinding(&testutil.DockerCLI{})
	binding.Paths.Webroot = t.TempDir()
	cert := &config.CertConfig{Bindings: []config.SiteBinding{*binding}}
	if roots := collectWebroots(cert); len(roots) != 0 {
		t.Fatal("不能把容器 webroot 用作宿主机路径")
	}
}

func TestDockerCopyMixedBindingPendingDoesNotRewriteFailedHost(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	oldPair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	newPair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, newPair.CertPEM, newPair.KeyPEM)
	hostKey := filepath.Join(t.TempDir(), "host.key")
	if err := os.WriteFile(hostKey, []byte(oldPair.KeyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	cert := &config.CertConfig{CertName: "mixed", Bindings: []config.SiteBinding{
		{Enabled: true, ServerType: config.ServerTypeNginx, Paths: config.BindingPaths{PrivateKey: hostKey}},
		*copyBinding(f),
	}}
	workDir := t.TempDir()
	if err := savePendingKey(workDir, cert.CertName, newPair.KeyPEM); err != nil {
		t.Fatal(err)
	}
	CommitPendingKeyIfMatches(workDir, cert, newPair.KeyPEM, nil)
	host, err := os.ReadFile(hostKey)
	if err != nil || string(host) != oldPair.KeyPEM {
		t.Fatal("pending 清理不能重写部署失败绑定的私钥")
	}
	key, err := GetPrivateKeyForCert(t.Context(), workDir, cert, newPair.CertPEM, "", nil)
	if err != nil || key != newPair.KeyPEM {
		t.Fatalf("应从已成功部署的容器绑定读取配对私钥: %v", err)
	}
}

func TestDockerCopyPreflightAndRecoveryErrors(t *testing.T) {
	for _, failure := range []string{"invalid-cert", "wrong-key", "invalid-binding", "inspect", "missing-cert", "missing-key", "backup", "temporary", "rollback"} {
		t.Run(failure, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			pair, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.WritePair(t, "old-cert", "old-key")
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(cm, logger.NewNopLogger())
			binding := copyBinding(f)
			data, key := &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM
			switch failure {
			case "invalid-cert":
				data.Cert = "invalid-certificate"
			case "wrong-key":
				key = "invalid-private-key"
			case "invalid-binding":
				binding.Reload.TestCommand = "invalid command"
			case "inspect":
				t.Setenv("TEST_DOCKER_INSPECT_FAIL", "1")
			case "missing-cert":
				if err := os.Remove(f.CertPath); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if err := os.Remove(f.KeyPath); err != nil {
					t.Fatal(err)
				}
			case "backup":
				if err := os.RemoveAll(cm.GetBackupDir()); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cm.GetBackupDir(), []byte("not-directory"), 0600); err != nil {
					t.Fatal(err)
				}
			case "temporary":
				t.Setenv("TMPDIR", filepath.Join(f.Dir, "missing"))
			case "rollback":
				t.Setenv("TEST_DOCKER_FAIL_TEST", "1")
				t.Setenv("TEST_DOCKER_FAIL_RELOAD", "1")
			}
			err = svc.DeployToBinding(t.Context(), binding, data, key)
			if err == nil {
				t.Fatal("错误必须阻止成功结果")
			}
			if failure == "rollback" && (!strings.Contains(err.Error(), "回滚失败") || !strings.Contains(err.Error(), cm.GetBackupDir())) {
				t.Fatalf("回滚失败应提供持久备份位置: %v", err)
			}
			if !strings.HasPrefix(failure, "missing-") {
				f.AssertPair(t, "old-cert", "old-key")
			}
		})
	}
}

func TestDockerCopyPrivateKeyFailuresAndPendingRetention(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	binding := copyBinding(f)
	if _, err := ReadBindingPrivateKey(t.Context(), nil); err == nil {
		t.Fatal("缺少绑定应失败")
	}
	t.Setenv("TEST_DOCKER_INSPECT_FAIL", "1")
	if _, err := ReadBindingPrivateKey(t.Context(), binding); err == nil {
		t.Fatal("不能忽略容器探测失败")
	}
	t.Setenv("TEST_DOCKER_INSPECT_FAIL", "")
	cert := &config.CertConfig{CertName: "retained", Bindings: []config.SiteBinding{*binding}}
	workDir := t.TempDir()
	if err := savePendingKey(workDir, cert.CertName, "pending-key"); err != nil {
		t.Fatal(err)
	}
	CommitPendingKeyIfMatches(workDir, cert, "pending-key", logger.NewNopLogger())
	if key, err := readPendingKey(workDir, cert.CertName); err != nil || key != "pending-key" {
		t.Fatalf("未确认部署时应保留 pending: %v", err)
	}
	f.AssertPair(t, "old-cert", "old-key")
	cert.Bindings[0].Enabled = false
	if key, err := GetPrivateKey(t.Context(), cert, "", nil); err != nil || key != "old-key" {
		t.Fatalf("没有启用绑定时保留原有回退取钥行为: %v", err)
	}
}

func TestDockerCopyCancellationStillRestoresAndReloads(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	pair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, "old-cert", "old-key")
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	t.Setenv("TEST_DOCKER_WAIT_CP", "2")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reachedCopy := make(chan bool, 1)
	go func() {
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if _, err := os.Stat(filepath.Join(f.Dir, "cp-blocked")); err == nil {
					reachedCopy <- true
					cancel()
					return
				}
			case <-deadline.C:
				reachedCopy <- false
				cancel()
				return
			case <-ctx.Done():
				reachedCopy <- false
				return
			}
		}
	}()
	err = svc.DeployToBinding(ctx, copyBinding(f), &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM)
	if !<-reachedCopy {
		t.Fatal("未进入复制阶段，不能证明取消后回滚")
	}
	if err == nil || !strings.Contains(err.Error(), "已回滚") {
		t.Fatalf("取消后仍须用独立预算回滚: %v", err)
	}
	f.AssertPair(t, "old-cert", "old-key")
	loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
	if err != nil || string(loaded) != "old-cert" {
		t.Fatal("取消后未重新加载旧证书")
	}
}
