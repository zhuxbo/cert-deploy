package cleanup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
)

func TestServiceRemoveCertificate_CleansInternalStateButPreservesDeployedFiles(t *testing.T) {
	workDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(workDir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	externalValidation := filepath.Join(t.TempDir(), "challenge.txt")
	writeFixture(t, externalValidation)
	cert := &config.CertConfig{
		CertName: "remove-cert",
		Bindings: []config.SiteBinding{
			{ServerName: "a.example.com", Enabled: true},
			{ServerName: "b.example.com", Enabled: true},
		},
		Metadata: config.CertMetadata{ValidationFiles: []string{externalValidation}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	pendingPath := filepath.Join(workDir, "pending-keys", cert.CertName, "pending-key.pem")
	backupA := filepath.Join(cm.GetBackupDir(), "a.example.com", "20260101", "key.pem")
	backupB := filepath.Join(cm.GetBackupDir(), "b.example.com", "20260101", "key.pem")
	deployedA := filepath.Join(cm.GetCertsDir(), "a.example.com", "key.pem")
	deployedB := filepath.Join(cm.GetCertsDir(), "b.example.com", "key.pem")
	for _, path := range []string{pendingPath, backupA, backupB, deployedA, deployedB} {
		writeFixture(t, path)
	}

	result, err := New(cm).RemoveCertificate(cert.CertName)
	if err != nil {
		t.Fatalf("RemoveCertificate() error = %v", err)
	}
	if result.RemovedBindings != 2 || result.RemovedCertificates != 1 {
		t.Fatalf("result = %+v, want 2 bindings and 1 certificate", result)
	}
	if _, err := cm.GetCert(cert.CertName); err == nil {
		t.Fatal("certificate config still exists")
	}
	for _, path := range []string{pendingPath, filepath.Dir(filepath.Dir(backupA)), filepath.Dir(filepath.Dir(backupB))} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("internal path %s still exists or cannot be checked: %v", path, err)
		}
	}
	for _, path := range []string{deployedA, deployedB, externalValidation} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("live/external file %s must be preserved: %v", path, err)
		}
	}
}

func TestServiceRemoveSite_KeepsSharedCertificatePendingState(t *testing.T) {
	workDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(workDir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	cert := &config.CertConfig{
		CertName: "shared-cert",
		Bindings: []config.SiteBinding{
			{ServerName: "remove.example.com", Enabled: true},
			{ServerName: "keep.example.com", Enabled: true},
		},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	pendingPath := filepath.Join(workDir, "pending-keys", cert.CertName, "pending-key.pem")
	removedBackup := filepath.Join(cm.GetBackupDir(), "remove.example.com", "20260101", "key.pem")
	keptBackup := filepath.Join(cm.GetBackupDir(), "keep.example.com", "20260101", "key.pem")
	deployed := filepath.Join(cm.GetCertsDir(), "remove.example.com", "key.pem")
	for _, path := range []string{pendingPath, removedBackup, keptBackup, deployed} {
		writeFixture(t, path)
	}

	result, err := New(cm).RemoveSite("remove.example.com")
	if err != nil {
		t.Fatalf("RemoveSite() error = %v", err)
	}
	if result.RemovedBindings != 1 || result.RemovedCertificates != 0 {
		t.Fatalf("result = %+v, want 1 binding and 0 certificates", result)
	}
	for _, path := range []string{pendingPath, keptBackup, deployed} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("path %s must be preserved: %v", path, err)
		}
	}
	if _, err := os.Lstat(filepath.Dir(filepath.Dir(removedBackup))); !os.IsNotExist(err) {
		t.Fatalf("removed site backup still exists or cannot be checked: %v", err)
	}
}

func TestServiceRemoveSite_LastBindingCleansCertificatePendingState(t *testing.T) {
	workDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(workDir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	cert := &config.CertConfig{
		CertName: "orphan-cert",
		Bindings: []config.SiteBinding{{ServerName: "only.example.com", Enabled: true}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}
	pendingPath := filepath.Join(workDir, "pending-keys", cert.CertName, "pending-key.pem")
	writeFixture(t, pendingPath)

	result, err := New(cm).RemoveSite("only.example.com")
	if err != nil {
		t.Fatalf("RemoveSite() error = %v", err)
	}
	if result.RemovedCertificates != 1 {
		t.Fatalf("RemovedCertificates = %d, want 1", result.RemovedCertificates)
	}
	if _, err := cm.GetCert(cert.CertName); err == nil {
		t.Fatal("orphan certificate config still exists")
	}
	if _, err := os.Lstat(pendingPath); !os.IsNotExist(err) {
		t.Fatalf("orphan pending key still exists or cannot be checked: %v", err)
	}
}

func TestServiceRemoveCertificate_MissingTargetDoesNotDeleteUnrelatedData(t *testing.T) {
	workDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(workDir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	unrelated := filepath.Join(cm.GetBackupDir(), "keep.example.com", "20260101", "key.pem")
	writeFixture(t, unrelated)

	_, err = New(cm).RemoveCertificate("missing-cert")
	if !errors.Is(err, config.ErrCertNotFound) {
		t.Fatalf("RemoveCertificate() error = %v, want ErrCertNotFound", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated data changed: %v", err)
	}
}

func TestServiceRemoveCertificate_PreservesBackupStillReferencedByAnotherCertificate(t *testing.T) {
	workDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(workDir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.Save(&config.Config{Certificates: []config.CertConfig{
		{CertName: "remove-cert", Bindings: []config.SiteBinding{{ServerName: "shared.example.com"}}},
		{CertName: "keep-cert", Bindings: []config.SiteBinding{{ServerName: "shared.example.com"}}},
	}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	sharedBackup := filepath.Join(cm.GetBackupDir(), "shared.example.com", "20260101", "key.pem")
	writeFixture(t, sharedBackup)

	if _, err := New(cm).RemoveCertificate("remove-cert"); err != nil {
		t.Fatalf("RemoveCertificate() error = %v", err)
	}
	if _, err := os.Stat(sharedBackup); err != nil {
		t.Fatalf("backup used by remaining certificate was removed: %v", err)
	}
}

func writeFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", path, err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
