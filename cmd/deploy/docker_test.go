package deploy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/testdata/certs"
	"github.com/zhuxbo/sslctl/testdata/testutil"
)

func TestDeployBindingDockerCopyRoutesContainer(t *testing.T) {
	for _, failTest := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[failTest], func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			f.WritePair(t, "old-cert", "old-key")
			pair, err := certs.GenerateValidCert("test.example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			binding := &config.SiteBinding{ServerName: "test.example.com", ServerType: config.ServerTypeDockerNginx, Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"}, Paths: config.BindingPaths{Certificate: f.CertPath, PrivateKey: f.KeyPath}, Reload: config.ReloadConfig{TestCommand: "docker exec web nginx -t", ReloadCommand: "docker exec web nginx -s reload"}}
			if failTest {
				t.Setenv("TEST_DOCKER_FAIL_TEST", "1")
			}
			err = deployToBinding(t.Context(), binding, &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM, backup.NewManager(t.TempDir(), 5), nil)
			if (err != nil) != failTest {
				t.Fatalf("deployToBinding()=%v, wantError=%v", err, failTest)
			}
			expected := pair.CertPEM
			if failTest {
				expected = "old-cert"
				f.AssertPair(t, "old-cert", "old-key")
			} else {
				f.AssertPair(t, pair.CertPEM, pair.KeyPEM)
			}
			loaded, err := os.ReadFile(filepath.Join(f.Dir, "loaded-cert"))
			if err != nil || string(loaded) != expected {
				t.Fatal("CLI 必须在容器中重载预期证书")
			}
		})
	}
}
