package setup

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/testdata/certs"
	"github.com/zhuxbo/sslctl/testdata/testutil"
)

func TestSetupReadsExistingDockerCopyKeyWhenAPIOmitsIt(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	pair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, pair.CertPEM, pair.KeyPEM)
	bindings := []config.SiteBinding{{Enabled: true, ServerType: config.ServerTypeDockerNginx, Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"}, Paths: config.BindingPaths{Certificate: f.CertPath, PrivateKey: f.KeyPath}}}
	data := &fetcher.CertData{Cert: pair.CertPEM}
	key, err := getAndValidatePrivateKey("", bindings, data, validator.New(""), false)
	if err != nil || key != pair.KeyPEM {
		t.Fatalf("setup 应从容器读取配对私钥: %v", err)
	}
	trace, err := os.ReadFile(f.Trace)
	if err != nil || !strings.Contains(string(trace), "exec --user 0 fixture-id sh -c") {
		t.Fatal("默认私钥必须通过容器读取")
	}
	f.WritePair(t, pair.CertPEM, "wrong-key")
	if _, err := getAndValidatePrivateKey("", bindings, data, validator.New(""), false); !errors.Is(err, errNeedPrivateKey) {
		t.Fatalf("不匹配的容器私钥必须报需提供私钥: %v", err)
	}
}
