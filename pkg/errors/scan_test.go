package errors

import (
	"strings"
	"testing"
)

func TestPrefixUnknownError_Error(t *testing.T) {
	e := &PrefixUnknownError{
		ServerKind: ServerKindNginx,
		Sites: []AffectedSite{
			{ServerName: "a.com"},
			{ServerName: "b.com"},
		},
	}
	msg := e.Error()
	if !strings.Contains(msg, "2") {
		t.Errorf("Error() 应包含站点数量：%s", msg)
	}
	if !strings.Contains(msg, "nginx") {
		t.Errorf("Error() 应包含 server kind：%s", msg)
	}
}

func TestPrefixUnknownError_RenderHintNginx(t *testing.T) {
	e := &PrefixUnknownError{
		ServerKind: ServerKindNginx,
		BinaryPath: `C:\nginx\nginx.exe`,
		Candidates: []string{`C:\nginx\`, `C:\nginx\conf\`},
		Sites: []AffectedSite{
			{
				ServerName:      "example.com",
				ConfigFile:      `C:\nginx\conf\vhost\example.conf`,
				CertificatePath: "cert/example.pem",
				PrivateKeyPath:  "cert/example.key",
			},
		},
	}

	hint := e.RenderHint()

	musts := []string{
		"无法确定 Web 服务器相对路径的解析基准",
		"受影响的站点:",
		"example.com",
		`C:\nginx\conf\vhost\example.conf`,
		"cert/example.pem",
		"ssl_certificate",
		"ssl_certificate_key",
		"常用路径:",
		`C:\nginx\`,
		"部署已中止",
		"修复方法 1:",
		"编辑配置文件",
		"nginx -t",
		"sslctl scan|setup",
		"修复方法 2:",
		"--nginx-prefix",
		"<实际 prefix 路径>",
		"[其它原有参数]",
	}
	for _, m := range musts {
		if !strings.Contains(hint, m) {
			t.Errorf("RenderHint(nginx) 缺少预期内容：%q\n实际输出:\n%s", m, hint)
		}
	}
	// nginx 场景不应出现 Apache 相关内容
	forbidden := []string{"SSLCertificateFile", "apachectl", "--apache-prefix"}
	for _, f := range forbidden {
		if strings.Contains(hint, f) {
			t.Errorf("RenderHint(nginx) 不应包含 Apache 相关内容：%q\n%s", f, hint)
		}
	}
}

func TestPrefixUnknownError_RenderHintApache(t *testing.T) {
	e := &PrefixUnknownError{
		ServerKind: ServerKindApache,
		BinaryPath: "/usr/sbin/httpd",
		Candidates: []string{"/etc/httpd/", "/etc/httpd/conf/"},
		Sites: []AffectedSite{
			{
				ServerName:      "example.com",
				ConfigFile:      "/etc/httpd/sites/example.conf",
				CertificatePath: "ssl/example.crt",
				PrivateKeyPath:  "ssl/example.key",
				ChainPath:       "ssl/chain.crt",
			},
		},
	}

	hint := e.RenderHint()

	musts := []string{
		"受影响的站点:",
		"example.com",
		"ssl/example.crt",
		"ssl/example.key",
		"ssl/chain.crt",
		"SSLCertificateFile",
		"SSLCertificateKeyFile",
		"SSLCertificateChainFile",
		"apachectl configtest",
		"--apache-prefix",
		"修复方法 1:",
		"修复方法 2:",
	}
	for _, m := range musts {
		if !strings.Contains(hint, m) {
			t.Errorf("RenderHint(apache) 缺少预期内容：%q\n实际输出:\n%s", m, hint)
		}
	}
	// apache 场景不应出现 nginx 相关内容
	forbidden := []string{"ssl_certificate ", "ssl_certificate_key", "nginx -t", "--nginx-prefix"}
	for _, f := range forbidden {
		if strings.Contains(hint, f) {
			t.Errorf("RenderHint(apache) 不应包含 nginx 相关内容：%q\n%s", f, hint)
		}
	}
}

func TestPrefixUnknownError_RenderHint_NoCandidates(t *testing.T) {
	e := &PrefixUnknownError{
		ServerKind: ServerKindNginx,
		Sites:      []AffectedSite{{ServerName: "a.com", CertificatePath: "cert/a.pem"}},
	}
	hint := e.RenderHint()
	if strings.Contains(hint, "常用路径") {
		t.Errorf("无候选时不应出现 '常用路径' 段落：\n%s", hint)
	}
}

func TestPrefixUnknownError_RenderHint_EmptyServerName(t *testing.T) {
	e := &PrefixUnknownError{
		ServerKind: ServerKindNginx,
		Sites:      []AffectedSite{{CertificatePath: "cert/a.pem"}},
	}
	hint := e.RenderHint()
	if !strings.Contains(hint, "<未命名>") {
		t.Errorf("空 ServerName 应显示 <未命名>：\n%s", hint)
	}
}
