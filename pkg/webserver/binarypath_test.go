package webserver

import "testing"

func TestExtractServiceExePath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", `C:\nginx\nginx.exe`, `C:\nginx\nginx.exe`},
		{"plain with args", `C:\nginx\nginx.exe -s reload`, `C:\nginx\nginx.exe`},
		{"plain with tab", "C:\\nginx\\nginx.exe\t-s\treload", `C:\nginx\nginx.exe`},
		{"quoted", `"C:\Program Files\nginx\nginx.exe"`, `C:\Program Files\nginx\nginx.exe`},
		{"quoted with args", `"C:\Program Files\nginx\nginx.exe" -s reload`, `C:\Program Files\nginx\nginx.exe`},
		{"quoted with spaces", `"C:\BtSoft\nginx\nginx_server.exe"`, `C:\BtSoft\nginx\nginx_server.exe`},
		{"unbalanced quote", `"C:\broken`, ""},
		{"whitespace only", "   ", ""},
		{"leading whitespace", `  C:\nginx\nginx.exe`, `C:\nginx\nginx.exe`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractServiceExePath(c.in); got != c.want {
				t.Errorf("extractServiceExePath(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeWindowsPath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"lowercase", `C:\nginx\nginx.exe`, `c:\nginx\nginx.exe`},
		{"forward slash", `C:/nginx/nginx.exe`, `c:\nginx\nginx.exe`},
		{"double slash", `C:\\nginx\\nginx.exe`, `c:\nginx\nginx.exe`},
		{"trailing slash", `C:\nginx\`, `c:\nginx`},
		{"mixed case", `C:\NGINX\Nginx.EXE`, `c:\nginx\nginx.exe`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeWindowsPath(c.in); got != c.want {
				t.Errorf("normalizeWindowsPath(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestNormalizeWindowsPath_EqualityCheck 验证规范化后等价路径相等。
func TestNormalizeWindowsPath_EqualityCheck(t *testing.T) {
	pairs := []struct {
		a, b string
	}{
		{`C:\nginx\nginx.exe`, `c:\nginx\nginx.exe`},
		{`C:\nginx\nginx.exe`, `C:/nginx/nginx.exe`},
		{`C:\nginx\nginx.exe`, `C:\\nginx\\nginx.exe`},
	}
	for _, p := range pairs {
		if normalizeWindowsPath(p.a) != normalizeWindowsPath(p.b) {
			t.Errorf("expected equal: %q vs %q -> %q vs %q",
				p.a, p.b, normalizeWindowsPath(p.a), normalizeWindowsPath(p.b))
		}
	}
}
