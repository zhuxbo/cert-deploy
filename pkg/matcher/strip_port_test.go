package matcher

import "testing"

func TestStripPort(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"带443端口", "www.example.com:443", "www.example.com"},
		{"带80端口", "www.example.com:80", "www.example.com"},
		{"无端口", "www.example.com", "www.example.com"},
		{"带scheme和端口", "https://www.example.com:443", "www.example.com"},
		{"带scheme无端口", "http://www.example.com", "www.example.com"},
		{"前后空白", "  www.example.com:443  ", "www.example.com"},
		{"IPv4带端口", "192.168.1.1:443", "192.168.1.1"},
		{"IPv4无端口", "192.168.1.1", "192.168.1.1"},
		{"IPv6带括号端口", "[2001:db8::1]:443", "2001:db8::1"},
		{"裸IPv6保留", "2001:db8::1", "2001:db8::1"},
		{"default占位", "_default_", "_default_"},
		{"default带端口", "_default_:443", "_default_"},
		{"空字符串", "", ""},
		{"端口为空", "example.com:", "example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := StripPort(c.in); got != c.want {
				t.Errorf("StripPort(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
