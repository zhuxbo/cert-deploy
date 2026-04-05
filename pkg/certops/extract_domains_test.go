// Package certops extractDomainsFromParsedCert 测试
package certops

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"reflect"
	"sort"
	"testing"
)

// TestExtractDomainsFromParsedCert 测试从已解析证书提取域名
func TestExtractDomainsFromParsedCert(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want []string
	}{
		{
			name: "只有 DNSNames，无 IP",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com", "www.example.com"},
				Subject:  pkix.Name{CommonName: "example.com"},
			},
			want: []string{"example.com", "www.example.com"},
		},
		{
			name: "只有 IPAddresses，无 DNS",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
				Subject:     pkix.Name{CommonName: "192.168.1.1"},
			},
			want: []string{"192.168.1.1", "10.0.0.1"},
		},
		{
			name: "CN 与 SAN 重复时去重",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com", "www.example.com"},
				Subject:  pkix.Name{CommonName: "example.com"},
			},
			want: []string{"example.com", "www.example.com"},
		},
		{
			name: "CN 与 IP SAN 重复时去重",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("1.2.3.4")},
				Subject:     pkix.Name{CommonName: "1.2.3.4"},
			},
			want: []string{"1.2.3.4"},
		},
		{
			name: "空证书（无 DNS、无 IP、无 CN）",
			cert: &x509.Certificate{},
			want: nil,
		},
		{
			name: "通配符域名正确返回",
			cert: &x509.Certificate{
				DNSNames: []string{"*.example.com"},
				Subject:  pkix.Name{CommonName: "*.example.com"},
			},
			want: []string{"*.example.com"},
		},
		{
			name: "DNS + IP 混合",
			cert: &x509.Certificate{
				DNSNames:    []string{"example.com"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
				Subject:     pkix.Name{CommonName: "example.com"},
			},
			want: []string{"example.com", "10.0.0.1"},
		},
		{
			name: "CN 不在 SAN 中时补充",
			cert: &x509.Certificate{
				DNSNames: []string{"www.example.com"},
				Subject:  pkix.Name{CommonName: "example.com"},
			},
			want: []string{"www.example.com", "example.com"},
		},
		{
			name: "只有 CN，无 SAN",
			cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "standalone.example.com"},
			},
			want: []string{"standalone.example.com"},
		},
		{
			name: "IPv6 地址",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("::1")},
				Subject:     pkix.Name{CommonName: "::1"},
			},
			want: []string{"::1"},
		},
		{
			name: "多个 DNS + 多个 IP + CN 不重复",
			cert: &x509.Certificate{
				DNSNames:    []string{"a.com", "b.com"},
				IPAddresses: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")},
				Subject:     pkix.Name{CommonName: "c.com"},
			},
			want: []string{"a.com", "b.com", "1.1.1.1", "2.2.2.2", "c.com"},
		},
		{
			name: "DNS 中有重复项",
			cert: &x509.Certificate{
				DNSNames: []string{"dup.com", "dup.com", "other.com"},
				Subject:  pkix.Name{CommonName: "dup.com"},
			},
			want: []string{"dup.com", "other.com"},
		},
		{
			name: "CN 为空但有 SAN",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com"},
				Subject:  pkix.Name{CommonName: ""},
			},
			want: []string{"example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomainsFromParsedCert(tt.cert)

			// 排序后比较，避免顺序问题影响断言
			// 但 extractDomainsFromParsedCert 有确定的顺序：DNS → IP → CN
			// 所以直接比较顺序
			if !reflect.DeepEqual(got, tt.want) {
				// 额外检查是否仅顺序不同
				gotSorted := make([]string, len(got))
				copy(gotSorted, got)
				sort.Strings(gotSorted)

				wantSorted := make([]string, len(tt.want))
				copy(wantSorted, tt.want)
				sort.Strings(wantSorted)

				if reflect.DeepEqual(gotSorted, wantSorted) {
					t.Errorf("extractDomainsFromParsedCert() 顺序不同\n  got:  %v\n  want: %v", got, tt.want)
				} else {
					t.Errorf("extractDomainsFromParsedCert() = %v, 期望 %v", got, tt.want)
				}
			}
		})
	}
}
