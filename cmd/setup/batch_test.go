package setup

import (
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
)

// TestDeriveRenewPolicy 表驱动验证逐证书续签策略派生（deploy-spec §5.2）：
// SAN 含 IP 的证书强制 local + file；DNS 证书按命令行参数透传。
// 每条独立派生，混合批次下 IP 证书不影响 DNS 证书（同批不同证书各走本行断言）。
func TestDeriveRenewPolicy(t *testing.T) {
	tests := []struct {
		name           string
		domains        []string
		localKey       bool
		fileValidation bool
		wantLocal      bool
		wantFile       bool
	}{
		{"纯 IPv4 强制 local+file", []string{"192.0.2.1"}, false, false, true, true},
		{"纯 IPv6 强制 local+file", []string{"2001:db8::1"}, false, false, true, true},
		{"DNS+IP 混合仍强制 local+file", []string{"a.example.com", "192.0.2.1"}, false, false, true, true},
		{"IP 忽略 pull 意图强制 local+file", []string{"192.0.2.1"}, false, false, true, true},
		{"纯 DNS pull 透传", []string{"a.example.com"}, false, false, false, false},
		{"纯 DNS local+delegation 透传", []string{"a.example.com"}, true, false, true, false},
		{"纯 DNS local+file 透传", []string{"a.example.com"}, true, true, true, true},
		{"通配符 DNS pull 透传", []string{"*.example.com"}, false, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLocal, gotFile := deriveRenewPolicy(tt.domains, tt.localKey, tt.fileValidation)
			if gotLocal != tt.wantLocal || gotFile != tt.wantFile {
				t.Errorf("deriveRenewPolicy(%v, local=%v, file=%v) = (%v, %v), 期望 (%v, %v)",
					tt.domains, tt.localKey, tt.fileValidation, gotLocal, gotFile, tt.wantLocal, tt.wantFile)
			}
		})
	}
}

func TestBetterCandidate(t *testing.T) {
	tests := []struct {
		name string
		a, b siteCandidate
		want bool
	}{
		{
			name: "完全匹配优先于部分匹配",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 1, orderID: 1},
			b:    siteCandidate{matchType: config.MatchTypePartial, matchedCount: 3, orderID: 100},
			want: true,
		},
		{
			name: "部分匹配不优于完全匹配",
			a:    siteCandidate{matchType: config.MatchTypePartial, matchedCount: 5, orderID: 100},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 1, orderID: 1},
			want: false,
		},
		{
			name: "同级别匹配域名数多的优先",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 3, orderID: 1},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 1, orderID: 100},
			want: true,
		},
		{
			name: "同级别同数量OrderID大的优先",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 200},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 100},
			want: true,
		},
		{
			name: "同级别同数量OrderID小的不优先",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 50},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 100},
			want: false,
		},
		{
			name: "完全相同不优先",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 100},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 100},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := betterCandidate(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("betterCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}
