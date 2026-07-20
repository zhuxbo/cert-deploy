package config

import "testing"

// TestContainsIPDomain 验证 SAN 含 IP 判断（IPv4/IPv6/混合）
func TestContainsIPDomain(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		want    bool
	}{
		{"纯 DNS", []string{"a.example.com", "www.example.com"}, false},
		{"通配符 DNS", []string{"*.example.com"}, false},
		{"纯 IPv4", []string{"192.0.2.1"}, true},
		{"纯 IPv6", []string{"2001:db8::1"}, true},
		{"DNS+IPv4 混合", []string{"a.example.com", "192.0.2.1"}, true},
		{"空列表", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsIPDomain(tt.domains); got != tt.want {
				t.Errorf("ContainsIPDomain(%v) = %v, want %v", tt.domains, got, tt.want)
			}
		})
	}
}

// TestIsIllegalIPConfig 验证非法 IP 配置判断（deploy-spec §5.2）：
// IP 证书必须 local + file；IP+pull 或 IP+delegation 为非法；DNS 证书永不非法。
func TestIsIllegalIPConfig(t *testing.T) {
	tests := []struct {
		name       string
		domains    []string
		renewMode  string
		validation string
		global     string
		want       bool
	}{
		{"IP + 证书级 pull", []string{"192.0.2.1"}, RenewModePull, "", RenewModePull, true},
		{"IP + 全局 pull（证书级空）", []string{"192.0.2.1"}, "", "", RenewModePull, true},
		{"IP + local + delegation", []string{"192.0.2.1"}, RenewModeLocal, ValidationMethodDelegation, RenewModePull, true},
		{"IP + local + file 合法", []string{"192.0.2.1"}, RenewModeLocal, ValidationMethodFile, RenewModePull, false},
		{"IP + local + 空验证合法", []string{"192.0.2.1"}, RenewModeLocal, "", RenewModePull, false},
		{"IPv6 + pull 非法", []string{"2001:db8::1"}, RenewModePull, "", RenewModePull, true},
		{"DNS + pull 合法", []string{"a.example.com"}, RenewModePull, "", RenewModePull, false},
		{"DNS + local + delegation 合法", []string{"a.example.com"}, RenewModeLocal, ValidationMethodDelegation, RenewModePull, false},
		{"混合 DNS+IP + local + file 合法", []string{"a.example.com", "192.0.2.1"}, RenewModeLocal, ValidationMethodFile, RenewModePull, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &CertConfig{Domains: tt.domains, RenewMode: tt.renewMode, ValidationMethod: tt.validation}
			schedule := &ScheduleConfig{RenewMode: tt.global}
			if got := cert.IsIllegalIPConfig(schedule); got != tt.want {
				t.Errorf("IsIllegalIPConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
