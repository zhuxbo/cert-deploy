// sslctl status 停机/阻断状态展示测试（P3-4）
package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
)

// TestPrintCertHaltState 这些状态此前只出现在日志里，`status` 看上去一切正常，
// 人工排查无从下手。
func TestPrintCertHaltState(t *testing.T) {
	tests := []struct {
		name     string
		meta     config.CertMetadata
		want     []string
		wantNone bool
	}{
		{
			name: "零绑定阻断",
			meta: config.CertMetadata{NoBindingBlockedAt: time.Now().Add(-2 * time.Hour)},
			want: []string{"阻断", "无启用绑定", "重新 setup"},
		},
		{
			name: "触顶停机含阶段",
			meta: config.CertMetadata{LastIssueState: config.IssueStateCapped, CappedPhase: "deploy"},
			want: []string{"停机", "尝试次数上限", "deploy"},
		},
		{
			name: "触顶停机缺阶段时给占位",
			meta: config.CertMetadata{LastIssueState: config.IssueStateCapped},
			want: []string{"停机", "未知阶段"},
		},
		{
			name: "陈旧绑定",
			meta: config.CertMetadata{
				StaleBindings: []string{"a.example.com", "b.example.com"},
				StaleSince:    time.Now().Add(-30 * 24 * time.Hour),
			},
			want: []string{"陈旧", "a.example.com", "b.example.com", "旧证书"},
		},
		{
			name: "陈旧绑定缺起始时间时给占位",
			meta: config.CertMetadata{StaleBindings: []string{"a.example.com"}},
			want: []string{"陈旧", "时间未知"},
		},
		{
			name: "待重试站点带进度",
			meta: config.CertMetadata{
				FailedBindings:    []string{"c.example.com"},
				RetryAttemptCount: 3,
			},
			want: []string{"重试中", "c.example.com", "3/10"},
		},
		{
			name:     "一切正常时不输出任何行",
			meta:     config.CertMetadata{CertExpiresAt: time.Now().Add(60 * 24 * time.Hour)},
			wantNone: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printCertHaltState(&buf, &config.CertConfig{CertName: "cert", Metadata: tt.meta})
			got := buf.String()

			if tt.wantNone {
				if got != "" {
					t.Errorf("期望无输出，实际:\n%s", got)
				}
				return
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("输出缺少 %q，实际:\n%s", want, got)
				}
			}
		})
	}
}
