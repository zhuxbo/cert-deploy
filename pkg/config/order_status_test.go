package config

import "testing"

// TestClassifyOrderStatus 服务端 12 个状态必须全部显式归类。
//
// 此前客户端只认 active / processing / pending / approving，其余 8 个落 default
// 一律当终态——unpaid（服务端会自动推进、孤儿单 60 分钟清理）与 cancelling
// （过渡态）因此被误判为需要人工，local 模式还会因 last_issue_state 非空
// 永远只走查询分支、再也走不到能触发服务端自愈的提交路径。
func TestClassifyOrderStatus(t *testing.T) {
	tests := []struct {
		status string
		want   OrderStatusClass
	}{
		{OrderStatusActive, OrderClassActive},

		{OrderStatusPending, OrderClassWaiting},
		{OrderStatusProcessing, OrderClassWaiting},
		{OrderStatusApproving, OrderClassWaiting},
		{OrderStatusUnpaid, OrderClassWaiting},
		{OrderStatusCancelling, OrderClassWaiting},

		{OrderStatusFailed, OrderClassTerminal},
		{OrderStatusCancelled, OrderClassTerminal},
		{OrderStatusRevoked, OrderClassTerminal},
		{OrderStatusExpired, OrderClassTerminal},

		{OrderStatusRenewed, OrderClassChainAnomaly},
		{OrderStatusReissued, OrderClassChainAnomaly},

		{"", OrderClassUnknown},
		{"verifying", OrderClassUnknown},
		{"ACTIVE", OrderClassUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			if got := ClassifyOrderStatus(tt.status); got != tt.want {
				t.Errorf("ClassifyOrderStatus(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

// TestClassifyOrderStatus_CoversServerEnum 覆盖服务端 certs.status 枚举全集，
// 防止服务端新增状态后客户端漏归类（未知状态必须落 Unknown 而非被漏掉）
func TestClassifyOrderStatus_CoversServerEnum(t *testing.T) {
	serverEnum := []string{
		"unpaid", "pending", "processing", "approving", "active", "failed",
		"cancelling", "cancelled", "revoked", "renewed", "reissued", "expired",
	}
	for _, status := range serverEnum {
		if ClassifyOrderStatus(status) == OrderClassUnknown {
			t.Errorf("服务端状态 %q 未被显式归类", status)
		}
	}
}

// TestOrderClassUnknownIsWaiting 未知状态的处置方向必须保守。
// 若当终态，服务端新增一个中间态就会把所有证书打进停机。
func TestOrderClassUnknownIsWaiting(t *testing.T) {
	if ClassifyOrderStatus("some_new_state") == OrderClassTerminal {
		t.Fatal("未知状态不得归为终态")
	}
}
