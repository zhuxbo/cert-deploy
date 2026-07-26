package fetcher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
)

// errorCodeServer 返回固定 code=0 响应的服务端；errorsField 为 errors 字段的原始 JSON（空则不带该字段）
func errorCodeServer(t *testing.T, errorsField string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := `{"code":0,"msg":"boom"`
		if errorsField != "" {
			body += `,"errors":` + errorsField
		}
		body += `}`
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestQueryOrder_ErrorCodeClassifiesAsBusiness 带 error_code 的失败必须归为业务拒绝。
//
// HTTP 状态码恒为 200（deploy-spec §2.2），此前一律包成 NetworkError——「订单不存在」
// 这类确定性失败因此被当成传输故障，由调用方每日重试到证书过期。
func TestQueryOrder_ErrorCodeClassifiesAsBusiness(t *testing.T) {
	tests := []struct {
		name       string
		errorsJSON string
		wantCode   string
		wantRetry  int
	}{
		{"订单不存在", `{"error_code":"order_not_found"}`, ErrorCodeOrderNotFound, 0},
		{"token 被禁用", `{"error_code":"token_disabled"}`, ErrorCodeTokenDisabled, 0},
		{"限流带 retry_after", `{"error_code":"rate_limited","retry_after":42}`, ErrorCodeRateLimited, 42},
		{"order 形态非法", `{"error_code":"invalid_order"}`, ErrorCodeInvalidOrder, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := errorCodeServer(t, tt.errorsJSON)
			f := NewWithRetry(RetryConfig{MaxRetries: 0})

			_, _, err := f.QueryOrder(context.Background(), server.URL, "token", 12345)
			if err == nil {
				t.Fatal("QueryOrder() error = nil, want failure")
			}
			if !sslerrors.IsBusinessError(err) {
				t.Errorf("IsBusinessError() = false, want true（带 error_code 必须是确定性失败）")
			}
			if got := sslerrors.ErrorCodeOf(err); got != tt.wantCode {
				t.Errorf("ErrorCodeOf() = %q, want %q", got, tt.wantCode)
			}
			if got := sslerrors.RetryAfterOf(err); got != tt.wantRetry {
				t.Errorf("RetryAfterOf() = %d, want %d", got, tt.wantRetry)
			}
			// error_code 必须进入错误文本，否则运维无从判断为何停止
			if !strings.Contains(err.Error(), tt.wantCode) {
				t.Errorf("error text %q should contain error_code %q", err.Error(), tt.wantCode)
			}
		})
	}
}

// TestQueryOrder_NoErrorCodeStaysNetworkError 无 error_code 时沿用既有重试策略（spec §2.2）
func TestQueryOrder_NoErrorCodeStaysNetworkError(t *testing.T) {
	server := errorCodeServer(t, "")
	f := NewWithRetry(RetryConfig{MaxRetries: 0})

	_, _, err := f.QueryOrder(context.Background(), server.URL, "token", 12345)
	if err == nil {
		t.Fatal("QueryOrder() error = nil, want failure")
	}
	if sslerrors.IsBusinessError(err) {
		t.Error("IsBusinessError() = true, want false（未分类响应不得升级为确定性失败）")
	}
	if got := sslerrors.ErrorCodeOf(err); got != "" {
		t.Errorf("ErrorCodeOf() = %q, want empty", got)
	}
}

// TestUpdate_KeepsBusinessSemanticsWithoutErrorCode POST 的拒绝判定先于 error_code 存在，
// 服务端未下发标识时不得退回可重试（spec §2.6）
func TestUpdate_KeepsBusinessSemanticsWithoutErrorCode(t *testing.T) {
	server := errorCodeServer(t, "")
	f := NewWithRetry(RetryConfig{MaxRetries: 0})

	_, _, err := f.Update(context.Background(), server.URL, "token", 12345, "csr", "", "")
	if err == nil {
		t.Fatal("Update() error = nil, want failure")
	}
	if !sslerrors.IsBusinessError(err) {
		t.Error("IsBusinessError() = false, want true（POST 拒绝恒为业务错误）")
	}
}

// TestCallback_ErrorCodeClassifiesAsBusiness 回调路径同样按 error_code 分类
func TestCallback_ErrorCodeClassifiesAsBusiness(t *testing.T) {
	server := errorCodeServer(t, `{"error_code":"order_not_found"}`)
	f := NewWithRetry(RetryConfig{MaxRetries: 0})

	_, err := f.Callback(context.Background(), server.URL, "token", &CallbackRequest{
		OrderID: 12345,
		Status:  "success",
	})
	if err == nil {
		t.Fatal("Callback() error = nil, want failure")
	}
	if !sslerrors.IsBusinessError(err) {
		t.Error("IsBusinessError() = false, want true")
	}
	if got := sslerrors.ErrorCodeOf(err); got != ErrorCodeOrderNotFound {
		t.Errorf("ErrorCodeOf() = %q, want %q", got, ErrorCodeOrderNotFound)
	}
}
