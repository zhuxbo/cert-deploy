// Package fetcher 负责从 API 获取证书
package fetcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// API 响应状态码
const (
	APICodeSuccess = 1 // API 成功响应码
)

// RetryConfig 重试配置
type RetryConfig struct {
	MaxRetries  int           // 最大重试次数
	InitialWait time.Duration // 初始等待时间
	MaxWait     time.Duration // 最大等待时间
	Multiplier  float64       // 退避乘数
}

// DefaultRetryConfig 默认重试配置（指数退避：1s, 2s, 4s）
var DefaultRetryConfig = RetryConfig{
	MaxRetries:  3,
	InitialWait: 1 * time.Second,
	MaxWait:     4 * time.Second,
	Multiplier:  2.0,
}

type FileChallenge struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// CertData 证书数据
type CertData struct {
	OrderID          int            `json:"order_id"`
	Status           string         `json:"status"`
	Domains          string         `json:"domains"`
	Cert             string         `json:"certificate"`
	IntermediateCert string         `json:"ca_certificate"`
	PrivateKey       string         `json:"private_key"`
	IssuedAt         string         `json:"issued_at"`
	ExpiresAt        string         `json:"expires_at"`
	File             *FileChallenge `json:"file,omitempty"`
}

func validateCertDataSizes(cert *CertData) error {
	if len(cert.Cert)+len(cert.IntermediateCert) > config.MaxCertFileSize {
		return fmt.Errorf("certificate chain exceeds %d bytes", config.MaxCertFileSize)
	}
	if len(cert.PrivateKey) > config.MaxPrivateKeySize {
		return fmt.Errorf("private key exceeds %d bytes", config.MaxPrivateKeySize)
	}
	return nil
}

func validateCertDataList(certs []CertData) error {
	for i := range certs {
		if err := validateCertDataSizes(&certs[i]); err != nil {
			return fmt.Errorf("certificate order %d: %w", certs[i].OrderID, err)
		}
	}
	return nil
}

// APIResponse API 响应结构
type APIResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"msg"` // API 使用 msg 字段
	Data    json.RawMessage `json:"data"`
	// Errors 错误响应的附加信息（deploy-spec §2.2）；仅 code != 1 时有值
	Errors APIErrors `json:"errors"`
}

// APIErrors 错误响应的 errors 字段（deploy-spec §2.2）。
// HTTP 状态码恒为 200、业务成败只由 code 区分，因此 error_code 是客户端
// 唯一可靠的失败分类依据——没有它就只能把「订单不存在」这类确定性失败
// 当成网络错误无限重试。
type APIErrors struct {
	// ErrorCode 机器可读的失败标识，取值见 deploy-spec §2.2；缺失表示未分类
	ErrorCode string `json:"error_code"`
	// RetryAfter 限流时的窗口剩余秒数（仅 error_code=rate_limited 时有值）
	RetryAfter int `json:"retry_after"`
}

// 服务端下发的 error_code 取值（deploy-spec §2.2）。
// 取值一旦发布不得改动，只允许新增；未列出的取值按未分类处理。
const (
	ErrorCodeRateLimited     = "rate_limited"     // 触发限流，带 retry_after
	ErrorCodeTokenMissing    = "token_missing"    // 请求未携带 token
	ErrorCodeTokenInvalid    = "token_invalid"    // token 不存在或已失效
	ErrorCodeTokenDisabled   = "token_disabled"   // token 被禁用
	ErrorCodeAccountDisabled = "account_disabled" // token 所属账号被禁用
	ErrorCodeIPNotAllowed    = "ip_not_allowed"   // 来源 IP 不在白名单
	ErrorCodeOrderNotFound   = "order_not_found"  // 订单不存在或不可见
	ErrorCodeCertNotFound    = "cert_not_found"   // 订单存在但无可用证书
	ErrorCodeInvalidOrder    = "invalid_order"    // order 参数缺失或形态非法
)

// apiError 依据 error_code 构造错误：带 error_code 一律是服务端明确拒绝
// （确定性失败，调用方应停止本轮而非重试），无 error_code 沿用网络错误语义。
//
// 不按取值再分档：spec §2.2 表格中每一项的「客户端应对」都是停止本轮，
// 逐值分支只会引入无谓的分类漂移。retry_after 由调用方按需读取。
func (r *APIResponse) apiError(msg string) error {
	if r.Errors.ErrorCode == "" {
		return errors.NewNetworkError(msg, nil)
	}
	return errors.NewBusinessErrorWithCode(msg, r.Errors.ErrorCode, r.Errors.RetryAfter)
}

// ParseData 解析 Data 字段，支持单个对象或数组格式
func (r *APIResponse) ParseData() (*CertData, error) {
	if len(r.Data) == 0 {
		return nil, fmt.Errorf("empty data field")
	}
	// 尝试解析为单个对象
	var single CertData
	if err := json.Unmarshal(r.Data, &single); err == nil {
		if err := validateCertDataSizes(&single); err != nil {
			return nil, err
		}
		return &single, nil
	}
	// 尝试解析为数组
	var list []CertData
	if err := json.Unmarshal(r.Data, &list); err != nil {
		return nil, fmt.Errorf("failed to parse data: not object or array")
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("empty data array")
	}
	if err := validateCertDataSizes(&list[0]); err != nil {
		return nil, err
	}
	return &list[0], nil
}

// QueryResponse 查询接口的 data 字段结构（deploy-spec §2.3，无分页）
type QueryResponse struct {
	RenewBeforeDays int        `json:"renew_before_days"`
	Data            []CertData `json:"data"`
}

// ParseQueryData 解析查询响应
// 标准格式: {"renew_before_days": 14, "data": [...]}；服务端不分页，单次取完。
// 兼容单对象与裸数组格式: 包装成切片返回
// 返回: (certs, renewBeforeDays, error)
func (r *APIResponse) ParseQueryData() ([]CertData, int, error) {
	if len(r.Data) == 0 {
		return nil, 0, fmt.Errorf("empty data field")
	}
	// 尝试解析为标准查询响应
	var listResp QueryResponse
	if err := json.Unmarshal(r.Data, &listResp); err == nil && listResp.Data != nil {
		if err := validateCertDataList(listResp.Data); err != nil {
			return nil, 0, err
		}
		return listResp.Data, listResp.RenewBeforeDays, nil
	}
	// 兼容：尝试解析为单个对象
	var single CertData
	if err := json.Unmarshal(r.Data, &single); err == nil && single.OrderID != 0 {
		if err := validateCertDataSizes(&single); err != nil {
			return nil, 0, err
		}
		return []CertData{single}, 0, nil
	}
	// 兼容：尝试解析为数组
	var list []CertData
	if err := json.Unmarshal(r.Data, &list); err == nil {
		if err := validateCertDataList(list); err != nil {
			return nil, 0, err
		}
		return list, 0, nil
	}
	return nil, 0, fmt.Errorf("failed to parse query data")
}

// UpdateRequest 更新/续费证书请求

type UpdateRequest struct {
	OrderID          int    `json:"order_id,omitempty"`
	CSR              string `json:"csr,omitempty"`
	Domains          string `json:"domains,omitempty"`
	ValidationMethod string `json:"validation_method,omitempty"`
}

// CallbackRequest 部署回调请求
type CallbackRequest struct {
	OrderID    int    `json:"order_id"`
	Status     string `json:"status"` // success, failure
	DeployedAt string `json:"deployed_at"`
	// Message 失败原因摘要，可选，仅 status=failure 时填充；
	// 客户端已脱敏并按 rune 截断 ≤256，success 不携带（omitempty）
	Message string `json:"message,omitempty"`
}

// UpdateResponse update 接口的 data 字段结构
// 服务端格式：{"order_id": ..., "status": ..., ..., "renew_before_days": 14}
type UpdateResponse struct {
	CertData
	RenewBeforeDays int `json:"renew_before_days"`
}

// CallbackResponse 回调响应。
// data 用 RawMessage 承接：服务端在不同分支下可能返回对象、null 或空数组，
// 直接声明为结构体时非对象形状会让整条响应解析失败——回调其实已被受理，
// 却被记成失败并丢掉 renew_before_days。形状不符时忽略 data，不影响成功判定。
type CallbackResponse struct {
	Code            int             `json:"code"`
	Message         string          `json:"msg"`
	RenewBeforeDays int             `json:"renew_before_days"`
	Data            json.RawMessage `json:"data"`
	Errors          APIErrors       `json:"errors"`
}

// renewBeforeDaysFromData 从 data 对象中提取 renew_before_days，形状不符或缺失返回 0
func renewBeforeDaysFromData(data json.RawMessage) int {
	if len(data) == 0 {
		return 0
	}
	var payload struct {
		RenewBeforeDays int `json:"renew_before_days"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return 0
	}
	return payload.RenewBeforeDays
}

// 单次请求超时（deploy-spec §11）：GET 30s、POST 60s。
// 不再使用 http.Client.Timeout——它是覆盖整个请求的单一上限，
// 无法按方法区分，且会把 POST 一并压到 GET 的时长上。
const (
	defaultGetTimeout  = 30 * time.Second
	defaultPostTimeout = 60 * time.Second
)

// Fetcher 证书获取器
type Fetcher struct {
	client      *http.Client
	getTimeout  time.Duration
	postTimeout time.Duration
	retryConfig RetryConfig
}

// New 创建新的 Fetcher
// - 强制 TLS >= 1.2
// - 连接池复用与 HTTP/2
// - 合理的连接/空闲超时
// - DNS Rebinding 防护：在 TCP 连接时二次校验目标 IP
//
// 超时统一在 doAttempt 内按方法套用（含响应体读取），client 本身不设 Timeout；
// 新增的请求路径必须走 doWithRetry，直连 f.client.Do 将完全没有超时保护。
func New() *Fetcher {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         makeSSRFSafeDialContext(dialer),
		ForceAttemptHTTP2:   true,
	}
	return &Fetcher{
		client:      &http.Client{Transport: transport},
		getTimeout:  defaultGetTimeout,
		postTimeout: defaultPostTimeout,
		retryConfig: DefaultRetryConfig,
	}
}

// makeSSRFSafeDialContext 创建带 SSRF 防护的 DialContext
// 在 TCP 连接时二次校验目标 IP，防止 DNS Rebinding 攻击
func makeSSRFSafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %s: %w", addr, err)
		}

		// 检查是否为本地地址（允许 HTTP）
		isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if isLocal {
			return dialer.DialContext(ctx, network, addr)
		}

		// 手动解析 DNS 并校验每个 IP
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}

		// 筛选安全的 IP 并尝试连接
		var lastErr error
		for _, ip := range ips {
			if err := validateIPForSSRF(ip); err != nil {
				lastErr = err
				continue
			}

			// 使用已验证的 IP 直接连接，绕过 DNS 重新解析
			targetAddr := net.JoinHostPort(ip.String(), port)
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err != nil {
				lastErr = err
				continue
			}
			return conn, nil
		}

		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no valid IP address found for %s", host)
	}
}

// validateIPForSSRF 校验 IP 是否安全（非内网、非回环、非云元数据）
func validateIPForSSRF(ip net.IP) error {
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified address not allowed: %s", ip)
	}
	if ip.IsLoopback() {
		return fmt.Errorf("loopback address not allowed: %s", ip)
	}
	if ip.IsPrivate() {
		return fmt.Errorf("private IP not allowed: %s", ip)
	}
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("link-local address not allowed: %s", ip)
	}
	if ip.String() == "169.254.169.254" {
		return fmt.Errorf("cloud metadata endpoint not allowed")
	}
	return nil
}

// NewWithRetry 创建带自定义重试配置的 Fetcher
func NewWithRetry(retryConfig RetryConfig) *Fetcher {
	f := New()
	f.retryConfig = retryConfig
	return f
}

// defaultMaxResponseSize API 响应体最大大小（512KB 足够承载证书链）
const defaultMaxResponseSize = 512 * 1024

// batchMaxResponseSize 批量查询响应体最大大小（5MB，100 条证书约 500-800KB）
const batchMaxResponseSize = 5 * 1024 * 1024

// isRetryable 判断错误是否可重试
func isRetryable(err error, statusCode int) bool {
	// 网络错误可重试，但 SSRF 防护拒绝的请求除外
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not allowed") || strings.Contains(msg, "cloud metadata endpoint") {
			return false
		}
		return true
	}
	// 5xx 服务器错误可重试
	if statusCode >= 500 && statusCode < 600 {
		return true
	}
	// 429 Too Many Requests 可重试
	if statusCode == http.StatusTooManyRequests {
		return true
	}
	return false
}

// errorBodyLimit 非 200 响应体的读取上限。
// 这类响应体只用于拼错误信息：批量查询的 5MB 上限 × 最多 4 次尝试会让 lastErr
// 本身变成 MB 级字符串，一路流进日志与回调 message 的脱敏正则。
const errorBodyLimit = 1024

// attemptTimeout 返回单次尝试的超时（deploy-spec §11）
func (f *Fetcher) attemptTimeout(method string) time.Duration {
	if method == http.MethodPost {
		return f.postTimeout
	}
	return f.getTimeout
}

// doAttempt 执行单次请求，并在同一超时作用域内读完响应体。
// per-request 超时覆盖连接、首字节与响应体读取全过程，与父 ctx deadline 取更早者
// （context.WithTimeout 语义）。返回时响应体已关闭，调用方不再持有 *http.Response。
func (f *Fetcher) doAttempt(req *http.Request, maxBodySize int64) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(req.Context(), f.attemptTimeout(req.Method))
	defer cancel()

	resp, err := f.client.Do(req.WithContext(ctx))
	if err != nil {
		// Go http.Client.Do 规范保证 err != nil 时 resp == nil
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	limit := maxBodySize
	if resp.StatusCode != http.StatusOK {
		limit = errorBodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// doWithRetry 带重试的 HTTP 请求，返回状态码与已读取的响应体。
// 响应体在 per-request 超时到期前读完（否则 deadline 会在调用方读 body 时才触发），
// 且由本函数负责关闭——调用方不再持有 *http.Response。
func (f *Fetcher) doWithRetry(ctx context.Context, newRequest func() (*http.Request, error), maxBodySize int64) (int, []byte, error) {
	var lastErr error

	for attempt := 0; attempt <= f.retryConfig.MaxRetries; attempt++ {
		req, err := newRequest()
		if err != nil {
			return 0, nil, err
		}

		statusCode, body, err := f.doAttempt(req, maxBodySize)

		// 请求成功且不需要重试，返回状态码与响应体
		if err == nil && !isRetryable(nil, statusCode) {
			return statusCode, body, nil
		}

		if err != nil {
			// 网络错误或响应体读取中断：读取失败同样按可重试处理，
			// 否则一次连接中断就会变成 JSON 解析失败并终止整条链路
			lastErr = err
			statusCode = 0
		} else if len(body) > 0 {
			// HTTP 错误但需要重试（5xx、429 等）
			lastErr = fmt.Errorf("HTTP %d: %s", statusCode, string(body))
		} else {
			lastErr = fmt.Errorf("HTTP %d", statusCode)
		}

		// 最后一次尝试不等待
		if attempt == f.retryConfig.MaxRetries {
			break
		}

		// 检查是否可重试
		if !isRetryable(err, statusCode) {
			break
		}

		// 指数退避 + 抖动：InitialWait * Multiplier^attempt * (0.75~1.25)
		multiplier := f.retryConfig.Multiplier
		if multiplier < 1.0 {
			multiplier = 2.0
		}
		wait := float64(f.retryConfig.InitialWait)
		for i := 0; i < attempt; i++ {
			wait *= multiplier
		}
		// ±25% 随机抖动，防止多实例同时重试的惊群效应
		jitter := 0.75 + rand.Float64()*0.5 // [0.75, 1.25)
		sleepTime := time.Duration(wait * jitter)
		if sleepTime > f.retryConfig.MaxWait {
			sleepTime = f.retryConfig.MaxWait
		}

		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(sleepTime):
		}
	}

	return 0, nil, lastErr
}

// doAPICallQuery 查询接口的 API 调用流程，返回证书列表和 renewBeforeDays
func (f *Fetcher) doAPICallQuery(ctx context.Context, newRequest func() (*http.Request, error), errMsg string) ([]CertData, int, error) {
	statusCode, body, err := f.doWithRetry(ctx, newRequest, batchMaxResponseSize)
	if err != nil {
		return nil, 0, errors.NewNetworkError(errMsg, err)
	}
	if statusCode != http.StatusOK {
		return nil, 0, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", statusCode), nil)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, 0, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		// 带 error_code 时归为业务拒绝：订单不存在 / token 失效 / 形态非法都是
		// 确定结果，此前一律当网络错误会让调用方每日重试到证书过期
		return nil, 0, apiResp.apiError(fmt.Sprintf("API error: %s", apiResp.Message))
	}
	return apiResp.ParseQueryData()
}

// mustValidURL 校验 URL 是否有效。
// 仅 localhost/127.0.0.1 允许 HTTP，其他必须使用 HTTPS。
// 同时检查 SSRF 风险，阻止访问内网 IP 和云元数据地址。
// 委托给 validator.ValidateAPIURL 实现，避免代码重复。
func mustValidURL(apiURL string) error {
	return validator.ValidateAPIURL(apiURL)
}

// Callback 调用回调接口通知部署结果
// 返回：(renewBeforeDays, error)
func (f *Fetcher) Callback(ctx context.Context, callbackURL, token string, callbackReq *CallbackRequest) (int, error) {
	if err := mustValidURL(callbackURL); err != nil {
		return 0, errors.NewNetworkError("invalid callback URL", err)
	}
	bodyData, err := json.Marshal(callbackReq)
	if err != nil {
		return 0, errors.NewNetworkError("failed to marshal callback request", err)
	}

	newRequest := func() (*http.Request, error) {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, callbackURL, bytes.NewReader(bodyData))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+token)
		return httpReq, nil
	}

	const maxResponseSize = 64 * 1024 // 64KB 足够回调响应
	statusCode, body, err := f.doWithRetry(ctx, newRequest, maxResponseSize)
	if err != nil {
		return 0, errors.NewNetworkError("failed to send callback", err)
	}
	if statusCode != http.StatusOK {
		return 0, errors.NewNetworkError(fmt.Sprintf("callback returned unexpected status: %d", statusCode), nil)
	}
	var callbackResp CallbackResponse
	if err := json.Unmarshal(body, &callbackResp); err != nil {
		return 0, errors.NewNetworkError("failed to parse callback response", err)
	}
	if callbackResp.Code != APICodeSuccess {
		msg := fmt.Sprintf("callback failed: %s", callbackResp.Message)
		if callbackResp.Errors.ErrorCode != "" {
			return 0, errors.NewBusinessErrorWithCode(msg, callbackResp.Errors.ErrorCode, callbackResp.Errors.RetryAfter)
		}
		return 0, errors.NewNetworkError(msg, nil)
	}
	renewBeforeDays := renewBeforeDaysFromData(callbackResp.Data)
	if renewBeforeDays == 0 {
		// 兼容旧服务端把 renew_before_days 放在顶层的响应。
		renewBeforeDays = callbackResp.RenewBeforeDays
	}
	return renewBeforeDays, nil
}

// buildAPIURL 构建 API URL
// 如果 baseURL 已包含路径（如 /api/deploy），直接使用
// 如果只有 host，自动拼接 /api/deploy
func buildAPIURL(baseURL, path string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL + path
	}
	// 如果已有路径，直接拼接
	if u.Path != "" && u.Path != "/" {
		return baseURL + path
	}
	// 否则使用默认的 /api/deploy 路径
	return baseURL + "/api/deploy" + path
}

// Update 更新/续费证书（新 API：POST {baseURL}/api/deploy）
// 返回：(certData, renewBeforeDays, error)
func (f *Fetcher) Update(ctx context.Context, baseURL, token string, orderID int, csr, domains, method string) (*CertData, int, error) {
	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	reqBody := UpdateRequest{
		OrderID:          orderID,
		CSR:              csr,
		Domains:          domains,
		ValidationMethod: method,
	}
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, errors.NewNetworkError("failed to marshal request", err)
	}

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	statusCode, body, err := f.doWithRetry(ctx, newRequest, defaultMaxResponseSize)
	if err != nil {
		return nil, 0, errors.NewNetworkError("failed to update certificate", err)
	}
	if statusCode != http.StatusOK {
		return nil, 0, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", statusCode), nil)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, 0, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		// 服务端已成功响应但明确拒绝提交（校验失败、订单状态不允许等）：
		// 属确定结果而非传输失败，调用方据此清理在途 pending 后停止（spec 2.6）。
		// 无 error_code 时同样保持业务拒绝语义——POST 的拒绝判定先于 error_code 存在，
		// 不能因服务端未下发标识而退回可重试。
		if apiResp.Errors.ErrorCode != "" {
			return nil, 0, apiResp.apiError(fmt.Sprintf("API error: %s", apiResp.Message))
		}
		return nil, 0, errors.NewBusinessError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	// update 响应 data 字段为单条，同层包含 renew_before_days
	var updateResp UpdateResponse
	if err := json.Unmarshal(apiResp.Data, &updateResp); err != nil {
		// 兼容旧格式（data 为数组）
		certData, parseErr := apiResp.ParseData()
		if parseErr != nil {
			return nil, 0, errors.NewNetworkError("failed to parse update response", err)
		}
		return certData, 0, nil
	}
	if err := validateCertDataSizes(&updateResp.CertData); err != nil {
		return nil, 0, errors.NewNetworkError("invalid update response", err)
	}
	return &updateResp.CertData, updateResp.RenewBeforeDays, nil
}

// CallbackNew 调用新的回调接口（POST {baseURL}/api/deploy/callback）
// 返回：(renewBeforeDays, error)
func (f *Fetcher) CallbackNew(ctx context.Context, baseURL, token string, callbackReq *CallbackRequest) (int, error) {
	callbackURL := buildAPIURL(baseURL, "/callback")
	return f.Callback(ctx, callbackURL, token, callbackReq)
}

// QueryOrder 按 OrderID 查询订单状态
// GET {baseURL}/api/deploy?order=xxx
// 取第一条结果
// 返回: (certData, renewBeforeDays, error)
func (f *Fetcher) QueryOrder(ctx context.Context, baseURL, token string, orderID int) (*CertData, int, error) {
	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	// 构建带 order 参数的 URL
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}
	q := u.Query()
	q.Set("order", fmt.Sprintf("%d", orderID))
	u.RawQuery = q.Encode()
	fullURL := u.String()

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	certs, renewBeforeDays, err := f.doAPICallQuery(ctx, newRequest, "failed to query order")
	if err != nil {
		return nil, 0, err
	}
	if len(certs) == 0 {
		return nil, 0, errors.NewNetworkError("order not found", nil)
	}
	return &certs[0], renewBeforeDays, nil
}

// ToggleAutoReissueRequest toggleAutoReissue 请求体
type ToggleAutoReissueRequest struct {
	OrderID     int  `json:"order_id"`
	AutoReissue bool `json:"auto_reissue"`
}

// ToggleAutoReissue 通知服务端是否自动续签
// POST {baseURL}/api/deploy/auto-reissue
// 此为非关键路径，调用失败返回 error 由调用方决定是否记录日志
func (f *Fetcher) ToggleAutoReissue(ctx context.Context, baseURL, token string, orderID int, autoReissue bool) (int, error) {
	apiURL := buildAPIURL(baseURL, "/auto-reissue")
	if err := mustValidURL(apiURL); err != nil {
		return 0, errors.NewNetworkError("invalid API URL", err)
	}

	reqBody := ToggleAutoReissueRequest{
		OrderID:     orderID,
		AutoReissue: autoReissue,
	}
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return 0, errors.NewNetworkError("failed to marshal request", err)
	}

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	statusCode, body, err := f.doWithRetry(ctx, newRequest, defaultMaxResponseSize)
	if err != nil {
		return 0, errors.NewNetworkError("failed to toggle auto reissue", err)
	}
	if statusCode != http.StatusOK {
		return 0, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", statusCode), nil)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return 0, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return 0, apiResp.apiError(fmt.Sprintf("API error: %s", apiResp.Message))
	}
	var data struct {
		RenewBeforeDays int `json:"renew_before_days"`
	}
	if len(apiResp.Data) > 0 {
		if err := json.Unmarshal(apiResp.Data, &data); err != nil {
			return 0, errors.NewNetworkError("failed to parse auto reissue response data", err)
		}
	}
	return data.RenewBeforeDays, nil
}

// MaxBatchQueryItems 单次批量查询的订单 ID 项数上限（deploy-spec §2.3）
const MaxBatchQueryItems = 100

// batchQueryPattern 批量查询形态（deploy-spec §2.3）：仅订单 ID，单个或逗号分隔多个。
// 与服务端校验一致；本地先拒绝可以少发一次注定失败的请求。
var batchQueryPattern = regexp.MustCompile(`^\d+(,\d+)*$`)

// QueryBatch 批量查询证书（单次请求，无分页）
// GET {baseURL}/api/deploy?order={id1,id2,...}
// query 必填且只接受订单 ID（单个或英文逗号分隔，上限 MaxBatchQueryItems）。
// 不存在的 ID 被服务端静默跳过，全部未命中返回空切片，由调用方决定语义。
// 返回: (certs, renewBeforeDays, error)
//
// 协议无分页（不发也不认 page / page_size / total），单次取完即止：
// 翻页循环的终止只依赖服务端自报的计数与非空页，一旦失真即无限翻页且累积内存无界。
func (f *Fetcher) QueryBatch(ctx context.Context, baseURL, token, query string) ([]CertData, int, error) {
	if !batchQueryPattern.MatchString(query) {
		return nil, 0, errors.NewBusinessError(
			fmt.Sprintf("批量查询只接受订单 ID（纯数字，英文逗号分隔）: %q", query), nil)
	}
	if parts := strings.Split(query, ","); len(parts) > MaxBatchQueryItems {
		return nil, 0, errors.NewBusinessError(
			fmt.Sprintf("批量查询超过上限: %d（最大 %d）", len(parts), MaxBatchQueryItems), nil)
	}

	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	q := u.Query()
	q.Set("order", query)
	u.RawQuery = q.Encode()
	fullURL := u.String()

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	return f.doAPICallQuery(ctx, newRequest, "failed to batch query")
}
