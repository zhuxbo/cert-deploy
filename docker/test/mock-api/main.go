// 模拟证书 API 服务器
// 用于测试证书部署流程
// 支持场景切换、请求记录、多端点模拟
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ==============================================================================
// 数据结构
// ==============================================================================

// FileChallenge 文件验证
type FileChallenge struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// CertData 证书数据（与 fetcher.CertData 字段名匹配）
type CertData struct {
	OrderID          int            `json:"order_id"`
	Status           string         `json:"status"`
	Domains          string         `json:"domains,omitempty"`
	Cert             string         `json:"certificate"`
	IntermediateCert string         `json:"ca_certificate"`
	PrivateKey       string         `json:"private_key"`
	IssuedAt         string         `json:"issued_at,omitempty"`
	ExpiresAt        string         `json:"expires_at"`
	File             *FileChallenge `json:"file,omitempty"`
}

// OrderData 订单数据
type OrderData struct {
	OrderID    int      `json:"order_id"`
	Status     string   `json:"status"`
	Domains    string   `json:"domains"`
	CommonName string   `json:"common_name"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  string   `json:"expires_at"`
	RenewMode  string   `json:"renew_mode,omitempty"`
	CertData   CertData `json:"-"` // 内部使用
}

// APIResponse 统一响应格式
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
	// Errors 失败分类（deploy-spec §2.2）。真实服务端的业务失败一律 HTTP 200 + code=0，
	// 分类只由 errors.error_code 提供——mock 必须照同样形态返回，否则 e2e 验证的是
	// 一条生产环境不存在的路径（客户端对 HTTP 4xx 与对 code=0+error_code 的处置完全不同）。
	Errors *APIErrors `json:"errors,omitempty"`
}

// APIErrors errors 字段的第一种形态：参与分类的 {error_code, retry_after?}
type APIErrors struct {
	ErrorCode  string `json:"error_code"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// PaginatedData 查询响应数据（fetcher.QueryResponse 消费 data/renew_before_days，
// 其余分页字段作为多余字段被忽略，保留以模拟旧服务端形态）
type PaginatedData struct {
	Total           int         `json:"total"`
	CurrentPage     int         `json:"page"`
	PageSize        int         `json:"page_size"`
	RenewBeforeDays int         `json:"renew_before_days"`
	Data            interface{} `json:"data"`
}

// CallbackRequest 部署回调请求
type CallbackRequest struct {
	OrderID    int    `json:"order_id"`
	Status     string `json:"status"`
	DeployedAt string `json:"deployed_at"`
	Message    string `json:"message,omitempty"`
}

// RenewRequest 续签请求
type RenewRequest struct {
	OrderID          int    `json:"order_id"`
	CSR              string `json:"csr,omitempty"`
	Domains          string `json:"domains,omitempty"`
	ValidationMethod string `json:"validation_method,omitempty"`
}

type AutoReissueRequest struct {
	OrderID     int  `json:"order_id"`
	AutoReissue bool `json:"auto_reissue"`
}

// RequestLog 请求日志
type RequestLog struct {
	Time      string              `json:"time"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Headers   map[string][]string `json:"headers"`
	Query     map[string][]string `json:"query"`
	Body      string              `json:"body,omitempty"`
	RemoteIP  string              `json:"remote_ip"`
	UserAgent string              `json:"user_agent"`
}

// ==============================================================================
// releases.json 结构（与 pkg/upgrade/release.go 匹配）
// ==============================================================================

// VersionInfo 版本详细信息
type VersionInfo struct {
	Version    string            `json:"version"`
	ReleasedAt string            `json:"released_at,omitempty"`
	Checksums  map[string]string `json:"checksums"`
	Signatures map[string]string `json:"signatures,omitempty"`
}

// ChannelInfo 通道版本信息
type ChannelInfo struct {
	Latest   string        `json:"latest"`
	Versions []VersionInfo `json:"versions"`
}

// ReleaseIndex 发布索引
type ReleaseIndex map[string]*ChannelInfo

// ==============================================================================
// 全局状态
// ==============================================================================

var (
	certFile   string
	keyFile    string
	chainFile  string
	commonName string

	// 缓存的证书内容（启动时生成/加载）
	cachedCert  string // 服务器证书 PEM
	cachedKey   string // 服务器私钥 PEM
	cachedChain string // CA（中间）证书 PEM

	// 场景模式
	currentScenario = "active"
	scenarioMutex   sync.RWMutex

	// 订单存储
	orders      = make(map[int]*OrderData)
	ordersMutex sync.RWMutex
	nextOrderID = 1006

	// 请求日志
	requestLogs      []RequestLog
	requestLogsMutex sync.Mutex
	maxLogSize       = 100

	// 回调记录
	callbacks      []CallbackRequest
	callbacksMutex sync.Mutex

	// renew-flow 场景：每个订单被查询的次数
	renewQueryCount      = make(map[int]int)
	renewQueryCountMutex sync.Mutex

	// releases 虚拟二进制数据
	releaseBinaryData []byte
	releaseBinaryHash string
	releaseIndex      ReleaseIndex
)

// 场景配置。
//
// httpStatus 只用于协议外的服务端崩溃（未捕获异常 → HTTP 500）；所有业务失败必须
// httpStatus=200 + code=0 + apiErrorCode，与 deploy-spec §2.2 一致。
var scenarios = map[string]struct {
	status       string
	expiresIn    time.Duration
	httpStatus   int
	apiErrorCode string
	retryAfter   int
	errorMsg     string
}{
	"active":     {status: "active", expiresIn: 90 * 24 * time.Hour},
	"processing": {status: "processing", expiresIn: 0},
	"expired":    {status: "expired", expiresIn: -30 * 24 * time.Hour},
	// 服务端未捕获异常：协议之外，客户端应按传输故障处理（可重试）
	"error": {httpStatus: 500, errorMsg: "Internal server error"},
	// 以下为业务失败：HTTP 200 + code=0 + error_code
	"unauthorized": {apiErrorCode: "token_invalid", errorMsg: "Invalid deploy token"},
	"not_found":    {apiErrorCode: "order_not_found", errorMsg: "Order not found"},
	"rate_limited": {apiErrorCode: "rate_limited", retryAfter: 100, errorMsg: "Deploy token rate limit exceeded"},
	"batch":        {status: "active", expiresIn: 90 * 24 * time.Hour},
	"renew-flow":   {status: "processing", expiresIn: 0},
	"releases":     {status: "active", expiresIn: 90 * 24 * time.Hour},
}

// scenarioNames 返回排序后的场景名，供日志与错误提示使用（避免多处硬编码后漂移）
func scenarioNames() string {
	names := make([]string, 0, len(scenarios))
	for name := range scenarios {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// order 查询参数的形态与条数上限（deploy-spec §2.3）：仅订单 ID，单个或英文逗号分隔多个
var orderQueryPattern = regexp.MustCompile(`^\d+(,\d+)*$`)

const maxBatchQueryItems = 100

// writeAPIError 按 deploy-spec §2.2 输出业务失败：HTTP 200 + code=0 + errors.error_code
func writeAPIError(w http.ResponseWriter, msg, errorCode string, retryAfter int) {
	w.Header().Set("Content-Type", "application/json")
	resp := APIResponse{Code: 0, Message: msg}
	if errorCode != "" {
		resp.Errors = &APIErrors{ErrorCode: errorCode, RetryAfter: retryAfter}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// scenarioFailure 若当前场景配置了失败则写出响应并返回 true
func scenarioFailure(w http.ResponseWriter) bool {
	cfg, ok := scenarios[getScenario()]
	if !ok {
		return false
	}
	switch {
	case cfg.httpStatus > 0:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(cfg.httpStatus)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: cfg.errorMsg})
		return true
	case cfg.apiErrorCode != "":
		writeAPIError(w, cfg.errorMsg, cfg.apiErrorCode, cfg.retryAfter)
		return true
	}
	return false
}

// ==============================================================================
// 主函数
// ==============================================================================

func main() {
	port := flag.Int("port", 8080, "API 服务端口")
	flag.StringVar(&certFile, "cert", "", "证书文件路径")
	flag.StringVar(&keyFile, "key", "", "私钥文件路径")
	flag.StringVar(&chainFile, "chain", "", "中间证书文件路径")
	flag.StringVar(&commonName, "cn", "example.com", "证书 CommonName")
	flag.Parse()

	// 启动时加载/生成证书
	loadCertFiles()

	// 初始化测试订单
	initTestOrders()

	// 初始化 releases 数据
	initReleaseData()

	// 注册路由
	mux := http.NewServeMux()

	// 主要 API 端点
	mux.HandleFunc("/api/deploy", handleDeploy)
	mux.HandleFunc("/api/deploy/auto-reissue", handleAutoReissue)
	mux.HandleFunc("/api/deploy/callback", handleCallback)
	mux.HandleFunc("/api/cert", handleCert)
	mux.HandleFunc("/api/callback", handleCallback)

	// releases 端点
	// /releases/releases.json - 版本索引（精确匹配优先于 /releases/ 子树）
	// /releases/{channel}/v{version}/{filename} - 二进制下载
	mux.HandleFunc("/releases/releases.json", handleReleasesJSON)
	mux.HandleFunc("/releases/", handleReleasesDownload)

	// 管理端点
	mux.HandleFunc("/admin/scenario/", handleSetScenario)
	mux.HandleFunc("/admin/reset", handleReset)
	mux.HandleFunc("/admin/logs", handleGetLogs)
	mux.HandleFunc("/admin/callbacks", handleGetCallbacks)
	mux.HandleFunc("/admin/orders", handleManageOrders)

	// 健康检查
	mux.HandleFunc("/health", handleHealth)

	// 包装中间件
	handler := loggingMiddleware(mux)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock API server starting on %s", addr)
	log.Printf("Cert: %s, Key: %s, Chain: %s", certFile, keyFile, chainFile)
	log.Printf("Default scenario: %s", currentScenario)
	log.Printf("Available scenarios: %s", scenarioNames())
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

// ==============================================================================
// 初始化
// ==============================================================================

// loadCertFiles 加载或生成证书（CA → 服务器证书分层）
func loadCertFiles() {
	// 如果指定了外部证书文件，使用外部文件
	if certFile != "" && keyFile != "" {
		cert, err := os.ReadFile(certFile)
		if err != nil {
			log.Printf("Warning: Cannot read cert file %s: %v", certFile, err)
		} else {
			cachedCert = string(cert)
			log.Printf("Loaded cert from %s", certFile)
		}

		key, err := os.ReadFile(keyFile)
		if err != nil {
			log.Printf("Warning: Cannot read key file %s: %v", keyFile, err)
		} else {
			cachedKey = string(key)
			log.Printf("Loaded key from %s", keyFile)
		}

		if chainFile != "" {
			chain, err := os.ReadFile(chainFile)
			if err != nil {
				log.Printf("Warning: Cannot read chain file %s: %v", chainFile, err)
			} else {
				cachedChain = string(chain)
				log.Printf("Loaded chain from %s", chainFile)
			}
		}

		// 如果成功加载了证书和私钥，直接返回
		if cachedCert != "" && cachedKey != "" {
			return
		}
	}

	// 动态生成 CA → 服务器证书分层
	generateCACertPair(commonName)
}

func initTestOrders() {
	ordersMutex.Lock()
	defer ordersMutex.Unlock()

	// 清空重建
	orders = make(map[int]*OrderData)

	orders[1001] = &OrderData{
		OrderID:    1001,
		Status:     "active",
		Domains:    "test.example.com,*.test.example.com",
		CommonName: "test.example.com",
		CreatedAt:  time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
		ExpiresAt:  time.Now().AddDate(0, 2, 0).Format(time.RFC3339),
		RenewMode:  "pull",
	}

	orders[1002] = &OrderData{
		OrderID:    1002,
		Status:     "processing",
		Domains:    "pending.example.com",
		CommonName: "pending.example.com",
		CreatedAt:  time.Now().Format(time.RFC3339),
		ExpiresAt:  "",
	}

	orders[1003] = &OrderData{
		OrderID:    1003,
		Status:     "expired",
		Domains:    "expired.example.com",
		CommonName: "expired.example.com",
		CreatedAt:  time.Now().AddDate(-1, 0, 0).Format(time.RFC3339),
		ExpiresAt:  time.Now().AddDate(0, 0, -30).Format(time.RFC3339),
	}

	// batch 场景用订单
	orders[1004] = &OrderData{
		OrderID:    1004,
		Status:     "active",
		Domains:    "batch1.example.com,*.batch1.example.com",
		CommonName: "batch1.example.com",
		CreatedAt:  time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
		ExpiresAt:  time.Now().AddDate(0, 2, 0).Format(time.RFC3339),
		RenewMode:  "pull",
	}

	orders[1005] = &OrderData{
		OrderID:    1005,
		Status:     "active",
		Domains:    "batch2.example.com,*.batch2.example.com",
		CommonName: "batch2.example.com",
		CreatedAt:  time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
		ExpiresAt:  time.Now().AddDate(0, 2, 0).Format(time.RFC3339),
		RenewMode:  "pull",
	}

	nextOrderID = 1006
}

// initReleaseData 初始化升级测试数据
func initReleaseData() {
	// 生成虚拟二进制（4KB），然后 gzip 压缩
	// sslctl upgrade 下载的是 gzip 数据，校验和也基于 gzip 数据计算
	rawBinary := make([]byte, 4096)
	for i := range rawBinary {
		rawBinary[i] = byte(i % 256)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(rawBinary); err != nil {
		log.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		log.Fatalf("gzip close: %v", err)
	}
	releaseBinaryData = buf.Bytes()

	// 校验和格式: "sha256:<hex>"（与 pkg/upgrade.VerifyChecksum 一致）
	hash := sha256.Sum256(releaseBinaryData)
	releaseBinaryHash = "sha256:" + hex.EncodeToString(hash[:])

	// 文件名格式: sslctl-{os}-{arch}.gz（与 pkg/upgrade.GetDownloadFilename 一致）
	files := []string{
		"sslctl-linux-amd64.gz",
		"sslctl-linux-arm64.gz",
		"sslctl-windows-amd64.exe.gz",
	}

	checksums := make(map[string]string)
	for _, f := range files {
		checksums[f] = releaseBinaryHash
	}

	releaseIndex = ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "99.0.0",
			Versions: []VersionInfo{
				{
					Version:    "99.0.0",
					ReleasedAt: time.Now().Format("2006-01-02"),
					Checksums:  checksums,
				},
			},
		},
		"dev": &ChannelInfo{
			Latest: "99.0.0-dev1",
			Versions: []VersionInfo{
				{
					Version:    "99.0.0-dev1",
					ReleasedAt: time.Now().Format("2006-01-02"),
					Checksums:  checksums,
				},
			},
		},
	}

	log.Printf("Initialized release data: main=v99.0.0, dev=v99.0.0-dev1, gzip=%d bytes, %s",
		len(releaseBinaryData), releaseBinaryHash[:24]+"...")
}

// ==============================================================================
// 中间件
// ==============================================================================

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 跳过健康检查的日志
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// 记录请求
		logRequest(r)

		log.Printf("[%s] %s %s from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func logRequest(r *http.Request) {
	requestLogsMutex.Lock()
	defer requestLogsMutex.Unlock()

	entry := RequestLog{
		Time:      time.Now().Format(time.RFC3339),
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   r.Header,
		Query:     r.URL.Query(),
		RemoteIP:  r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}

	requestLogs = append(requestLogs, entry)

	// 限制日志大小
	if len(requestLogs) > maxLogSize {
		requestLogs = requestLogs[len(requestLogs)-maxLogSize:]
	}
}

// ==============================================================================
// API 处理函数
// ==============================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// handleDeploy 处理部署相关 API
// GET /api/deploy - 获取订单列表
// GET /api/deploy?order=xxx - 获取指定订单
// POST /api/deploy - 续签请求
func handleDeploy(w http.ResponseWriter, r *http.Request) {
	// 检查 Authorization
	if !checkAuth(w, r) {
		return
	}

	// 检查场景
	if scenarioFailure(w) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleGetOrders(w, r)
	case http.MethodPost:
		handleRenewRequest(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Method not allowed"})
	}
}

func handleGetOrders(w http.ResponseWriter, r *http.Request) {
	ordersMutex.RLock()
	defer ordersMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	scenario := getScenario()

	// order 必填且只接受订单 ID（deploy-spec §2.3）：缺参、空串、含域名、超过上限
	// 一律 invalid_order。真实服务端不再提供「无 order 返回列表」与按域名匹配的行为。
	orderIDStr := r.URL.Query().Get("order")
	if !orderQueryPattern.MatchString(orderIDStr) {
		writeAPIError(w, "order 参数形态非法（仅接受订单 ID）", "invalid_order", 0)
		return
	}
	if strings.Count(orderIDStr, ",")+1 > maxBatchQueryItems {
		writeAPIError(w, fmt.Sprintf("单次最多查询 %d 条", maxBatchQueryItems), "invalid_order", 0)
		return
	}

	if strings.Contains(orderIDStr, ",") {
		// 批量查询：全部未命中返回空数组而非报错（spec §2.3）
		matchedOrders := filterOrdersByQuery(orderIDStr, scenario)
		_ = json.NewEncoder(w).Encode(APIResponse{
			Code:    1,
			Message: "success",
			Data: PaginatedData{
				Total: len(matchedOrders), CurrentPage: 1, PageSize: 100,
				RenewBeforeDays: 14,
				Data:            matchedOrders,
			},
		})
		return
	}

	{
		orderID, _ := strconv.Atoi(orderIDStr)

		order, exists := orders[orderID]
		if !exists {
			// 单 ID 查询未命中：业务失败，HTTP 200 + code=0 + error_code（spec §2.3）
			writeAPIError(w, "Order not found", "order_not_found", 0)
			return
		}

		// local CSR 已提交：POST 仅返回 processing；后续 GET 返回按该 CSR 公钥签发的证书。
		if order.CertData.Cert != "" {
			certData := order.CertData
			_ = json.NewEncoder(w).Encode(APIResponse{
				Code:    1,
				Message: "success",
				Data: PaginatedData{
					Total: 1, CurrentPage: 1, PageSize: 100,
					RenewBeforeDays: 14,
					Data:            []interface{}{certData},
				},
			})
			return
		}

		// renew-flow 场景：根据查询次数切换状态
		if scenario == "renew-flow" {
			certData := getRenewFlowResponse(order)
			_ = json.NewEncoder(w).Encode(APIResponse{
				Code:    1,
				Message: "success",
				Data: PaginatedData{
					Total: 1, CurrentPage: 1, PageSize: 100,
					RenewBeforeDays: 14,
					Data:            []interface{}{certData},
				},
			})
			return
		}

		// processing 场景
		if scenario == "processing" || order.Status == "processing" {
			data := buildOrderResponse(order, scenario)
			_ = json.NewEncoder(w).Encode(APIResponse{
				Code:    1,
				Message: "success",
				Data: PaginatedData{
					Total: 1, CurrentPage: 1, PageSize: 100,
					RenewBeforeDays: 14,
					Data:            []interface{}{data},
				},
			})
			return
		}

		// active 订单，附加证书数据
		if order.Status == "active" {
			certData := getCertDataWithOrder(order.CommonName, order.OrderID)
			certData.Domains = order.Domains
			_ = json.NewEncoder(w).Encode(APIResponse{
				Code:    1,
				Message: "success",
				Data: PaginatedData{
					Total: 1, CurrentPage: 1, PageSize: 100,
					RenewBeforeDays: 14,
					Data:            []interface{}{certData},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(APIResponse{
				Code:    1,
				Message: "success",
				Data: PaginatedData{
					Total: 1, CurrentPage: 1, PageSize: 100,
					RenewBeforeDays: 14,
					Data:            []interface{}{order},
				},
			})
		}
	}
}

func handleRenewRequest(w http.ResponseWriter, r *http.Request) {
	var req RenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Invalid request body"})
		return
	}

	log.Printf("=== Renew request received ===")
	log.Printf("  OrderID: %d", req.OrderID)
	log.Printf("  CSR: %s...", truncate(req.CSR, 50))

	ordersMutex.Lock()
	defer ordersMutex.Unlock()

	order, exists := orders[req.OrderID]
	if !exists {
		// 业务失败（spec §2.6 单条目组）：HTTP 200 + code=0 + error_code
		writeAPIError(w, "Order not found", "order_not_found", 0)
		return
	}

	issued, err := issueCertificateForCSR(req.CSR, order.OrderID, order.CommonName)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: err.Error()})
		return
	}
	order.Status = "processing"
	order.CertData = issued
	order.ExpiresAt = issued.ExpiresAt

	processing := CertData{
		OrderID:  order.OrderID,
		Status:   "processing",
		Domains:  order.Domains,
		IssuedAt: "",
	}
	if req.ValidationMethod == "file" {
		processing.File = &FileChallenge{
			Path:    ".well-known/pki-validation/local-renew.txt",
			Content: "local-renew-validation-content",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{
		Code:    1,
		Message: "success",
		Data: map[string]interface{}{
			"order_id":          processing.OrderID,
			"status":            processing.Status,
			"domains":           processing.Domains,
			"file":              processing.File,
			"renew_before_days": 14,
		},
	})
}

func handleCert(w http.ResponseWriter, r *http.Request) {
	// 检查 Authorization header
	if !checkAuth(w, r) {
		return
	}

	// 检查场景
	if scenarioFailure(w) {
		return
	}

	certData := getCertData(commonName)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{
		Code:    1,
		Message: "success",
		Data:    certData,
	})
	log.Printf("Served certificate for %s to %s", commonName, r.RemoteAddr)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Method not allowed"})
		return
	}

	// 检查 Authorization header
	if !checkAuth(w, r) {
		return
	}

	// 解析回调请求
	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Invalid request body"})
		return
	}
	if len([]rune(req.Message)) > 500 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Message exceeds 500 characters"})
		return
	}

	// 记录回调
	callbacksMutex.Lock()
	callbacks = append(callbacks, req)
	callbacksMutex.Unlock()

	log.Printf("=== Callback received ===")
	log.Printf("  OrderID: %d", req.OrderID)
	log.Printf("  Status: %s", req.Status)
	log.Printf("  DeployedAt: %s", req.DeployedAt)
	if req.Message != "" {
		log.Printf("  Message: %s", req.Message)
	}
	log.Printf("========================")

	w.Header().Set("Content-Type", "application/json")
	// 回调响应包含 renew_before_days（与 fetcher.CallbackResponse 匹配）
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 1,
		"msg":  "success",
		"data": map[string]int{
			"renew_before_days": 14,
		},
	})
}

func handleAutoReissue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Method not allowed"})
		return
	}
	if !checkAuth(w, r) {
		return
	}
	var req AutoReissueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Invalid request body"})
		return
	}
	ordersMutex.Lock()
	order, ok := orders[req.OrderID]
	if ok {
		if req.AutoReissue {
			order.RenewMode = "pull"
		} else {
			order.RenewMode = "local"
		}
	}
	ordersMutex.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Order not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{
		Code:    1,
		Message: "success",
		Data: map[string]int{
			"renew_before_days": 14,
		},
	})
}

// ==============================================================================
// Releases 端点
// ==============================================================================

func handleReleasesJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(releaseIndex)
}

func handleReleasesDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 提取文件名: /releases/{channel}/v{version}/{filename}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	filename := parts[len(parts)-1]

	// 校验文件名是否在 releases.json 中
	found := false
	for _, ch := range releaseIndex {
		for _, v := range ch.Versions {
			if _, ok := v.Checksums[filename]; ok {
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("File not found"))
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(releaseBinaryData)))
	_, _ = w.Write(releaseBinaryData)
}

// ==============================================================================
// 管理端点
// ==============================================================================

func handleSetScenario(w http.ResponseWriter, r *http.Request) {
	// 提取场景名称
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Missing scenario name"))
		return
	}

	scenario := parts[3]
	if _, ok := scenarios[scenario]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("Unknown scenario: %s. Available: %s", scenario, scenarioNames())))
		return
	}

	setScenario(scenario)
	log.Printf("Scenario changed to: %s", scenario)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"scenario": scenario,
	})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 重置场景
	setScenario("active")

	// 重置日志
	requestLogsMutex.Lock()
	requestLogs = nil
	requestLogsMutex.Unlock()

	// 重置回调
	callbacksMutex.Lock()
	callbacks = nil
	callbacksMutex.Unlock()

	// 重置 renew-flow 查询计数
	renewQueryCountMutex.Lock()
	renewQueryCount = make(map[int]int)
	renewQueryCountMutex.Unlock()

	// 重置订单
	initTestOrders()

	log.Printf("State reset to default")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleGetLogs(w http.ResponseWriter, r *http.Request) {
	requestLogsMutex.Lock()
	logs := make([]RequestLog, len(requestLogs))
	copy(logs, requestLogs)
	requestLogsMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

func handleGetCallbacks(w http.ResponseWriter, r *http.Request) {
	callbacksMutex.Lock()
	cbs := make([]CallbackRequest, len(callbacks))
	copy(cbs, callbacks)
	callbacksMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cbs)
}

func handleManageOrders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 列出所有订单
		ordersMutex.RLock()
		var orderList []OrderData
		for _, order := range orders {
			orderList = append(orderList, *order)
		}
		ordersMutex.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(orderList)

	case http.MethodPost:
		// 创建新订单
		var order OrderData
		if err := json.NewDecoder(r.Body).Decode(&order); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Invalid request body"))
			return
		}

		ordersMutex.Lock()
		order.OrderID = nextOrderID
		nextOrderID++
		order.CreatedAt = time.Now().Format(time.RFC3339)
		if order.Status == "" {
			order.Status = "active"
		}
		orders[order.OrderID] = &order
		ordersMutex.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(order)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ==============================================================================
// renew-flow 场景逻辑
// ==============================================================================

// getRenewFlowResponse 根据查询次数返回不同状态
// 首次查询返回 processing（含 file 字段），第二次及以后返回 active（含证书）
func getRenewFlowResponse(order *OrderData) interface{} {
	renewQueryCountMutex.Lock()
	renewQueryCount[order.OrderID]++
	count := renewQueryCount[order.OrderID]
	renewQueryCountMutex.Unlock()

	log.Printf("renew-flow: order %d query count = %d", order.OrderID, count)

	if count <= 1 {
		// 首次查询：返回 processing + file 字段
		return CertData{
			OrderID:   order.OrderID,
			Status:    "processing",
			Domains:   order.Domains,
			ExpiresAt: "",
			File: &FileChallenge{
				Path:    ".well-known/pki-validation/test.txt",
				Content: "test-validation-content-12345",
			},
		}
	}

	// 第二次及以后：返回 active + 证书
	certData := getCertDataWithOrder(order.CommonName, order.OrderID)
	certData.Domains = order.Domains
	return certData
}

// ==============================================================================
// 辅助函数
// ==============================================================================

func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		// 认证中间件的失败同样是 HTTP 200 + code=0 + error_code（spec §2.2 整批共通组）
		writeAPIError(w, "Deploy token is missing", "token_missing", 0)
		return false
	}
	return true
}

func getScenario() string {
	scenarioMutex.RLock()
	defer scenarioMutex.RUnlock()
	return currentScenario
}

func setScenario(s string) {
	scenarioMutex.Lock()
	defer scenarioMutex.Unlock()
	currentScenario = s
}

func getCertData(cn string) CertData {
	return getCertDataWithOrder(cn, 1001) // 默认使用订单 1001
}

func getCertDataWithOrder(cn string, orderID int) CertData {
	scenario := getScenario()

	// processing 场景：返回 processing 状态 + file 字段
	if scenario == "processing" {
		return CertData{
			OrderID:   orderID,
			Status:    "processing",
			Domains:   cn + ",*." + cn,
			ExpiresAt: "",
			File: &FileChallenge{
				Path:    ".well-known/pki-validation/test.txt",
				Content: "test-validation-content-12345",
			},
		}
	}

	cfg := scenarios[scenario]

	issuedAt := time.Now().AddDate(0, -1, 0).Format("2006-01-02")
	expiresAt := time.Now().Add(cfg.expiresIn).Format("2006-01-02")

	// 使用缓存的证书内容（CA → 服务器证书分层）
	return CertData{
		OrderID:          orderID,
		Status:           cfg.status,
		Domains:          cn + ",*." + cn,
		Cert:             cachedCert,
		IntermediateCert: cachedChain,
		PrivateKey:       cachedKey,
		IssuedAt:         issuedAt,
		ExpiresAt:        expiresAt,
	}
}

// buildOrderResponse 构建订单响应（用于非 active 状态）
func buildOrderResponse(order *OrderData, scenario string) interface{} {
	if scenario == "processing" {
		return CertData{
			OrderID:   order.OrderID,
			Status:    "processing",
			Domains:   order.Domains,
			ExpiresAt: "",
			File: &FileChallenge{
				Path:    ".well-known/pki-validation/test.txt",
				Content: "test-validation-content-12345",
			},
		}
	}
	return order
}

// filterOrdersByQuery 按逗号分隔的查询条件过滤订单
// 支持混合 ID 和域名关键字，例如 "1001,test.example.com"
// 匹配逻辑：订单 ID 匹配 或 订单域名包含关键字
func filterOrdersByQuery(query, scenario string) []interface{} {
	parts := strings.Split(query, ",")
	var result []interface{}
	seen := make(map[int]bool)

	// 只按订单 ID 匹配：spec §2.3 已废止按域名查询，形态校验在调用前完成。
	// 未命中的 ID 直接略过——批量查询全部未命中返回空数组而非报错。
	for _, part := range parts {
		id, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		if order, exists := orders[id]; exists && !seen[order.OrderID] {
			seen[order.OrderID] = true
			result = append(result, orderToResponse(order, scenario))
		}
	}

	return result
}

// orderToResponse 根据场景将订单转换为 API 响应数据
func orderToResponse(order *OrderData, scenario string) interface{} {
	if scenario == "processing" || order.Status == "processing" {
		return buildOrderResponse(order, scenario)
	}
	if order.Status == "active" {
		certData := getCertDataWithOrder(order.CommonName, order.OrderID)
		certData.Domains = order.Domains
		return certData
	}
	return *order
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ==============================================================================
// 证书生成：CA → 服务器证书分层
// ==============================================================================

// generatedCertBundle 缓存生成的证书套件
var generatedCertBundle struct {
	serverCert string // 服务器证书 PEM
	serverKey  string // 服务器私钥 PEM (PKCS8)
	caCert     string // CA 证书 PEM（作为中间证书返回）
	caParsed   *x509.Certificate
	caKey      *rsa.PrivateKey
	once       sync.Once
}

// generateCACertPair 生成 CA 密钥对 + CA 证书，再用 CA 签发服务器证书
func generateCACertPair(cn string) {
	generatedCertBundle.once.Do(func() {
		doGenerateCACertPair(cn)
	})
	cachedCert = generatedCertBundle.serverCert
	cachedKey = generatedCertBundle.serverKey
	cachedChain = generatedCertBundle.caCert
}

func doGenerateCACertPair(cn string) {
	// 1. 生成 CA 密钥对
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Mock CA",
			Organization: []string{"Mock CA Org"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10年有效期
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// 自签 CA 证书
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		log.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// 编码 CA 证书 PEM
	var caPEM bytes.Buffer
	if err := pem.Encode(&caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		log.Fatalf("Failed to encode CA certificate PEM: %v", err)
	}
	generatedCertBundle.caCert = caPEM.String()
	generatedCertBundle.caParsed = caCert
	generatedCertBundle.caKey = caKey

	// 2. 生成服务器密钥对
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate server key: %v", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{cn, "*." + cn},
	}

	// 用 CA 签发服务器证书
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create server certificate: %v", err)
	}

	// 编码服务器证书 PEM
	var serverCertPEM bytes.Buffer
	if err := pem.Encode(&serverCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}); err != nil {
		log.Fatalf("Failed to encode server certificate PEM: %v", err)
	}
	generatedCertBundle.serverCert = serverCertPEM.String()

	// 编码服务器私钥为 PKCS8 格式 PEM
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		log.Fatalf("Failed to marshal server private key to PKCS8: %v", err)
	}
	var serverKeyPEM bytes.Buffer
	if err := pem.Encode(&serverKeyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key}); err != nil {
		log.Fatalf("Failed to encode server private key PEM: %v", err)
	}
	generatedCertBundle.serverKey = serverKeyPEM.String()

	log.Printf("Generated CA-signed certificate bundle for %s (CA: Mock CA)", cn)
}

// issueCertificateForCSR 使用 Mock CA 按 CSR 公钥签发证书。
// local 模式的私钥只存在客户端 pending-keys/，服务端响应不得返回 private_key。
func issueCertificateForCSR(csrPEM string, orderID int, fallbackCN string) (CertData, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return CertData{}, fmt.Errorf("invalid CSR PEM")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return CertData{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return CertData{}, fmt.Errorf("verify CSR signature: %w", err)
	}
	if generatedCertBundle.caParsed == nil || generatedCertBundle.caKey == nil {
		return CertData{}, fmt.Errorf("mock CA signer unavailable")
	}
	cn := req.Subject.CommonName
	if cn == "" {
		cn = fallbackCN
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Mock Local Renew"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(0, 3, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, generatedCertBundle.caParsed, req.PublicKey, generatedCertBundle.caKey)
	if err != nil {
		return CertData{}, fmt.Errorf("sign CSR: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return CertData{
		OrderID:          orderID,
		Status:           "active",
		Domains:          cn,
		Cert:             string(certPEM),
		IntermediateCert: generatedCertBundle.caCert,
		PrivateKey:       "",
		IssuedAt:         now.Format("2006-01-02"),
		ExpiresAt:        tmpl.NotAfter.Format("2006-01-02"),
	}, nil
}
