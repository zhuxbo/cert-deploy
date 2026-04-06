// 模拟证书 API 服务器
// 用于测试证书部署流程
// 支持场景切换、请求记录、多端点模拟
package main

import (
	"bytes"
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
}

// PaginatedData 分页数据（与 fetcher.PaginatedResponse 字段名匹配）
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
}

// RenewRequest 续签请求
type RenewRequest struct {
	OrderID int    `json:"order_id"`
	CSR     string `json:"csr,omitempty"`
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

// 场景配置
var scenarios = map[string]struct {
	status    string
	expiresIn time.Duration
	errorCode int
	errorMsg  string
}{
	"active":       {status: "active", expiresIn: 90 * 24 * time.Hour},
	"processing":   {status: "processing", expiresIn: 0},
	"expired":      {status: "expired", expiresIn: -30 * 24 * time.Hour},
	"error":        {errorCode: 500, errorMsg: "Internal server error"},
	"unauthorized":  {errorCode: 401, errorMsg: "Unauthorized"},
	"not_found":     {errorCode: 404, errorMsg: "Order not found"},
	"batch":        {status: "active", expiresIn: 90 * 24 * time.Hour},
	"renew-flow":   {status: "processing", expiresIn: 0},
	"releases":     {status: "active", expiresIn: 90 * 24 * time.Hour},
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
	mux.HandleFunc("/api/deploy/callback", handleCallback)
	mux.HandleFunc("/api/cert", handleCert)
	mux.HandleFunc("/api/callback", handleCallback)

	// releases 端点
	mux.HandleFunc("/releases/releases.json", handleReleasesJSON)
	mux.HandleFunc("/releases/download/", handleReleasesDownload)

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
	log.Printf("Available scenarios: active, processing, expired, error, unauthorized, not_found, batch, renew-flow, releases")
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
	// 生成虚拟二进制文件（4KB）
	releaseBinaryData = make([]byte, 4096)
	for i := range releaseBinaryData {
		releaseBinaryData[i] = byte(i % 256)
	}

	// 计算 SHA256 checksum
	hash := sha256.Sum256(releaseBinaryData)
	releaseBinaryHash = hex.EncodeToString(hash[:])

	// 文件名列表（与 sslctl 实际发布文件名匹配）
	files := []string{
		"sslctl_linux_amd64.tar.gz",
		"sslctl_linux_arm64.tar.gz",
		"sslctl_windows_amd64.zip",
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

	log.Printf("Initialized release data: main=v99.0.0, dev=v99.0.0-dev1, binary=%d bytes, sha256=%s",
		len(releaseBinaryData), releaseBinaryHash[:16]+"...")
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
	scenario := getScenario()
	if cfg, ok := scenarios[scenario]; ok && cfg.errorCode > 0 {
		w.WriteHeader(cfg.errorCode)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: cfg.errorMsg})
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

	// 检查是否请求特定订单
	orderIDStr := r.URL.Query().Get("order")
	if orderIDStr != "" {
		orderID, err := strconv.Atoi(orderIDStr)
		if err != nil {
			// 非纯整数: 批量查询（逗号分隔的 ID/域名混合）
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

		order, exists := orders[orderID]
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Order not found"})
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
		return
	}

	// 无 order 参数：返回订单列表
	// batch 场景下返回所有 active 订单（附带证书数据）
	if scenario == "batch" {
		var activeOrders []interface{}
		for _, order := range orders {
			if order.Status == "active" {
				certData := getCertDataWithOrder(order.CommonName, order.OrderID)
				certData.Domains = order.Domains
				activeOrders = append(activeOrders, certData)
			}
		}
		_ = json.NewEncoder(w).Encode(APIResponse{
			Code:    1,
			Message: "success",
			Data: PaginatedData{
				Total: len(activeOrders), CurrentPage: 1, PageSize: 100,
				RenewBeforeDays: 14,
				Data:            activeOrders,
			},
		})
		return
	}

	// 默认：返回所有订单
	var orderList []interface{}
	for _, order := range orders {
		orderList = append(orderList, *order)
	}

	_ = json.NewEncoder(w).Encode(APIResponse{
		Code:    1,
		Message: "success",
		Data: PaginatedData{
			Total: len(orderList), CurrentPage: 1, PageSize: 100,
			RenewBeforeDays: 14,
			Data:            orderList,
		},
	})
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
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Order not found"})
		return
	}

	// 模拟续签：更新订单状态
	order.Status = "active"
	order.ExpiresAt = time.Now().AddDate(0, 3, 0).Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{
		Code:    1,
		Message: "success",
		Data:    getCertData(order.CommonName),
	})
}

func handleCert(w http.ResponseWriter, r *http.Request) {
	// 检查 Authorization header
	if !checkAuth(w, r) {
		return
	}

	// 检查场景
	scenario := getScenario()
	if cfg, ok := scenarios[scenario]; ok && cfg.errorCode > 0 {
		w.WriteHeader(cfg.errorCode)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: cfg.errorMsg})
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

	// 记录回调
	callbacksMutex.Lock()
	callbacks = append(callbacks, req)
	callbacksMutex.Unlock()

	log.Printf("=== Callback received ===")
	log.Printf("  OrderID: %d", req.OrderID)
	log.Printf("  Status: %s", req.Status)
	log.Printf("  DeployedAt: %s", req.DeployedAt)
	log.Printf("========================")

	w.Header().Set("Content-Type", "application/json")
	// 回调响应包含 renew_before_days（与 fetcher.CallbackResponse 匹配）
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code":              1,
		"msg":               "success",
		"renew_before_days": 14,
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

	// 提取文件名: /releases/download/{filename}
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
		_, _ = w.Write([]byte(fmt.Sprintf("Unknown scenario: %s. Available: active, processing, expired, error, unauthorized, not_found, batch, renew-flow, releases", scenario)))
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
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Unauthorized"})
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

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 尝试按 ID 匹配
		if id, err := strconv.Atoi(part); err == nil {
			if order, exists := orders[id]; exists && !seen[order.OrderID] {
				seen[order.OrderID] = true
				result = append(result, orderToResponse(order, scenario))
			}
			continue
		}

		// 按域名关键字匹配
		for _, order := range orders {
			if seen[order.OrderID] {
				continue
			}
			if strings.Contains(order.Domains, part) || strings.Contains(order.CommonName, part) {
				seen[order.OrderID] = true
				result = append(result, orderToResponse(order, scenario))
			}
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
