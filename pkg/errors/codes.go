// Package errors 定义应用错误码
package errors

import (
	stderrors "errors"
	"fmt"
)

// 错误码常量
const (
	CodeSuccess       = 0  // 成功
	CodeConfigError   = 10 // 配置错误
	CodeAuthError     = 20 // 认证失败
	CodeValidateError = 30 // 证书校验失败
	CodeWriteError    = 40 // 文件写入失败
	CodeReloadError   = 41 // Reload 失败
	CodeDeployError   = 42 // 部署错误
	CodeNetworkError  = 50 // 网络错误
	CodeBusinessError = 51 // 业务拒绝（服务端明确拒绝请求，非传输失败）
	CodeUnknownError  = 99 // 未知错误
)

// AppError 应用错误类型
type AppError struct {
	Code    int
	Message string
	Err     error
	// ErrorCode 服务端下发的机器可读失败标识（deploy-spec §2.2），仅业务拒绝时有值
	ErrorCode string
	// RetryAfter 睡满即可重试的保守秒数，仅 ErrorCode=rate_limited 时有值
	RetryAfter int
}

// Error 实现 error 接口
func (e *AppError) Error() string {
	// ErrorCode 进入错误文本：它会随失败原因流入日志与回调 message，
	// 是运维定位「为什么停止」的唯一线索
	prefix := fmt.Sprintf("code=%d", e.Code)
	if e.ErrorCode != "" {
		prefix = fmt.Sprintf("code=%d, error_code=%s", e.Code, e.ErrorCode)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s, msg=%s, err=%v", prefix, e.Message, e.Err)
	}
	return fmt.Sprintf("%s, msg=%s", prefix, e.Message)
}

// Unwrap 支持 errors.Is/As
func (e *AppError) Unwrap() error {
	return e.Err
}

// 便捷构造函数

func NewConfigError(msg string, err error) *AppError {
	return &AppError{Code: CodeConfigError, Message: msg, Err: err}
}

func NewAuthError(msg string, err error) *AppError {
	return &AppError{Code: CodeAuthError, Message: msg, Err: err}
}

func NewValidateError(msg string, err error) *AppError {
	return &AppError{Code: CodeValidateError, Message: msg, Err: err}
}

func NewWriteError(msg string, err error) *AppError {
	return &AppError{Code: CodeWriteError, Message: msg, Err: err}
}

func NewReloadError(msg string, err error) *AppError {
	return &AppError{Code: CodeReloadError, Message: msg, Err: err}
}

func NewNetworkError(msg string, err error) *AppError {
	return &AppError{Code: CodeNetworkError, Message: msg, Err: err}
}

func NewBusinessError(msg string, err error) *AppError {
	return &AppError{Code: CodeBusinessError, Message: msg, Err: err}
}

// NewBusinessErrorWithCode 构造带服务端 error_code 的业务拒绝（deploy-spec §2.2）
func NewBusinessErrorWithCode(msg, errorCode string, retryAfter int) *AppError {
	return &AppError{
		Code:       CodeBusinessError,
		Message:    msg,
		ErrorCode:  errorCode,
		RetryAfter: retryAfter,
	}
}

// IsBusinessError 判断是否为服务端明确业务拒绝（区别于超时/断连/解析失败等不确定结果）
func IsBusinessError(err error) bool {
	var appErr *AppError
	return stderrors.As(err, &appErr) && appErr.Code == CodeBusinessError
}

// ErrorCodeOf 提取服务端下发的 error_code，无则返回空串。
// 供调用方区分「确定性失败」的具体成因（订单不存在 / token 失效 / 限流等）。
func ErrorCodeOf(err error) string {
	var appErr *AppError
	if stderrors.As(err, &appErr) {
		return appErr.ErrorCode
	}
	return ""
}

// RetryAfterOf 提取限流响应的可重试秒数（睡满即可重试的保守值），无则返回 0
func RetryAfterOf(err error) int {
	var appErr *AppError
	if stderrors.As(err, &appErr) {
		return appErr.RetryAfter
	}
	return 0
}

func NewDeployError(msg string, err error) *AppError {
	return &AppError{Code: CodeDeployError, Message: msg, Err: err}
}

// DeployErrorType 部署错误类型
type DeployErrorType int

const (
	DeployErrorUnknown    DeployErrorType = iota // 未知错误
	DeployErrorConfig                            // 配置错误（不可重试）
	DeployErrorPermission                        // 权限错误（不可重试）
	DeployErrorNetwork                           // 网络错误（可重试）
	DeployErrorValidation                        // 验证错误（不可重试）
	DeployErrorReload                            // 重载错误（可重试）
)

func (t DeployErrorType) String() string {
	switch t {
	case DeployErrorConfig:
		return "config"
	case DeployErrorPermission:
		return "permission"
	case DeployErrorNetwork:
		return "network"
	case DeployErrorValidation:
		return "validation"
	case DeployErrorReload:
		return "reload"
	default:
		return "unknown"
	}
}

// DeployPhase 部署阶段
type DeployPhase string

const (
	PhaseValidate   DeployPhase = "validate"    // 证书验证阶段
	PhaseBackup     DeployPhase = "backup"      // 备份阶段
	PhaseWriteCert  DeployPhase = "write_cert"  // 写入证书阶段
	PhaseWriteKey   DeployPhase = "write_key"   // 写入私钥阶段
	PhaseWriteChain DeployPhase = "write_chain" // 写入证书链阶段
	PhaseTest       DeployPhase = "test_config" // 测试配置阶段
	PhaseReload     DeployPhase = "reload"      // 重载服务阶段
	PhaseRollback   DeployPhase = "rollback"    // 回滚阶段
)

// StructuredDeployError 结构化部署错误
type StructuredDeployError struct {
	Type    DeployErrorType // 错误类型
	Phase   DeployPhase     // 发生阶段
	Message string          // 错误信息
	Cause   error           // 原始错误
}

func (e *StructuredDeployError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Type, e.Phase, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Type, e.Phase, e.Message)
}

func (e *StructuredDeployError) Unwrap() error {
	return e.Cause
}

// IsPermanentDeployError 判断部署错误是否为"重试不可能自愈、必须重新 setup"的永久性错误。
//
// 只有绑定配置本身有问题才算永久：
//   - Config@write_cert —— Docker 绑定校验不通过 / 创建部署器失败
//   - Validation@validate —— 证书或私钥根本不匹配
//
// 其余一律按可重试处理，交给 daemon 每日重试并上报，触顶后转入 stale 告警。
// 注意这不等于"一定会自愈"：Permission 类错误多半要人工介入，但禁用绑定会让
// daemon 永不接手、站点静默过期，保持可重试至少能持续暴露问题。
// 非结构化错误无法判定根因，同样按可重试处理（宁可多重试，不可静默丢弃）。
func IsPermanentDeployError(err error) bool {
	var se *StructuredDeployError
	if !stderrors.As(err, &se) {
		return false
	}
	switch {
	case se.Type == DeployErrorConfig && se.Phase == PhaseWriteCert:
		return true
	case se.Type == DeployErrorValidation && se.Phase == PhaseValidate:
		return true
	default:
		return false
	}
}

// NewStructuredDeployError 创建结构化部署错误
func NewStructuredDeployError(errType DeployErrorType, phase DeployPhase, msg string, cause error) *StructuredDeployError {
	return &StructuredDeployError{
		Type:    errType,
		Phase:   phase,
		Message: msg,
		Cause:   cause,
	}
}
