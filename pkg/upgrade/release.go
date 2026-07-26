// Package upgrade 版本升级模块
package upgrade

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/zhuxbo/sslctl/pkg/config"
)

// 版本信息配置常量
const (
	maxReleaseInfoSize = 1 * 1024 * 1024 // 最大版本信息大小 1MB
)

// VersionInfo 版本详细信息
type VersionInfo struct {
	Version    string            `json:"version"`               // 版本号（如 "1.2.0"，不带 v 前缀）
	ReleasedAt string            `json:"released_at,omitempty"` // 发布日期（YYYY-MM-DD）
	Checksums  map[string]string `json:"checksums"`             // 按文件名索引的 SHA256 哈希
	Signatures map[string]string `json:"signatures,omitempty"`  // 按文件名索引的 Ed25519 签名
}

// ChannelInfo 通道版本信息
type ChannelInfo struct {
	Latest   string        `json:"latest"`   // 该通道最新版本号（不带 v 前缀）
	Versions []VersionInfo `json:"versions"` // 版本列表，按发布时间倒序，最多 5 条
}

// ReleaseIndex 发布索引（releases.json 顶层结构，通道名为 key）
type ReleaseIndex map[string]*ChannelInfo

// FetchReleaseInfo 获取远程版本信息
func FetchReleaseInfo(baseURL string) (ReleaseIndex, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, &ErrReleaseSource{Msg: "未配置升级地址，请运行 sslctl upgrade 在交互终端中输入，或使用安装脚本升级"}
	}
	// 安全校验：强制 HTTPS（与 downloadBinaryWithClient 保持一致）
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, &ErrReleaseSource{Msg: "升级地址必须使用 HTTPS 协议"}
	}
	return fetchReleaseInfoFrom(baseURL+"/releases.json", secureHTTPClient())
}

// fetchReleaseInfoFrom 内部实现，接受 URL 和 client 参数（便于测试）
func fetchReleaseInfoFrom(url string, client *http.Client) (ReleaseIndex, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, &ErrReleaseSource{Msg: fmt.Sprintf("获取版本信息失败: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &ErrReleaseSource{Msg: fmt.Sprintf("获取版本信息失败: HTTP %d", resp.StatusCode)}
	}

	// 限制响应体大小，防止恶意服务器返回超大 JSON
	limitReader := io.LimitReader(resp.Body, maxReleaseInfoSize)
	var index ReleaseIndex
	if err := json.NewDecoder(limitReader).Decode(&index); err != nil {
		return nil, fmt.Errorf("解析版本信息失败: %w", err)
	}

	return index, nil
}

// ResolveTarget 确定目标版本
// 直接读取 channel 对应通道的 Latest
// 指定 targetVersion 时自动检测通道（含 "-" 为 dev，否则 main）
func ResolveTarget(targetVersion, channel string, index ReleaseIndex) (string, string, error) {
	if targetVersion != "" {
		target := NormalizeVersion(targetVersion)
		ch := channel
		if ch == "" {
			if strings.Contains(target, "-") {
				ch = "dev"
			} else {
				ch = "main"
			}
		}
		if err := config.ValidateChannel(ch); err != nil {
			return "", "", err
		}
		return target, ch, nil
	}

	ch := channel
	if ch == "" {
		ch = "main"
	}
	if err := config.ValidateChannel(ch); err != nil {
		return "", "", err
	}

	chInfo := index[ch]
	if chInfo == nil {
		return "", "", fmt.Errorf("通道 %q 不存在", ch)
	}

	if chInfo.Latest != "" {
		return NormalizeVersion(chInfo.Latest), ch, nil
	}
	if len(chInfo.Versions) > 0 {
		return NormalizeVersion(chInfo.Versions[0].Version), ch, nil
	}
	return "", "", &ErrReleaseSource{Msg: fmt.Sprintf("通道 %q 中未找到可用版本", ch)}
}

// FindVersion 在指定通道的版本列表中查找指定版本
func (index ReleaseIndex) FindVersion(channel, version string) *VersionInfo {
	chInfo := index[channel]
	if chInfo == nil {
		return nil
	}
	normalized := NormalizeVersion(version)
	for i := range chInfo.Versions {
		if NormalizeVersion(chInfo.Versions[i].Version) == normalized {
			return &chInfo.Versions[i]
		}
	}
	return nil
}

// GetChecksum 获取指定版本中指定文件的校验和
func (index ReleaseIndex) GetChecksum(channel, version, filename string) string {
	v := index.FindVersion(channel, version)
	if v == nil || v.Checksums == nil {
		return ""
	}
	return v.Checksums[filename]
}

// GetSignature 获取指定文件的签名
func (index ReleaseIndex) GetSignature(channel, version, filename string) string {
	v := index.FindVersion(channel, version)
	if v == nil || v.Signatures == nil {
		return ""
	}
	return v.Signatures[filename]
}

// NormalizeVersion 规范化版本号（确保带 v 前缀）
func NormalizeVersion(ver string) string {
	if !strings.HasPrefix(ver, "v") {
		return "v" + ver
	}
	return ver
}

// CompareVersions 比较两个语义化版本号
// 返回: -1 (a < b), 0 (a == b), 1 (a > b)
// 遵循 semver 规范：主版本号优先比较，pre-release 版本低于同号正式版；
// pre-release 内按 `.` 拆分逐段比较，纯数字段走数值比较，数字段低于字母段。
func CompareVersions(a, b string) int {
	parseVer := func(v string) ([3]int, string) {
		v = strings.TrimPrefix(v, "v")
		// 剥离 build metadata（semver: +xxx 不参与排序）
		if idx := strings.Index(v, "+"); idx >= 0 {
			v = v[:idx]
		}
		pre := ""
		if idx := strings.Index(v, "-"); idx >= 0 {
			pre = v[idx+1:]
			v = v[:idx]
		}
		parts := strings.Split(v, ".")
		var result [3]int
		for i := 0; i < 3 && i < len(parts); i++ {
			n, _ := strconv.Atoi(parts[i])
			result[i] = n
		}
		return result, pre
	}

	va, preA := parseVer(a)
	vb, preB := parseVer(b)

	// 先比较主版本号
	for i := 0; i < 3; i++ {
		if va[i] < vb[i] {
			return -1
		}
		if va[i] > vb[i] {
			return 1
		}
	}

	return comparePreRelease(preA, preB)
}

// comparePreRelease 按 semver 规范比较 pre-release 字段。
// 空字符串视为正式版，正式版高于任何 pre-release。
func comparePreRelease(a, b string) int {
	if a == b {
		return 0
	}
	// 有 pre-release 的版本 < 无 pre-release 的版本
	if a == "" {
		return 1
	}
	if b == "" {
		return -1
	}
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	n := len(aParts)
	if len(bParts) < n {
		n = len(bParts)
	}
	for i := 0; i < n; i++ {
		aNum, aIsNum := parseNumericIdent(aParts[i])
		bNum, bIsNum := parseNumericIdent(bParts[i])
		switch {
		case aIsNum && bIsNum:
			if aNum != bNum {
				if aNum < bNum {
					return -1
				}
				return 1
			}
		case aIsNum && !bIsNum:
			// 数字标识符低于字母数字标识符
			return -1
		case !aIsNum && bIsNum:
			return 1
		default:
			if aParts[i] != bParts[i] {
				if aParts[i] < bParts[i] {
					return -1
				}
				return 1
			}
		}
	}
	// 所有共同段相等，字段更多者更高（如 alpha < alpha.1）
	if len(aParts) < len(bParts) {
		return -1
	}
	if len(aParts) > len(bParts) {
		return 1
	}
	return 0
}

// parseNumericIdent 判断 pre-release 字段是否为纯数字标识符。
func parseNumericIdent(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}
