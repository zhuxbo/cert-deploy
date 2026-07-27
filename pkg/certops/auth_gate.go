package certops

import (
	"fmt"
	"sort"
	"sync"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
)

// authBlock 一次 token 级拒绝的记录
type authBlock struct {
	code       string
	retryAfter int
}

// desc 日志文案：error_code 必须出现在客户端错误文本里（deploy-spec §2.2），
// 它是运维判断「为何停止」的唯一线索——服务端 msg 可能只是「Unauthorized」，
// 而 token_disabled 与 ip_not_allowed 的处置完全不同。
func (b authBlock) desc() string {
	if b.retryAfter > 0 {
		return fmt.Sprintf("%s，约 %d 秒后可重试", b.code, b.retryAfter)
	}
	return b.code
}

// authGate 轮内 token 黑名单，实现 deploy-spec §2.2「整批共通」组的「本轮停止」。
//
// 按 (url, token) 而非全局拉黑：本项目每张证书自带 api 配置，同一台机器可能混用多个
// token 或多个 API 地址，别的 token 应照常跑完本轮。
//
// 只在内存里活一轮：拒绝语义是「本轮停止」而非永久停止，下一个调度周期必须重新尝试，
// 因此不落盘、不写入证书元数据。真正的永久边界由计数触顶与无进展时限提供（spec §3.2）。
// token 原文仅作 map key 使用，不写盘、不进日志。
type authGate struct {
	mu      sync.Mutex
	blocked map[string]authBlock
	// skipped 本轮因命中黑名单而跳过的证书数，供结束时汇总
	skipped int
}

// tokenKey 黑名单键：同一 (url, token) 共享服务端的认证与限流判定
func tokenKey(api config.APIConfig) string {
	return api.URL + "\x00" + api.Token
}

// record 把整批共通失败记入黑名单，返回 err 是否属于整批共通组。
// err 为 nil、未携带 error_code 或属于单条目组时不动作并返回 false。
// 首次原因优先保留：后续调用拿到的可能是同一问题的另一种表述，首个才对应真正的触发点。
func (g *authGate) record(api config.APIConfig, err error) bool {
	if err == nil {
		return false
	}
	code := errors.ErrorCodeOf(err)
	if !fetcher.IsAuthBlockErrorCode(code) {
		return false
	}
	key := tokenKey(api)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blocked == nil {
		g.blocked = make(map[string]authBlock)
	}
	if _, exists := g.blocked[key]; !exists {
		g.blocked[key] = authBlock{code: code, retryAfter: errors.RetryAfterOf(err)}
	}
	return true
}

// blockedBy 查询该 token 本轮是否已被服务端拒绝
func (g *authGate) blockedBy(api config.APIConfig) (authBlock, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	blk, ok := g.blocked[tokenKey(api)]
	return blk, ok
}

// markSkipped 累计一次因黑名单而跳过的证书
func (g *authGate) markSkipped() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.skipped++
}

// summary 本轮汇总：返回被拒 token 数、去重排序的 error_code 列表与跳过证书数。
// 列表进汇总文案而不只给数量：error_code 是运维判断「为何停止」的唯一线索（spec §2.2），
// 而被跳过的证书只记 debug，不该逼人去翻首张证书的日志才知道原因。
func (g *authGate) summary() (tokens int, codes []string, skipped int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	seen := make(map[string]bool, len(g.blocked))
	for _, blk := range g.blocked {
		if !seen[blk.code] {
			seen[blk.code] = true
			codes = append(codes, blk.code)
		}
	}
	sort.Strings(codes)
	return len(g.blocked), codes, g.skipped
}

// reset 每轮开始清空。不重置等于把「本轮停止」升级成「永久停止」，
// token 换发后再也不会被重试。
func (g *authGate) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked = nil
	g.skipped = 0
}
