package config

import (
	"encoding/json"
	"strings"
)

// migrateAction 迁移操作类型
type migrateAction int

const (
	actionRename migrateAction = iota + 1 // 重命名字段（path 下 field→target）
	actionDelete                          // 删除字段（path 下的 field）
	actionMove                            // 扁平字段移入子对象（path 下 field→target 子对象的同名键，不覆盖已有值）
	actionSpread                          // 顶层字段分发到数组元素（合并语义，不覆盖已有值）
)

// migrateRule 声明式迁移规则
// 路径格式: "." 表示根，"certificates[]" 表示遍历数组元素，可嵌套如 "certificates[].bindings[]"
type migrateRule struct {
	action migrateAction
	path   string // 操作目标路径
	field  string // 源字段名
	target string // rename→新字段名; move→目标子对象名; spread→目标路径（如 "certificates[].api"）
}

// migrateRules 所有迁移规则（按添加顺序执行）
// 新增规则追加到末尾；每条规则必须幂等
var migrateRules = []migrateRule{
	{actionSpread, ".", "api", "certificates[].api"},
	{actionRename, "certificates[].bindings[]", "site_name", "server_name"},
	{actionDelete, "certificates[].api", "callback_url", ""},
}

// migrateConfig 检查并迁移配置
// 遍历所有规则，返回迁移后的数据和是否发生变更
func migrateConfig(data []byte) ([]byte, bool, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return data, false, err
	}

	changed := false
	for _, rule := range migrateRules {
		if applyRule(raw, rule) {
			changed = true
		}
	}

	// 证书生命周期状态迁移（deploy-spec §3.4）
	if normalizeCertLifecycle(raw) {
		changed = true
	}

	// 递归补齐默认值
	if fillDefaults(raw) {
		changed = true
	}

	if !changed {
		return data, false, nil
	}

	newData, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return data, false, err
	}
	return newData, true, nil
}

// applyRule 分发执行迁移规则
func applyRule(root map[string]interface{}, rule migrateRule) bool {
	switch rule.action {
	case actionRename:
		return applyRename(root, rule.path, rule.field, rule.target)
	case actionDelete:
		return applyDelete(root, rule.path, rule.field)
	case actionMove:
		return applyMove(root, rule.path, rule.field, rule.target)
	case actionSpread:
		return applySpread(root, rule.field, rule.target)
	}
	return false
}

// applyRename 在 path 匹配的所有节点上，将 oldKey 重命名为 newKey
func applyRename(root map[string]interface{}, path, oldKey, newKey string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		val, has := node[oldKey]
		if !has {
			continue
		}
		if _, hasNew := node[newKey]; !hasNew {
			node[newKey] = val
		}
		delete(node, oldKey)
		changed = true
	}
	return changed
}

// applyDelete 在 path 匹配的所有节点上，删除 key
func applyDelete(root map[string]interface{}, path, key string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		if _, has := node[key]; has {
			delete(node, key)
			changed = true
		}
	}
	return changed
}

// applyMove 将 path 匹配节点的扁平字段移入子对象
// 例如：path=".", field="api_url", target="api" → root["api_url"] 移入 root["api"]["api_url"]
// 目标子对象不存在时自动创建，已有同名键时不覆盖
func applyMove(root map[string]interface{}, path, field, target string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		val, has := node[field]
		if !has {
			continue
		}
		// 确保目标子对象存在
		sub, ok := node[target].(map[string]interface{})
		if !ok {
			sub = make(map[string]interface{})
			node[target] = sub
		}
		// 仅在子对象中不存在同名键时写入
		if _, has := sub[field]; !has {
			sub[field] = val
		}
		delete(node, field)
		changed = true
	}
	return changed
}

// applySpread 将根节点的 sourceKey 字段分发到 targetPath 指向的每个数组元素
// 合并语义：仅补全目标节点中缺失的字段，不覆盖已有值
// 分发完成后删除源字段
func applySpread(root map[string]interface{}, sourceKey, targetPath string) bool {
	source, ok := root[sourceKey]
	if !ok {
		return false
	}
	sourceMap, ok := source.(map[string]interface{})
	if !ok {
		delete(root, sourceKey)
		return true
	}
	// 空 map 直接删除
	if len(sourceMap) == 0 {
		delete(root, sourceKey)
		return true
	}

	// 解析目标路径：parentPath 定位数组元素，field 是写入的字段名
	parentPath, field := splitTargetPath(targetPath)
	nodes := resolvePath(root, parentPath)

	for _, node := range nodes {
		existing, hasExisting := node[field]
		if !hasExisting {
			node[field] = copyMap(sourceMap)
			continue
		}
		existingMap, ok := existing.(map[string]interface{})
		if !ok {
			continue
		}
		// 合并：仅补全缺失字段
		for k, v := range sourceMap {
			if _, has := existingMap[k]; !has {
				existingMap[k] = v
			}
		}
	}

	delete(root, sourceKey)
	return true
}

// normalizeCertLifecycle 迁移证书生命周期状态（deploy-spec §3.4，均幂等）：
//   - 旧非法 IP 配置（IP+pull 或 IP+delegation）→ policy_blocked_needs_setup（不自动改配置、不计数、不回调）
//   - 旧计数 >= 10 → CAPPED(legacy)，升级即静默，不补发历史事件
//   - 旧 pending 状态 → processing（保留私钥与订单信息）
//
// 部署计数为新字段，默认 0，不从旧混合计数推断。三类判定优先级：非法 IP > 旧计数触顶 > pending 归一。
func normalizeCertLifecycle(root map[string]interface{}) bool {
	globalMode := RenewModePull
	if sched, ok := getMap(root, "schedule"); ok {
		if m, ok := sched["renew_mode"].(string); ok && m != "" {
			globalMode = m
		}
	}

	changed := false
	for _, cert := range resolvePath(root, "certificates[]") {
		meta, _ := getMap(cert, "metadata")

		curState := ""
		if meta != nil {
			curState, _ = meta["last_issue_state"].(string)
		}

		// 已是终止态（新版运行时已记录 CAPPED/EXPIRED/policy_blocked 及其阶段）：
		// 迁移不重复归一，避免覆盖运行时记录的触顶阶段（issue/deploy）为 legacy。
		if isRawTerminalState(curState) {
			continue
		}

		// 有效续签模式：证书级优先，回退全局
		effMode := globalMode
		if m, ok := cert["renew_mode"].(string); ok && m != "" {
			effMode = m
		}
		validation, _ := cert["validation_method"].(string)
		illegalIP := ContainsIPDomain(rawStringSlice(cert, "domains")) &&
			(effMode != RenewModeLocal || validation == ValidationMethodDelegation)

		var targetState, targetPhase string
		switch {
		case illegalIP:
			targetState = IssueStatePolicyBlocked
		case rawNumField(meta, "issue_retry_count") >= AttemptCap:
			targetState = IssueStateCapped
			targetPhase = CappedPhaseLegacy
		case curState == "pending":
			targetState = IssueStateProcessing
		}

		if targetState == "" {
			continue
		}
		if meta == nil {
			meta = make(map[string]interface{})
			cert["metadata"] = meta
		}
		if curState != targetState {
			meta["last_issue_state"] = targetState
			changed = true
		}
		if targetPhase != "" {
			if cp, _ := meta["capped_phase"].(string); cp != targetPhase {
				meta["capped_phase"] = targetPhase
				changed = true
			}
		}
	}
	return changed
}

// isRawTerminalState 判断状态是否为终止态（运行时权威，迁移不再归一）
func isRawTerminalState(state string) bool {
	switch state {
	case IssueStateCapped, IssueStateExpired, IssueStatePolicyBlocked:
		return true
	}
	return false
}

// rawStringSlice 从原始 map 读取字符串切片字段（非字符串元素跳过）
func rawStringSlice(m map[string]interface{}, key string) []string {
	var out []string
	for _, v := range getSlice(m, key) {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// rawNumField 从原始 map 读取数值字段（JSON 数字为 float64；缺失或非数值返回 0）
func rawNumField(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	if f, ok := m[key].(float64); ok {
		return f
	}
	return 0
}

// --- 默认值填充 ---

// configDefaults 当前版本的默认结构（仅包含需要补齐的顶层和 schedule 字段）
// 不包含 certificates 等数组内容——数组元素由 setup 流程创建
var configDefaults = map[string]interface{}{
	"schedule": map[string]interface{}{
		"renew_before_days": float64(DefaultRenewBeforeDays),
		"renew_mode":        RenewModePull,
	},
}

// fillDefaults 递归对比当前数据与默认结构，补齐缺失字段
// 仅添加不存在的键，不覆盖已有值
func fillDefaults(raw map[string]interface{}) bool {
	return mergeDefaults(raw, configDefaults)
}

// mergeDefaults 递归合并默认值到目标 map，返回是否有变更
func mergeDefaults(dst, defaults map[string]interface{}) bool {
	changed := false
	for k, defVal := range defaults {
		existing, has := dst[k]
		if !has {
			dst[k] = defVal
			changed = true
			continue
		}
		// 如果默认值和已有值都是 map，递归合并
		defMap, defIsMap := defVal.(map[string]interface{})
		existMap, existIsMap := existing.(map[string]interface{})
		if defIsMap && existIsMap {
			if mergeDefaults(existMap, defMap) {
				changed = true
			}
		}
	}
	return changed
}

// --- 路径解析 ---

// resolvePath 解析路径，返回所有匹配的 map 节点
// 路径格式: "." = 根节点，"key[]" = 遍历数组，"key" = 进入子 map，用 "." 分隔
func resolvePath(root map[string]interface{}, path string) []map[string]interface{} {
	if path == "." {
		return []map[string]interface{}{root}
	}

	current := []map[string]interface{}{root}
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		var next []map[string]interface{}
		if strings.HasSuffix(part, "[]") {
			key := strings.TrimSuffix(part, "[]")
			for _, node := range current {
				for _, elem := range getSlice(node, key) {
					if m, ok := elem.(map[string]interface{}); ok {
						next = append(next, m)
					}
				}
			}
		} else {
			for _, node := range current {
				if m, ok := getMap(node, part); ok {
					next = append(next, m)
				}
			}
		}
		current = next
	}
	return current
}

// splitTargetPath 拆分目标路径为父路径和字段名
// "certificates[].api" → ("certificates[]", "api")
// "api" → (".", "api")
func splitTargetPath(target string) (parentPath, field string) {
	idx := strings.LastIndex(target, ".")
	if idx < 0 {
		return ".", target
	}
	return target[:idx], target[idx+1:]
}

// --- 辅助函数 ---

func getSlice(m map[string]interface{}, key string) []interface{} {
	v, ok := m[key]
	if !ok {
		return nil
	}
	s, ok := v.([]interface{})
	if !ok {
		return nil
	}
	return s
}

func getMap(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	result, ok := v.(map[string]interface{})
	return result, ok
}

// copyMap 浅拷贝 map（当前迁移场景值均为 string 等非引用类型，无需深拷贝）
func copyMap(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
