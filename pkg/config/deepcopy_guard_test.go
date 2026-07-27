// Package config 深拷贝完整性的结构守卫
package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// deepCopiedRefFields 是 copyConfig 已显式深拷贝的引用类型字段路径。
// 新增 slice / map / 指针字段时必须同时更新 copyConfig 与本表，
// 否则 Load() 返回的"深拷贝"会与内部缓存共享底层数组，破坏并发安全保证。
var deepCopiedRefFields = []string{
	"Config.Certificates",
	"Config.Certificates[].Domains",
	"Config.Certificates[].Bindings",
	"Config.Certificates[].Bindings[].Docker",
	"Config.Certificates[].Metadata.FailedBindings",
	"Config.Certificates[].Metadata.StaleBindings",
	"Config.Certificates[].Metadata.ValidationFiles",
}

// TestDeepCopyRefFieldsCovered 反射枚举 Config 树上的全部引用类型字段，
// 与 copyConfig 已处理的清单比对。新增字段而忘记深拷贝时本用例会红，
// 且直接指出漏掉的字段路径——手写断言做不到这一点。
func TestDeepCopyRefFieldsCovered(t *testing.T) {
	found := collectRefFields("Config", reflect.TypeOf(Config{}), map[reflect.Type]bool{})

	want := make(map[string]bool, len(deepCopiedRefFields))
	for _, f := range deepCopiedRefFields {
		want[f] = true
	}

	var missing []string
	for _, f := range found {
		if !want[f] {
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("以下引用类型字段未登记深拷贝，请同步更新 copyConfig 与 deepCopiedRefFields:\n  %s",
			strings.Join(missing, "\n  "))
	}

	got := make(map[string]bool, len(found))
	for _, f := range found {
		got[f] = true
	}
	var stale []string
	for _, f := range deepCopiedRefFields {
		if !got[f] {
			stale = append(stale, f)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("deepCopiedRefFields 中的字段已不存在，请清理:\n  %s", strings.Join(stale, "\n  "))
	}
}

// collectRefFields 递归收集 slice / map / 指针字段的路径。
// 显式跳过 time.Time 与 time.Location：CertMetadata 有多个 time.Time 字段，
// 它们内部含指针但按值语义使用，不跳过会淹没在假阳性里。
func collectRefFields(path string, t reflect.Type, visiting map[reflect.Type]bool) []string {
	if t == reflect.TypeOf(time.Time{}) || t == reflect.TypeOf(time.Location{}) {
		return nil
	}
	if visiting[t] {
		return nil // 自引用类型，避免无限递归
	}

	switch t.Kind() {
	case reflect.Struct:
		visiting[t] = true
		defer delete(visiting, t)
		var out []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue // 未导出字段不参与配置深拷贝
			}
			out = append(out, collectRefFields(path+"."+f.Name, f.Type, visiting)...)
		}
		return out
	case reflect.Slice, reflect.Map, reflect.Pointer:
		out := []string{path}
		elem := t.Elem()
		suffix := "[]"
		if t.Kind() == reflect.Pointer {
			suffix = ""
		}
		return append(out, collectRefFields(path+suffix, elem, visiting)...)
	default:
		return nil
	}
}
