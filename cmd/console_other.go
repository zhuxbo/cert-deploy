//go:build !windows

package main

// supportsANSIColor 在非 Windows 平台默认支持 ANSI 颜色
// Linux、macOS 等主流终端原生支持 ANSI 转义序列
func supportsANSIColor() bool {
	return true
}
