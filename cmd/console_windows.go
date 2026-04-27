//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// vtEnabled 标识当前控制台是否支持 ANSI 虚拟终端序列
// 仅在 Windows 10 / Server 2016+ 且 SetConsoleMode 开启 VT 后回读验证通过时才为 true
var vtEnabled bool

// supportsANSIColor 返回当前环境是否支持 ANSI 颜色输出
// Windows 上等价于 vtEnabled；非 Windows 平台由 console_other.go 直接返回 true
func supportsANSIColor() bool {
	return vtEnabled
}

func init() {
	setupWindowsConsole()
}

// consoleDebugf 当环境变量 SSLCTL_CONSOLE_DEBUG=1 时向 stderr 打 ASCII 诊断行
// 诊断输出直接走 stderr，不经任何编码转换，便于排查老 Windows 控制台问题
func consoleDebugf(format string, args ...interface{}) {
	if os.Getenv("SSLCTL_CONSOLE_DEBUG") != "1" {
		return
	}
	fmt.Fprintf(os.Stderr, "[console-debug] "+format+"\n", args...)
}

// setupWindowsConsole 仅做一件事：在 Windows 10 / Server 2016+ 上开启虚拟终端处理
// 并把控制台代码页设为 UTF-8，便于和现代工具链互操作
//
// 老系统（Server 2012 R2 等，无 VT 支持）**完全不动控制台状态**。
// 原因：任何 SetConsoleOutputCP 调用都会触发 Windows 根据新代码页自动选择字体，
// 覆盖用户手动设置的 TrueType 字体，导致 CJK 字符重新变成空白或乱码。
// Go 的 WriteConsoleW 以 UTF-16 直接写入，用户只要把字体改成 TrueType 或
// 通过 chcp 把代码页切到匹配系统 OEM 的值，中文就能正常显示。
func setupWindowsConsole() {
	handle, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		consoleDebugf("GetStdHandle failed: %v", err)
		return
	}

	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		consoleDebugf("stdout not a console (pipe/file)")
		return
	}
	consoleDebugf("stdout is console, mode=0x%x", mode)

	// 尝试启用 VT 处理
	// 注意：SetConsoleMode 在老 Windows 上对未知标志位的行为不一致，
	// 有的版本返回 ERROR_INVALID_PARAMETER，有的版本静默接受但不实际处理 VT。
	// 无论哪种情况，我们都只在"写入成功且回读验证 VT 位确实被接受"时才认为 VT 可用。
	newMode := mode | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if err := windows.SetConsoleMode(handle, newMode); err != nil {
		consoleDebugf("SetConsoleMode(VT) failed: %v", err)
		return
	}
	var verify uint32
	if err := windows.GetConsoleMode(handle, &verify); err != nil {
		consoleDebugf("GetConsoleMode verify failed: %v", err)
		return
	}
	if verify&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
		consoleDebugf("VT bit not persisted after SetConsoleMode, treating as old console")
		return
	}

	// Windows 10+ 确认 VT 可用：允许 ANSI 颜色输出，并设置 UTF-8 代码页
	vtEnabled = true
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	// 失败非致命：CP 切换失败不影响 VT 已开启的 ANSI 输出能力
	_, _, _ = kernel32.NewProc("SetConsoleOutputCP").Call(65001)
	_, _, _ = kernel32.NewProc("SetConsoleCP").Call(65001)
	consoleDebugf("VT processing enabled, console CP set to 65001")
}
