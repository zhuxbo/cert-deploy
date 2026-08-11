package executor

import (
	"reflect"
	"testing"
)

func TestProcessIDsForExecutableFiltersExactWindowsPath(t *testing.T) {
	processes := parseWindowsProcessList("43180|D:\\Sanpin\\jk\\ui\\nginx.exe\r\n" +
		"29972|D:\\Sanpin\\jk\\ui\\nginx.exe\r\n" +
		"19856|G:\\soft\\nginx-1.26.3\\nginx.exe\r\n" +
		"bad|G:\\soft\\nginx-1.26.3\\nginx.exe\r\n")

	got := processIDsForExecutable(processes, `g:/soft/nginx-1.26.3/nginx.exe`)
	want := []int{19856}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("processIDsForExecutable() = %v, want %v", got, want)
	}
}

func TestWindowsProcessListPreservesUnknownExecutablePath(t *testing.T) {
	processes := parseWindowsProcessList("53244|\r\n")
	if len(processes) != 1 || processes[0].PID != 53244 || processes[0].ExecutablePath != "" {
		t.Fatalf("parseWindowsProcessList() = %+v，应保留路径不可读的进程", processes)
	}
	if !hasUnknownExecutablePath(processes) {
		t.Fatal("路径不可读时必须安全失败，不能当成目标进程不存在")
	}
}

func TestBroadTaskkillByImageIsNotAllowed(t *testing.T) {
	for _, command := range []string{
		"taskkill /F /T /IM nginx.exe",
		"taskkill /F /T /IM httpd.exe",
	} {
		if IsAllowed(command) {
			t.Errorf("按镜像名终止全部实例的命令不应在白名单中: %q", command)
		}
	}
}
