//go:build !windows

package deployer

import (
	"os"
	"syscall"
)

// signalUSR1 向进程发送 SIGUSR1 信号（Unix 专用）
func signalUSR1(proc *os.Process) error {
	return proc.Signal(syscall.SIGUSR1)
}
