//go:build windows

package deployer

import (
	"fmt"
	"os"
)

// signalUSR1 Windows 不支持 SIGUSR1，返回错误
func signalUSR1(proc *os.Process) error {
	return fmt.Errorf("SIGUSR1 not supported on Windows")
}
