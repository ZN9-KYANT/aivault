//go:build unix

package server

import (
	"fmt"
	"syscall"
)

// disableCoreDumps sets RLIMIT_CORE=0 so a crash cannot spill keyring
// memory into a core file (learned from pi-llm-gateway; SPEC 8.3 ally).
// Non-fatal: callers log the failure and keep serving.
func disableCoreDumps() error {
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &old); err != nil {
		return fmt.Errorf("read RLIMIT_CORE: %w", err)
	}
	if old.Cur == 0 {
		return nil // already zero
	}
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}