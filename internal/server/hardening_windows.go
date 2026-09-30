//go:build windows

package server

// disableCoreDumps is a Windows no-op: Windows Error Reporting dumps are
// controlled per-application via registry/WER policy, not RLIMIT_CORE. The
// 0700 home directory and WER default exclusions are the local mitigations.
func disableCoreDumps() error { return nil }
