//go:build unix

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckPerms verifies that the vault home directory and every file inside it
// (plus the vault/ subtree) are owner-only (no group/world bits), refusing
// to serve or otherwise touch secrets otherwise (Batch B, SPEC 4.2 ally).
// The returned error names each offending path with a one-line chmod hint.
func CheckPerms(home string) error {
	var bad []string
	if info, err := os.Stat(home); err == nil && info.IsDir() {
		if p := info.Mode().Perm(); p&0o077 != 0 {
			bad = append(bad, fmt.Sprintf("%s: %04o (directory; fix: chmod 700 %q)", home, p, home))
		}
	}
	entries, err := os.ReadDir(home)
	if err == nil {
		for _, e := range entries {
			info, err := e.Info()
			if err != nil || e.IsDir() {
				continue
			}
			if p := info.Mode().Perm(); p&0o077 != 0 {
				bad = append(bad, fmt.Sprintf("%s: %04o (fix: chmod 600 %q)", filepath.Join(home, e.Name()), p, filepath.Join(home, e.Name())))
			}
		}
	}
	vDir := filepath.Join(home, "vault")
	if info, err := os.Stat(vDir); err == nil && info.IsDir() {
		if p := info.Mode().Perm(); p&0o077 != 0 {
			bad = append(bad, fmt.Sprintf("%s: %04o (directory; fix: chmod 700 %q)", vDir, p, vDir))
		}
		if vEntries, err := os.ReadDir(vDir); err == nil {
			for _, e := range vEntries {
				info, err := e.Info()
				if err != nil || e.IsDir() {
					continue
				}
				if p := info.Mode().Perm(); p&0o077 != 0 {
					bad = append(bad, fmt.Sprintf("%s: %04o (fix: chmod 600 %q)", filepath.Join(vDir, e.Name()), p, filepath.Join(vDir, e.Name())))
				}
			}
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("vault file permissions are too open (owner-only required):\n  %s", strings.Join(bad, "\n  "))
	}
	return nil
}
