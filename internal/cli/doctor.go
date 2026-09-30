// aivault doctor: one-command health report with no unlock required
// (Batch B; the preflight analogue of pi-llm-gateway's `gateway -check`).
package cli

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/config"
	"github.com/ZN9-KYANT/aivault/internal/proxykey"
	"github.com/ZN9-KYANT/aivault/internal/server"
	"github.com/ZN9-KYANT/aivault/internal/vault"
	"github.com/ZN9-KYANT/aivault/internal/version"
)

// verdicts for the final doctor line.
const (
	doctorPass = "PASS"
	doctorWarn = "WARN"
	doctorFail = "FAIL"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run a health report of the vault home (no unlock needed)",
		RunE:  runDoctor,
	}
}

type doctorReport struct {
	warnings []string
	failures []string
}

func (d *doctorReport) ok(label string, format string, args ...any) {
	fmt.Printf("%-12s OK    %s\n", label+":", fmt.Sprintf(format, args...))
}
func (d *doctorReport) warn(label string, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	d.warnings = append(d.warnings, msg)
	fmt.Printf("%-12s WARN  %s\n", label+":", msg)
}
func (d *doctorReport) fail(label string, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	d.failures = append(d.failures, msg)
	fmt.Printf("%-12s FAIL  %s\n", label+":", msg)
}

// runDoctor aggregates checks that never require the master passphrase:
// config, meta/file agreement, permissions, proxy keys, the audit chain,
// key ages, and the live gateway. The command fails (exit 1) only when a
// hard problem is found; warnings keep the exit at zero for scripts.
func runDoctor(cmd *cobra.Command, _ []string) error {
	home := homeDir(cmd)
	rep := &doctorReport{}
	fmt.Printf("aivault doctor — home %s (version %s)\n", home, version.Version)

	st := vault.NewStore(home)
	cfgPath := config.Path(home)
	cfg, cfgErr := config.Load(cfgPath)
	cfgOK := cfgErr == nil

	// 1. Config.
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		rep.fail("config", "not initialized at %s (run aivault init)", cfgPath)
	} else if !cfgOK {
		rep.fail("config", "unreadable: %v", cfgErr)
	} else {
		rep.ok("config", "port=%d auto-lock=%dmin failover=%v egress=%v auth-limit=%s",
			cfg.Server.Port, cfg.AutoLockMins, cfg.Failover, cfg.EgressAllowlist, authLimitLabel(cfg.AuthMaxFailures))
	}

	// 2. Meta vs vault files (dangling entries, ghost files).
	meta, metaErr := st.LoadMeta()
	if metaErr != nil {
		rep.fail("meta.json", "unreadable: %v", metaErr)
	} else {
		none, dangling := 0, 0
		var ghost []string
		for id, pm := range meta.Providers {
			if pm.Kind == string(vault.KindNone) {
				none++
				continue
			}
			if !hasVaultFile(st, id) {
				dangling++
				rep.warn("vault files", "%s: meta entry without vault file (dangling entry)", id)
			}
		}
		if onDisk, err := vaultProviders(home); err == nil {
			for _, id := range onDisk {
				if _, ok := meta.Providers[id]; !ok {
					ghost = append(ghost, id)
				}
			}
		}
		for _, id := range ghost {
			rep.warn("vault files", "vault file without meta entry (ghost file): %s", id)
		}
		if dangling == 0 && len(ghost) == 0 {
			rep.ok("meta/files", "%d registered provider(s) (%d credential-free, 0 orphans)",
				len(meta.Providers), none)
		}
	}

	// 3. Permissions (hard on POSIX; documented no-op on Windows).
	if perr := vault.CheckPerms(home); perr != nil {
		rep.fail("permissions", "%v", perr)
	} else {
		rep.ok("permissions", "owner-only")
	}

	// 4. Proxy keys (hashes only).
	if pks, err := proxykey.NewStore(proxykey.DefaultPath(home)).List(); err != nil {
		rep.fail("proxy keys", "%v", err)
	} else {
		active, revoked := 0, 0
		for _, p := range pks {
			if p.Revoked {
				revoked++
			} else {
				active++
			}
		}
		rep.ok("proxy keys", "%d active, %d revoked", active, revoked)
	}

	// 5. Audit log + tamper-evident chain.
	if res, err := audit.Verify(auditPath(home)); err != nil {
		rep.fail("audit", "%v", err)
	} else if !res.OK {
		rep.fail("audit", "tamper-evident chain BROKEN — %s", res.Detail)
	} else {
		rep.ok("audit", "chain OK (%d entries, %d chained, %d legacy)", res.Entries, res.ChainLen, res.Legacy)
	}

	// 6. Key ages (only when the config loaded).
	if cfgOK && cfg.KeyMaxAgeDays > 0 {
		cut := time.Now().UTC().AddDate(0, 0, -cfg.KeyMaxAgeDays)
		var aged []string
		for id, pm := range meta.Providers {
			if pm.Kind == string(vault.KindNone) || pm.UpdatedAt.IsZero() || pm.UpdatedAt.After(cut) {
				continue
			}
			aged = append(aged, fmt.Sprintf("%s (%d days)", id, int(time.Since(pm.UpdatedAt).Hours()/24)))
		}
		sort.Strings(aged)
		for _, a := range aged {
			rep.warn("key age", "rotate: %s (max %d days)", a, cfg.KeyMaxAgeDays)
		}
		if len(aged) == 0 {
			rep.ok("key age", "all within %d days", cfg.KeyMaxAgeDays)
		}
	}

	// 7. Live gateway.
	sock := server.SocketPath(home)
	if stt, err := server.NewClient(sock).Status(); err == nil {
		if stt.Locked {
			rep.ok("gateway", "running (locked) on %s", sock)
		} else {
			rep.ok("gateway", "running (unlocked, %d provider(s), idle %.1f min)", stt.Providers, stt.IdleMinutes)
		}
	} else {
		rep.ok("gateway", "not running")
	}

	// Verdict: PASS with zero findings, WARN with only warnings, FAIL with
	// at least one failure (non-zero exit for scripts).
	switch {
	case len(rep.failures) > 0:
		fmt.Printf("doctor: %s (%d failure(s), %d warning(s))\n", doctorFail, len(rep.failures), len(rep.warnings))
		return fmt.Errorf("doctor: %s", doctorFail)
	case len(rep.warnings) > 0:
		fmt.Printf("doctor: %s (%d warning(s))\n", doctorWarn, len(rep.warnings))
	default:
		fmt.Printf("doctor: %s\n", doctorPass)
	}
	return nil
}

// authLimitLabel renders the auth_max_failures knob for the config line.
func authLimitLabel(n int) string {
	if n <= 0 {
		return "off"
	}
	return fmt.Sprintf("%d/min", n)
}
