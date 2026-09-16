package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/config"
	"github.com/ZN9-KYANT/aivault/internal/kdf"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup --out <file>",
		Short: "Write one combined age-encrypted archive of the vault (SPEC 3.1)",
		RunE:  runBackup,
	}
	cmd.Flags().String("out", "backup.age", "output archive path")
	return cmd
}

// runBackup archives the vault home (config, meta, proxy-key hashes, audit
// log, every encrypted vault file) into one age archive encrypted under the
// master passphrase (SPEC 3.1). The passphrase is verified against the
// verifier blob first, so a typo aborts before any tarball is written.
func runBackup(cmd *cobra.Command, _ []string) error {
	home := homeDir(cmd)
	cfg, err := loadVaultConfig(home)
	if err != nil {
		return err
	}
	out, _ := cmd.Flags().GetString("out")
	if out == "" {
		return fmt.Errorf("backup: --out is required")
	}

	pass, err := readAndVerifyPassphrase(home, cfg, "Master passphrase: ")
	if err != nil {
		return err
	}
	defer kdf.Zeroize(pass)

	if err := vault.Backup(home, out, pass); err != nil {
		return err
	}
	if err := audit.Log(auditPath(home), audit.Entry{Event: "backup", Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Wrote encrypted backup to %s\n", out)
	fmt.Println("The archive restores only with the master passphrase it was taken under.")
	return nil
}

func newRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore <file>",
		Short: "Restore the vault from an age-encrypted archive",
		Args:  cobra.ExactArgs(1),
		RunE:  runRestore,
	}
	cmd.Flags().Bool("force", false, "overwrite existing files without asking")
	return cmd
}

// runRestore decrypts an archive into the vault home. It refuses to clobber
// existing files unless --force is given (plus a y/N confirm), and re-prompts
// for the passphrase the archive was taken under (which may differ from the
// current one after a passwd).
func runRestore(cmd *cobra.Command, args []string) error {
	home := homeDir(cmd)
	force, _ := cmd.Flags().GetBool("force")

	if !force {
		ans, err := readLine(fmt.Sprintf("Restore into %s? Existing files are kept unless --force. Continue? (y/N) ", home))
		if err != nil {
			return err
		}
		if t := strings.ToLower(strings.TrimSpace(ans)); t != "y" && t != "yes" {
			fmt.Println("aborted — nothing restored")
			return nil
		}
	}

	pass, err := readSecret("Archive passphrase: ")
	if err != nil {
		return err
	}
	defer kdf.Zeroize(pass)

	restored, err := vault.RestoreArchive(home, args[0], pass, force)
	if err != nil {
		return err
	}
	sort.Strings(restored)

	// The archive may carry a config.toml with a different verifier — that is
	// by design (passwd history): unlock uses the restored passphrase.
	if _, cerr := config.Load(config.Path(home)); cerr != nil && !errors.Is(cerr, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "warning: restored config.toml does not parse: %v\n", cerr)
	}
	if err := audit.Log(auditPath(home), audit.Entry{Event: "restore", Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Restored %d file(s) into %s:\n", len(restored), home)
	for _, name := range restored {
		fmt.Printf("  %s\n", name)
	}
	fmt.Println("Note: the vault now uses the master passphrase the backup was taken under.")
	return nil
}
