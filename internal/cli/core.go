package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/audit"
	"github.com/ZN9-KYANT/aivault/internal/config"
	"github.com/ZN9-KYANT/aivault/internal/errs"
	"github.com/ZN9-KYANT/aivault/internal/kdf"
	"github.com/ZN9-KYANT/aivault/internal/vault"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the vault and set the master passphrase",
		RunE:  runInit,
	}
}

func runInit(cmd *cobra.Command, _ []string) error {
	home := homeDir(cmd)
	cfgPath := config.Path(home)
	if _, err := os.Stat(cfgPath); err == nil {
		return fmt.Errorf("%s already exists — vault already initialized (use aivault passwd to change the passphrase)", cfgPath)
	}

	pass, err := promptNewPassphrase()
	if err != nil {
		return err
	}
	defer kdf.Zeroize(pass)

	params, err := kdf.NewParams()
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	kek, err := kdf.DeriveKEK(pass, params)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	defer kdf.Zeroize(kek)
	blob, err := kdf.WrapVerifier(kek)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}

	// ~/.aivault and vault/ at 0700 (SPEC 3.1, 8.2).
	if err := os.MkdirAll(filepath.Join(home, "vault"), 0o700); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	cfg := config.Default()
	cfg.KDF = *params
	cfg.Verifier = hex.EncodeToString(blob)
	if err := config.Save(cfgPath, cfg); err != nil {
		return fmt.Errorf("init: %w", err)
	}

	fmt.Printf("Vault initialized at %s\n", home)
	fmt.Println("Next: aivault keys add <provider>")
	return nil
}

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the gateway server",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("serve: %w", errs.ErrNotImplemented)
		},
	}
	cmd.Flags().Int("port", 8317, "gateway port (SPEC 6.1)")
	cmd.Flags().String("config", "", "path to config file")
	return cmd
}

func newUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Prompt for the passphrase and decrypt all enabled providers into the server keyring",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("unlock: %w", errs.ErrNotImplemented)
		},
	}
}

func newLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Zeroize the server keyring immediately",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("lock: %w", errs.ErrNotImplemented)
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vault and server status",
		RunE:  runStatus,
	}
}

func runStatus(cmd *cobra.Command, _ []string) error {
	home := homeDir(cmd)
	fmt.Printf("home: %s\n", home)

	cfgPath := config.Path(home)
	if _, err := os.Stat(cfgPath); err != nil {
		fmt.Println("vault: not initialized")
		return nil
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	fmt.Println("vault: initialized")
	fmt.Printf("kdf: argon2id m=%dMiB t=%d p=%d\n", cfg.KDF.MemoryMiB, cfg.KDF.Time, cfg.KDF.Threads)
	fmt.Printf("auto-lock: %d min idle (SPEC 4.2)\n", cfg.AutoLockMins)

	st := vault.NewStore(home)
	meta, err := st.LoadMeta()
	if err != nil {
		return err
	}
	enabled := 0
	for _, pm := range meta.Providers {
		if pm.Enabled {
			enabled++
		}
	}
	fmt.Printf("providers: %d stored (%d enabled)\n", len(meta.Providers), enabled)
	fmt.Println("gateway: not running (server milestone pending)")
	return nil
}

func newPasswdCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd",
		Short: "Change the master passphrase (re-encrypts every vault file)",
		RunE:  runPasswd,
	}
}

// runPasswd implements SPEC 4.1: verify the current passphrase via the
// verifier blob, re-encrypt every vault file under the new passphrase
// (fresh age scrypt recipients), then re-wrap the verifier under a new
// Argon2id KEK. Every vault file is decrypted before anything is written
// so an unreadable file aborts with no changes made.
func runPasswd(cmd *cobra.Command, _ []string) error {
	home := homeDir(cmd)
	cfg, err := loadVaultConfig(home)
	if err != nil {
		return err
	}
	st := vault.NewStore(home)

	old, err := readSecret("Current master passphrase: ")
	if err != nil {
		return err
	}
	defer kdf.Zeroize(old)
	if err := cfg.VerifyPassphrase(old); err != nil {
		_ = audit.Log(auditPath(home), audit.Entry{Event: audit.EventAuthFail, Outcome: "wrong-passphrase"})
		if errors.Is(err, kdf.ErrWrongPassphrase) {
			return fmt.Errorf("incorrect passphrase")
		}
		return fmt.Errorf("verify passphrase: %w", err)
	}

	ids, err := vaultProviders(home)
	if err != nil {
		return err
	}
	payloads := make([]*vault.Payload, 0, len(ids))
	for _, id := range ids {
		p, err := st.Load(id, old)
		if err != nil {
			return fmt.Errorf("passwd: cannot decrypt %s (nothing changed): %w", id, err)
		}
		payloads = append(payloads, p)
	}

	newPass, err := promptNewPassphrase()
	if err != nil {
		return err
	}
	defer kdf.Zeroize(newPass)

	for i, id := range ids {
		if err := st.Save(id, newPass, payloads[i]); err != nil {
			return fmt.Errorf("passwd: re-encrypt %s: %w", id, err)
		}
	}
	for _, p := range payloads { // best-effort: drop decrypted secrets from memory
		p.APIKey = nil
		p.None = nil
	}

	// Fresh salt + params; re-wrap the verifier under the new KEK (SPEC 4.1).
	params, err := kdf.NewParams()
	if err != nil {
		return fmt.Errorf("passwd: %w", err)
	}
	kek, err := kdf.DeriveKEK(newPass, params)
	if err != nil {
		return fmt.Errorf("passwd: %w", err)
	}
	defer kdf.Zeroize(kek)
	blob, err := kdf.WrapVerifier(kek)
	if err != nil {
		return fmt.Errorf("passwd: %w", err)
	}
	cfg.KDF = *params
	cfg.Verifier = hex.EncodeToString(blob)
	if err := config.Save(config.Path(home), cfg); err != nil {
		return fmt.Errorf("passwd: %w", err)
	}

	if err := audit.Log(auditPath(home), audit.Entry{Event: audit.EventPasswd, Outcome: "ok"}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: audit log: %v\n", err)
	}
	fmt.Printf("Master passphrase changed; re-encrypted %d vault file(s)\n", len(ids))
	return nil
}

// loadVaultConfig loads config.toml with the standard not-initialized hint.
func loadVaultConfig(home string) (*config.Config, error) {
	cfg, err := config.Load(config.Path(home))
	if err != nil {
		return nil, fmt.Errorf("vault not initialized at %s (run aivault init first): %w", home, err)
	}
	return cfg, nil
}

// readAndVerifyPassphrase prompts for the master passphrase and checks it
// against the config.toml verifier blob without decrypting any vault file
// (SPEC 4.1); auth failures are audited. The caller must Zeroize the
// returned passphrase.
func readAndVerifyPassphrase(home string, cfg *config.Config, prompt string) ([]byte, error) {
	pass, err := readSecret(prompt)
	if err != nil {
		return nil, err
	}
	if err := cfg.VerifyPassphrase(pass); err != nil {
		_ = audit.Log(auditPath(home), audit.Entry{Event: audit.EventAuthFail, Outcome: "wrong-passphrase"})
		kdf.Zeroize(pass)
		if errors.Is(err, kdf.ErrWrongPassphrase) {
			return nil, fmt.Errorf("incorrect passphrase")
		}
		return nil, fmt.Errorf("verify passphrase: %w", err)
	}
	return pass, nil
}

// vaultProviders lists provider IDs with an existing vault file under
// home/vault, sorted. Passwd iterates the directory — not meta.json — so
// files missing from the index are still re-encrypted.
func vaultProviders(home string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(home, "vault"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("passwd: read vault dir: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if id, ok := strings.CutSuffix(e.Name(), vault.FileSuffix); ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}
