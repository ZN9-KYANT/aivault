package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

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
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("passwd: %w", errs.ErrNotImplemented)
		},
	}
}
