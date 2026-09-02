package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the vault and set the master passphrase",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("init: %w", errs.ErrNotImplemented)
		},
	}
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
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("status: %w", errs.ErrNotImplemented)
		},
	}
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