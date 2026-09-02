package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup --out <file>",
		Short: "Write one combined age-encrypted archive of the vault (SPEC 3.1)",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("backup: %w", errs.ErrNotImplemented)
		},
	}
	cmd.Flags().String("out", "backup.age", "output archive path")
	return cmd
}

func newRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <file>",
		Short: "Restore the vault from an age-encrypted archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("restore: %w", errs.ErrNotImplemented)
		},
	}
}
