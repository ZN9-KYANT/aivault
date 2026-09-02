package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read the append-only audit log (SPEC 4.5)",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("audit: %w", errs.ErrNotImplemented)
		},
	}
	cmd.Flags().Int("tail", 50, "show the last N entries")
	return cmd
}