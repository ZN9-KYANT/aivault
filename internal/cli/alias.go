package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

func newAliasCmd() *cobra.Command {
	alias := &cobra.Command{
		Use:   "alias",
		Short: "Manage model aliases with failover chains (SPEC 5)",
	}

	create := &cobra.Command{
		Use:   "create <name> --chain <provider/model,provider/model,...>",
		Short: "Create an alias mapping a virtual model name to a failover chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("alias create: %w", errs.ErrNotImplemented)
		},
	}
	create.Flags().String("chain", "", "comma-separated provider/model chain, tried in order")

	alias.AddCommand(create)
	return alias
}
