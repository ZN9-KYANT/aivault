package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

func newProxyKeyCmd() *cobra.Command {
	pk := &cobra.Command{
		Use:   "proxykey",
		Short: "Manage downstream proxy keys (SPEC 4.4)",
	}

	create := &cobra.Command{
		Use:   "create --name <name>",
		Short: "Issue a new proxy key (plaintext shown exactly once)",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("proxykey create: %w", errs.ErrNotImplemented)
		},
	}
	create.Flags().String("name", "", "human-readable key name")
	create.Flags().StringSlice("providers", nil, "allowed providers")
	create.Flags().Int("rpm", 0, "per-minute request limit")
	create.Flags().Float64("max-usd/day", 0, "daily spend cap in USD")

	list := &cobra.Command{
		Use:   "list",
		Short: "List proxy keys (hashes only, never plaintext)",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("proxykey list: %w", errs.ErrNotImplemented)
		},
	}

	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a proxy key",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("proxykey revoke: %w", errs.ErrNotImplemented)
		},
	}

	pk.AddCommand(create, list, revoke)
	return pk
}