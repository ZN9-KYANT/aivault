package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

func newKeysCmd() *cobra.Command {
	keys := &cobra.Command{
		Use:   "keys",
		Short: "Manage provider API keys (SPEC 7)",
	}

	add := &cobra.Command{
		Use:   "add <provider>",
		Short: "Store an API key (via --key-stdin or hidden prompt; never as an argument)",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("keys add: %w", errs.ErrNotImplemented)
		},
	}
	add.Flags().Bool("key-stdin", false, "read the key from stdin instead of prompting")

	list := &cobra.Command{
		Use:   "list",
		Short: "List providers from meta.json (no unlock needed)",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("keys list: %w", errs.ErrNotImplemented)
		},
	}

	show := &cobra.Command{
		Use:   "show <provider>",
		Short: "Show the stored key (hint by default; requires unlock)",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("keys show: %w", errs.ErrNotImplemented)
		},
	}
	show.Flags().Bool("reveal", false, "print the full key instead of the hint")

	remove := &cobra.Command{
		Use:   "remove <provider>",
		Short: "Remove a provider's stored key",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("keys remove: %w", errs.ErrNotImplemented)
		},
	}

	rotate := &cobra.Command{
		Use:   "rotate <provider>",
		Short: "Replace a provider's key (via --key-stdin or hidden prompt)",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("keys rotate: %w", errs.ErrNotImplemented)
		},
	}
	rotate.Flags().Bool("key-stdin", false, "read the new key from stdin instead of prompting")

	keys.AddCommand(add, list, show, remove, rotate)
	return keys
}