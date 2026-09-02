package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/errs"
)

func newProvidersCmd() *cobra.Command {
	providers := &cobra.Command{
		Use:   "providers",
		Short: "Inspect and manage providers (SPEC 5, 7)",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List configured providers from meta.json",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("providers list: %w", errs.ErrNotImplemented)
		},
	}

	models := &cobra.Command{
		Use:   "models",
		Short: "List cached /models per provider",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("providers models: %w", errs.ErrNotImplemented)
		},
	}

	test := &cobra.Command{
		Use:   "test <provider>",
		Short: "Test a provider's stored credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("providers test: %w", errs.ErrNotImplemented)
		},
	}

	add := &cobra.Command{
		Use:   "add <id> --base-url <url>",
		Short: "Add a custom provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("providers add: %w", errs.ErrNotImplemented)
		},
	}
	add.Flags().String("base-url", "", "provider base URL")

	providers.AddCommand(list, models, test, add)
	return providers
}