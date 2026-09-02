// Package cli defines the aivault command tree (SPEC 7).
package cli

import (
	"os"

	"github.com/spf13/cobra"
)

// NewRoot builds the full command tree.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "aivault",
		Short: "Encrypted API key vault and OpenAI-compatible gateway",
		Long: "aivault stores LLM provider API keys in an age-encrypted vault and\n" +
			"serves them through an OpenAI-compatible gateway via one-time proxy keys.\n" +
			"See SPEC.md for the full design.",
		SilenceUsage: true,
	}
	root.AddCommand(
		newInitCmd(), newServeCmd(), newUnlockCmd(), newLockCmd(), newStatusCmd(), newPasswdCmd(),
		newKeysCmd(), newProxyKeyCmd(), newProvidersCmd(), newAliasCmd(),
		newBackupCmd(), newRestoreCmd(), newAuditCmd(),
	)
	return root
}

// Execute runs the CLI root command and exits non-zero on failure.
func Execute() {
	if err := NewRoot().Execute(); err != nil {
		os.Exit(1)
	}
}