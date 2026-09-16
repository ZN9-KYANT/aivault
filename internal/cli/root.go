// Package cli defines the aivault command tree (SPEC 7).
package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/vault"
	"github.com/ZN9-KYANT/aivault/internal/version"
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
		Version:      version.Version,
	}
	root.PersistentFlags().String("home", "", "aivault home directory (default ~/.aivault)")
	root.AddCommand(
		newInitCmd(), newServeCmd(), newUnlockCmd(), newLockCmd(), newStatusCmd(), newPasswdCmd(),
		newKeysCmd(), newProxyKeyCmd(), newProvidersCmd(), newAliasCmd(),
		newBackupCmd(), newRestoreCmd(), newAuditCmd(), newVersionCmd(),
	)
	return root
}

// Execute runs the CLI root command and exits non-zero on failure.
func Execute() {
	if err := NewRoot().Execute(); err != nil {
		os.Exit(1)
	}
}

// homeDir resolves the vault home: --home flag, else ~/.aivault (SPEC 3.1).
func homeDir(cmd *cobra.Command) string {
	if h, err := cmd.Root().PersistentFlags().GetString("home"); err == nil && h != "" {
		return h
	}
	if h, err := vault.DefaultHome(); err == nil {
		return h
	}
	return ".aivault"
}

// auditPath returns the audit log path under home (SPEC 4.5).
func auditPath(home string) string {
	return home + string(os.PathSeparator) + "audit.log"
}
