package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ZN9-KYANT/aivault/internal/version"
)

// newVersionCmd prints the release version; the value lives in
// internal/version so release builds can stamp it via -ldflags -X.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the aivault version",
		Run: func(_ *cobra.Command, _ []string) {
			out := "aivault version " + version.Version
			if version.Commit != "none" || version.Date != "unknown" {
				out += fmt.Sprintf(" (commit %s, built %s)", version.Commit, version.Date)
			}
			fmt.Println(out)
		},
	}
}
