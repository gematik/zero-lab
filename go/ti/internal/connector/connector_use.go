package connector

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

func newConnectorUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Set the active connector configuration",
		Long: "Set the active connector configuration. Subsequent commands without\n" +
			"-c/--connector-config or " + common.ConnectorConfigEnv + " env var will use this selection.\n\n" +
			"The selection is stored at $XDG_CONFIG_HOME/telematik/connectors/active.",
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return common.CompleteConnectorConfigNames(cmd, args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			name := args[0]
			if _, err := common.ResolveConnectorConfigFile(name); err != nil {
				return err
			}
			path := common.ActiveConnectorFile()
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
			}
			if err := os.WriteFile(path, []byte(name+"\n"), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}
			fmt.Fprintf(os.Stderr, "active connector set to %q\n", name)
			return nil
		},
	}
}
