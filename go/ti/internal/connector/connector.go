package connector

import (
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

// NewCmd builds the `ti connector` command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connector",
		Short: "Connector (Konnektor) commands",
		Long: "Commands for interacting with the Gematik Konnektor.\n\n" +
			"Select a configuration with -c/--connector-config, the " + common.ConnectorConfigEnv + " env var,\n" +
			"or `ti connector use <name>` to make a selection sticky.\n\n" +
			"Names resolve as: exact path, <name>.kon in current dir, then $XDG_CONFIG_HOME/telematik/connectors/.",
	}
	cmd.PersistentFlags().StringVarP(&common.OutputFlag, "output", "o", "text", "output format: text, json")

	cmd.AddCommand(newGetCmd())
	cmd.AddCommand(newDescribeCmd())
	cmd.AddCommand(newVerifyCmd())
	cmd.AddCommand(newChangeCmd())
	cmd.AddCommand(newConnectorConfigsCmd())
	cmd.AddCommand(newConnectorUseCmd())

	return cmd
}
