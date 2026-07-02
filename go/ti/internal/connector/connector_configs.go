package connector

import (
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

func newConnectorConfigsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "configs",
		Short: "List available connector configuration files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runConnectorConfigs()
		},
	}
}

func runConnectorConfigs() error {
	configs := common.CollectConnectorConfigs()

	if common.OutputFlag == "json" {
		return common.PrintJSON(configs)
	}

	return common.PrintTable("NAME\tURL\tCONTEXT", func(w io.Writer) {
		for _, c := range configs {
			fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, c.URL, c.Context)
		}
	})
}
