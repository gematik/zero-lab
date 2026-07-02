package connector

import (
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

func newGetServicesCmd() *cobra.Command {
	var raw bool

	cmd := &cobra.Command{
		Use:   "services",
		Short: "List available services",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := common.LoadConnectorConfig()
			if err != nil {
				return err
			}
			if raw {
				return runGetServicesRaw(config)
			}
			return runGetServices(config)
		},
	}

	cmd.Flags().BoolVar(&raw, "raw", false, "show raw service directory XML")
	common.AddConnectorConfigFlag(cmd)

	return cmd
}

func runGetServices(config *kon.Dotkon) error {
	services, err := common.LoadServices(config)
	if err != nil {
		return err
	}

	if common.OutputFlag == "json" {
		return common.PrintJSON(services.ServiceInformation.Service)
	}

	return common.PrintTable("SERVICE\tVERSION\tENDPOINT", func(w io.Writer) {
		for _, svc := range services.ServiceInformation.Service {
			for _, v := range svc.Versions {
				endpoint := ""
				if v.EndpointTLS != nil {
					endpoint = v.EndpointTLS.Location
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", svc.Name, v.Version, endpoint)
			}
		}
	})
}

func runGetServicesRaw(config *kon.Dotkon) error {
	services, err := common.LoadServices(config)
	if err != nil {
		return err
	}

	indented, err := common.IndentXML(services.Raw)
	if err != nil {
		fmt.Print(string(services.Raw))
		return nil
	}

	if common.IsTerminal() {
		return quick.Highlight(os.Stdout, indented, "xml", "terminal256", "monokai")
	}
	fmt.Print(indented)
	return nil
}
