package connector

import (
	"github.com/spf13/cobra"
)

func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get resources from the Konnektor",
	}

	cmd.AddCommand(newGetInfoCmd())
	cmd.AddCommand(newGetServicesCmd())
	cmd.AddCommand(newGetCardsCmd())
	cmd.AddCommand(newGetCertificatesCmd())
	cmd.AddCommand(newGetStatusCmd())
	cmd.AddCommand(newGetIdentitiesCmd())
	cmd.AddCommand(newGetExpirationCmd())

	return cmd
}
