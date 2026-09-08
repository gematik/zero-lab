package connector

import (
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify card PINs and certificates",
	}

	cmd.AddCommand(newVerifyPinCmd())
	cmd.AddCommand(newVerifyCertificateCmd())

	return cmd
}
