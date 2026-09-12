// Package idp is the gematik IDP-Dienst side of the CLI. Its one command so
// far plays the part of the gematik Authenticator app for a client that
// emitted an authenticator:// deep link: it signs the IDP's challenge with an
// SMC-B and hands the resulting redirect back to whoever called it.
package idp

import "github.com/spf13/cobra"

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "idp",
		Short: "gematik IDP-Dienst: authenticate with an SMC-B",
	}
	cmd.AddCommand(newAuthenticateCmd())
	return cmd
}
