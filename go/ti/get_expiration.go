package main

import (
	"context"
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/spf13/cobra"
)

func newGetExpirationCmd() *cobra.Command {
	var crypt string

	cmd := &cobra.Command{
		Use:   "expiration [card-handle]",
		Short: "Check certificate expiration status",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadDotkon()
			if err != nil {
				return err
			}
			cryptType := certificateservice601.CryptType(crypt)
			if crypt != "" && !cryptType.IsValid() {
				return fmt.Errorf("invalid crypt type %q, valid values: RSA, ECC", crypt)
			}
			cardHandle := ""
			if len(args) > 0 {
				cardHandle = args[0]
			}
			return runGetExpiration(cmd.Context(), config, cryptType, cardHandle)
		},
	}

	cmd.Flags().StringVar(&crypt, "crypt", "", "Cryptography type (RSA or ECC)")
	cmd.RegisterFlagCompletionFunc("crypt", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"RSA", "ECC"}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

func runGetExpiration(ctx context.Context, config *kon.Dotkon, crypt certificateservice601.CryptType, cardHandle string) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	expirations, err := client.CheckCertificateExpiration(ctx, crypt, cardHandle)
	if err != nil {
		return err
	}

	if outputFlag == "json" {
		return printJSON(expirations)
	}

	return printTable("CT\tHANDLE\tICCSN\tSUBJECT\tSERIAL\tVALIDITY", func(w io.Writer) {
		for _, e := range expirations {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				e.CtID,
				e.CardHandle,
				e.Iccsn,
				e.SubjectCommonname,
				e.SerialNumber,
				e.Validity,
			)
		}
	})
}
