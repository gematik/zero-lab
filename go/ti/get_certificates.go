package main

import (
	"context"
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/spf13/cobra"
)

func newGetCertificatesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "certificates <card-handle>",
		Short: "List certificates of a card",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadDotkon()
			if err != nil {
				return err
			}
			return runGetCertificates(cmd.Context(), config, args[0])
		},
	}
}

func runGetCertificates(ctx context.Context, config *kon.Dotkon, cardHandle string) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	card, err := client.GetCardWithCertificates(ctx, cardHandle)
	if err != nil {
		return err
	}

	if outputFlag == "json" {
		return printJSON(card.Certificates)
	}

	return printTable("REF\tSUBJECT\tTELEMATIK-ID\tNOT BEFORE\tNOT AFTER\tKEY", func(w io.Writer) {
		for _, c := range card.Certificates {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				c.CertRef,
				c.X509.Subject.CommonName,
				c.Admission.RegistrationNumber,
				c.X509.NotBefore.Format("2006-01-02"),
				c.X509.NotAfter.Format("2006-01-02"),
				describePublicKey(c.X509.PublicKey),
			)
		}
	})
}
