package main

import (
	"context"
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservice81"
	"github.com/spf13/cobra"
)

func newDescribeCardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "card <card-handle>",
		Short: "Show detailed card information",
		Long:  "Show detailed card information.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadDotkon()
			if err != nil {
				return err
			}
			cardHandle := args[0]
			return runDescribeCard(cmd.Context(), config, cardHandle)
		},
	}
}

func runDescribeCard(ctx context.Context, config *kon.Dotkon, cardHandle string) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	card, certs, err := client.GetCard(ctx, cardHandle)
	if err != nil {
		return err
	}

	if outputFlag == "json" {
		return printJSON(struct {
			Card  *cardservice81.Card    `json:"card"`
			Certs []*kon.CardCertificate `json:"certificates"`
		}{
			Card:  card,
			Certs: certs,
		})
	}

	return printKeyValue(func(w io.Writer) {
		fmt.Fprintf(w, "Card Handle\t%s\n", card.CardHandle)
		fmt.Fprintf(w, "Card Type\t%s\n", card.CardType)
		fmt.Fprintf(w, "ICCSN\t%s\n", card.Iccsn)
		fmt.Fprintf(w, "CT ID\t%s\n", card.CtId)
		fmt.Fprintf(w, "Slot ID\t%d\n", card.SlotId)
		fmt.Fprintf(w, "Card Holder Name\t%s\n", card.CardHolderName)
		for _, cert := range certs {
			fmt.Fprintf(w, "Certificate %s\n", cert.CertRef)
			fmt.Fprintf(w, "    Subject\t%s\n", cert.X509.Subject)
			fmt.Fprintf(w, "    Issuer\t%s\n", cert.X509.Issuer)
			fmt.Fprintf(w, "    Valid From\t%s\n", cert.X509.NotBefore)
			fmt.Fprintf(w, "    Valid To\t%s\n", cert.X509.NotAfter)
			fmt.Fprintf(w, "    Public Key\t%s\n", describePublicKey(cert.X509.PublicKey))
		}
	})

}
