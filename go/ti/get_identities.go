package main

import (
	"context"
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
	"github.com/spf13/cobra"
)

func newGetIdentitiesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "identities",
		Short: "List identities (Telematik-IDs) from HBA and SMC-B cards",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadDotkon()
			if err != nil {
				return err
			}
			return runGetIdentities(cmd.Context(), config)
		},
	}
}

func runGetIdentities(ctx context.Context, config *kon.Dotkon) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	cards, err := client.GetCardsByType(ctx,
		cardservicecommon20.CardTypeHba,
		cardservicecommon20.CardTypeSmcB,
		cardservicecommon20.CardTypeHsmB,
		cardservicecommon20.CardTypeSmB,
	)
	if err != nil {
		return err
	}

	for i := range cards {
		certs, err := client.ReadCardCertificates(
			ctx,
			cards[i].CardHandle,
			certificateservice601.CryptTypeEcc,
			certificateservicecommon20.CertRefEnumCAut)
		if err != nil {
			continue
		}
		cards[i].Certificates = certs
	}

	if outputFlag == "json" {
		return printJSON(cards)
	}

	return printTable("TELEMATIK-ID\tTYPE\tHOLDER\tHANDLE", func(w io.Writer) {
		for _, card := range cards {
			telematikID := ""
			for _, cert := range card.Certificates {
				if cert.Admission != nil && cert.Admission.RegistrationNumber != "" {
					telematikID = cert.Admission.RegistrationNumber
					break
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				telematikID, card.CardType, card.CardHolderName, card.CardHandle)
		}
	})
}
