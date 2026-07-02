package connector

import (
	"context"
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

func newGetIdentitiesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identities",
		Short: "List identities (Telematik-IDs) from HBA and SMC-B cards",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := common.LoadConnectorConfig()
			if err != nil {
				return err
			}
			return runGetIdentities(cmd.Context(), config)
		},
	}
	common.AddConnectorConfigFlag(cmd)
	return cmd
}

func runGetIdentities(ctx context.Context, config *kon.Dotkon) error {
	client, err := common.LoadClient(config)
	if err != nil {
		return err
	}

	cards, err := client.GetCardsByType(ctx,
		cardservicecommon20.CardTypeHba,
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

	if common.OutputFlag == "json" {
		return common.PrintJSON(cards)
	}

	return common.PrintTable("TELEMATIK-ID\tTYPE\tHOLDER\tHANDLE", func(w io.Writer) {
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
