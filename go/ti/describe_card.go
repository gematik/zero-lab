package main

import (
	"context"
	"fmt"

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

	kv := newKVWriter()

	kv.Section("Card")
	kv.KV("Card Handle", card.CardHandle)
	kv.KV("Card Type", string(card.CardType))
	kv.KV("ICCSN", card.Iccsn)
	kv.KV("CT ID", card.CtId)
	kv.KV("Slot ID", fmt.Sprintf("%d", card.SlotId))
	if card.InsertTime != "" {
		kv.KV("Insert Time", card.InsertTime)
	}
	if card.CardHolderName != "" {
		kv.KV("Card Holder", card.CardHolderName)
	}
	if card.Kvnr != "" {
		kv.KV("KVNR", card.Kvnr)
	}
	if card.CertificateExpirationDate != "" {
		kv.KV("Cert Expiration", card.CertificateExpirationDate)
	}
	if card.CardVersion != nil {
		kv.Section("Card Version")
		v := card.CardVersion
		kv.KV("COS", fmt.Sprintf("%d.%d.%d", v.COSVersion.Major, v.COSVersion.Minor, v.COSVersion.Revision))
		kv.KV("Object System", fmt.Sprintf("%d.%d.%d", v.ObjectSystemVersion.Major, v.ObjectSystemVersion.Minor, v.ObjectSystemVersion.Revision))
		if v.CardPTPersVersion != nil {
			kv.KV("Card PT Pers", fmt.Sprintf("%d.%d.%d", v.CardPTPersVersion.Major, v.CardPTPersVersion.Minor, v.CardPTPersVersion.Revision))
		}
		if v.DataStructureVersion != nil {
			kv.KV("Data Structure", fmt.Sprintf("%d.%d.%d", v.DataStructureVersion.Major, v.DataStructureVersion.Minor, v.DataStructureVersion.Revision))
		}
		kv.EndSection()
	}
	kv.EndSection()

	for _, c := range certs {
		writeCertificateDetail(kv, c)
	}

	return kv.Print()
}
