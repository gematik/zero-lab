package main

import (
	"context"
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/spf13/cobra"
)

func newGetStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show resource information (connector, card terminals, cards)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadDotkon()
			if err != nil {
				return err
			}
			return runGetStatus(cmd.Context(), config)
		},
	}
}

func runGetStatus(ctx context.Context, config *kon.Dotkon) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	resp, err := client.GetResourceInformation(ctx)
	if err != nil {
		return err
	}

	if outputFlag == "json" {
		return printJSON(resp)
	}

	if conn := resp.Connector; conn != nil {
		fmt.Println(sectionHeader("Connector"))
		printKeyValue(func(w io.Writer) {
			fmt.Fprintf(w, "VPN TI\t%s\n", conn.VPNTIStatus.ConnectionStatus)
			fmt.Fprintf(w, "VPN SIS\t%s\n", conn.VPNSISStatus.ConnectionStatus)
		})
		if len(conn.OperatingState.ErrorState) > 0 {
			fmt.Println()
			fmt.Println(sectionHeader("Error States"))
			printTable("CONDITION\tSEVERITY\tTYPE\tVALUE\tSINCE", func(w io.Writer) {
				for _, es := range conn.OperatingState.ErrorState {
					fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n",
						es.ErrorCondition, es.Severity, es.Type, es.Value, es.ValidFrom)
				}
			})
		}
	}

	if ct := resp.CardTerminal; ct != nil {
		fmt.Println()
		fmt.Println(sectionHeader("Card Terminal"))
		printKeyValue(func(w io.Writer) {
			fmt.Fprintf(w, "CT ID\t%s\n", ct.CtId)
			fmt.Fprintf(w, "Name\t%s\n", ct.Name)
			fmt.Fprintf(w, "MAC\t%s\n", ct.MacAddress)
			if ct.IPAddress != nil {
				if ct.IPAddress.IPV4Address != "" {
					fmt.Fprintf(w, "IPv4\t%s\n", ct.IPAddress.IPV4Address)
				}
				if ct.IPAddress.IPV6Address != "" {
					fmt.Fprintf(w, "IPv6\t%s\n", ct.IPAddress.IPV6Address)
				}
			}
			fmt.Fprintf(w, "Slots\t%d\n", ct.Slots)
			fmt.Fprintf(w, "Physical\t%v\n", ct.IsPhysical)
			fmt.Fprintf(w, "Connected\t%v\n", ct.Connected)
		})
	}

	if card := resp.Card; card != nil {
		fmt.Println()
		fmt.Println(sectionHeader("Card"))
		printKeyValue(func(w io.Writer) {
			fmt.Fprintf(w, "Handle\t%s\n", card.CardHandle)
			fmt.Fprintf(w, "Type\t%s\n", card.CardType)
			fmt.Fprintf(w, "ICCSN\t%s\n", card.Iccsn)
			fmt.Fprintf(w, "CT ID\t%s\n", card.CtId)
			fmt.Fprintf(w, "Slot\t%d\n", card.SlotId)
			if card.CardHolderName != "" {
				fmt.Fprintf(w, "Holder\t%s\n", card.CardHolderName)
			}
			if card.InsertTime != "" {
				fmt.Fprintf(w, "Inserted\t%s\n", card.InsertTime)
			}
			if card.CertificateExpirationDate != "" {
				fmt.Fprintf(w, "Cert Expires\t%s\n", card.CertificateExpirationDate)
			}
		})
	}

	return nil
}
