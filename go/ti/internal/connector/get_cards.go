package connector

import (
	"context"
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

func newGetCardsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cards",
		Short: "List inserted cards",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := common.LoadConnectorConfig()
			if err != nil {
				return err
			}
			return runGetCards(cmd.Context(), config)
		},
	}
	common.AddConnectorConfigFlag(cmd)
	return cmd
}

func runGetCards(ctx context.Context, config *kon.Dotkon) error {
	client, err := common.LoadClient(config)
	if err != nil {
		return err
	}

	cards, err := client.GetAllCards(ctx)
	if err != nil {
		return err
	}

	if common.OutputFlag == "json" {
		return common.PrintJSON(cards)
	}

	return common.PrintTable("HANDLE\tTYPE\tICCSN\tCT\tSLOT\tHOLDER", func(w io.Writer) {
		for _, c := range cards {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
				c.CardHandle, c.CardType, c.Iccsn, c.CtId, c.SlotId, c.CardHolderName)
		}
	})
}
