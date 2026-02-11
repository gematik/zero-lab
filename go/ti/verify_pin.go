package main

import (
	"context"
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify card PINs",
	}

	cmd.AddCommand(newVerifyPinCmd())

	return cmd
}

func newVerifyPinCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pin <card-handle> <pin-type>",
		Short: "Verify PIN of a card",
		Long:  fmt.Sprintf("Verify PIN of a card.\nValid PIN types: %s", kon.PinTypValuesString()),
		Args:  cobra.ExactArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 1 {
				return kon.PinTypValues(), cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadDotkon()
			if err != nil {
				return err
			}
			pinTyp := kon.PinTyp(args[1])
			if !pinTyp.IsValid() {
				return fmt.Errorf("invalid PIN type %q, valid types: %s", args[1], kon.PinTypValuesString())
			}
			return runVerifyPin(cmd.Context(), config, args[0], pinTyp)
		},
	}
	return cmd
}

func runVerifyPin(ctx context.Context, config *kon.Dotkon, cardHandle string, pinTyp kon.PinTyp) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	resp, err := client.VerifyPin(ctx, cardHandle, pinTyp)
	if err != nil {
		return err
	}

	if outputFlag == "json" {
		return printJSON(resp)
	}

	return printKeyValue(func(w io.Writer) {
		fmt.Fprintf(w, "Result\t%s\n", resp.Status.Result)
		fmt.Fprintf(w, "PIN Result\t%s\n", resp.PinResult)
		if resp.LeftTries > 0 {
			fmt.Fprintf(w, "Left Tries\t%d\n", resp.LeftTries)
		}
	})
}
