package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

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
		Use:   "pin <card-handle-or-telematik-id> <pin-type>",
		Short: "Verify PIN of a card",
		Long:  fmt.Sprintf("Verify PIN of a card.\nThe first argument can be a card handle or a Telematik-ID (registration number).\nValid PIN types: %s", kon.PinTypValuesString()),
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

func resolveCardHandle(ctx context.Context, client *kon.Client, identifier string) (string, error) {
	// Try as card handle first
	_, err := client.GetCard(ctx, identifier)
	if err == nil {
		return identifier, nil
	}

	// Fall back to registration number (Telematik-ID)
	card, err := client.FindCardByRegistrationNumber(ctx, identifier)
	if err != nil {
		return "", fmt.Errorf("could not resolve %q as card handle or Telematik-ID: %w", identifier, err)
	}
	return card.CardHandle, nil
}

// spinner displays an animated waiting indicator on stderr.
type spinner struct {
	msg    string
	stop   chan struct{}
	done   sync.WaitGroup
}

func startSpinner(msg string) *spinner {
	s := &spinner{msg: msg, stop: make(chan struct{})}
	if !isTerminal() {
		return s
	}
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				fmt.Fprintf(os.Stderr, "\r%s %s", frames[i%len(frames)], s.msg)
				i++
			}
		}
	}()
	return s
}

func (s *spinner) Stop() {
	close(s.stop)
	s.done.Wait()
}

func newChangeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "change",
		Short: "Change card PINs",
	}

	cmd.AddCommand(newChangePinCmd())

	return cmd
}

func newChangePinCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pin <card-handle-or-telematik-id> <pin-type>",
		Short: "Change PIN of a card",
		Long:  fmt.Sprintf("Change PIN of a card.\nThe first argument can be a card handle or a Telematik-ID (registration number).\nValid PIN types: %s", kon.PinTypValuesString()),
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
			return runChangePin(cmd.Context(), config, args[0], pinTyp)
		},
	}
	return cmd
}

// pinResult displays a PIN operation result with emoji indicators.
func pinResult(operation string, pinResult string, leftTries int) {
	if pinResult == "OK" {
		fmt.Fprintf(os.Stderr, "✅ %s successful\n", operation)
	} else {
		fmt.Fprintf(os.Stderr, "❌ %s failed: %s\n", operation, pinResult)
		if leftTries > 0 {
			fmt.Fprintf(os.Stderr, "   Remaining tries: %d\n", leftTries)
		}
	}
}

func runVerifyPin(ctx context.Context, config *kon.Dotkon, identifier string, pinTyp kon.PinTyp) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	spin := startSpinner("Resolving card...")
	cardHandle, err := resolveCardHandle(ctx, client, identifier)
	spin.Stop()
	if err != nil {
		return err
	}

	spin = startSpinner("Initiated. Follow instructions on card terminal.")
	resp, err := client.VerifyPin(ctx, cardHandle, pinTyp)
	spin.Stop()
	if err != nil {
		return err
	}

	if outputFlag == "json" {
		return printJSON(resp)
	}

	pinResult("PIN verification", string(resp.PinResult), resp.LeftTries)
	return nil
}

func runChangePin(ctx context.Context, config *kon.Dotkon, identifier string, pinTyp kon.PinTyp) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	spin := startSpinner("Resolving card...")
	cardHandle, err := resolveCardHandle(ctx, client, identifier)
	spin.Stop()
	if err != nil {
		return err
	}

	spin = startSpinner("Initiated. Follow instructions on card terminal.")
	resp, err := client.ChangePin(ctx, cardHandle, pinTyp)
	spin.Stop()
	if err != nil {
		return err
	}

	if outputFlag == "json" {
		return printJSON(resp)
	}

	pinResult("PIN change", string(resp.PinResult), resp.LeftTries)
	return nil
}
