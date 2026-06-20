package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
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
		Use:   "pin <card-handle-or-telematik-id> [pin-type]",
		Short: "Verify PIN of a card",
		Long: "Verify PIN of a card.\n" +
			"The first argument can be a card handle or a Telematik-ID (registration number).\n" +
			"The PIN type is optional when the card type has only one (e.g. SMC-B → PIN.SMC);\n" +
			"required when the card type supports multiple (e.g. HBA → PIN.CH or PIN.QES).\n" +
			"Valid PIN types: " + kon.PinTypValuesString(),
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: pinTypeCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadConnectorConfig()
			if err != nil {
				return err
			}
			userPinTyp, err := parseUserPinTyp(args)
			if err != nil {
				return err
			}
			return runVerifyPin(cmd.Context(), config, args[0], userPinTyp)
		},
	}
	addConnectorConfigFlag(cmd)
	return cmd
}

func pinTypeCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 1 {
		return kon.PinTypValues(), cobra.ShellCompDirectiveNoFileComp
	}
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// parseUserPinTyp validates an optional pin-type CLI argument. Returns the empty
// PinTyp when the user did not supply one (the runner will derive it from card type).
func parseUserPinTyp(args []string) (kon.PinTyp, error) {
	if len(args) < 2 {
		return "", nil
	}
	pinTyp := kon.PinTyp(args[1])
	if !pinTyp.IsValid() {
		return "", fmt.Errorf("invalid PIN type %q, valid types: %s", args[1], kon.PinTypValuesString())
	}
	return pinTyp, nil
}

// resolvePinTyp picks the PIN type to use for a given card. If the user supplied
// one, it is validated against the card type's allowed set (when known) and returned.
// Otherwise the card type must have exactly one allowed PIN type; on 0 or >1, an
// error tells the user which to pass explicitly.
func resolvePinTyp(cardType cardservicecommon20.CardType, userPinTyp kon.PinTyp) (kon.PinTyp, error) {
	allowed := kon.PinTypesForCardType(cardType)

	if userPinTyp != "" {
		if len(allowed) > 0 && !slices.Contains(allowed, userPinTyp) {
			return "", fmt.Errorf("PIN type %s is not valid for card type %s; valid: %s",
				userPinTyp, cardType, joinPinTypes(allowed))
		}
		return userPinTyp, nil
	}

	switch len(allowed) {
	case 0:
		return "", fmt.Errorf("card type %s has no known PIN types; pass a PIN type explicitly", cardType)
	case 1:
		return allowed[0], nil
	default:
		return "", fmt.Errorf("card type %s supports multiple PIN types (%s); specify one",
			cardType, joinPinTypes(allowed))
	}
}

func joinPinTypes(types []kon.PinTyp) string {
	s := make([]string, len(types))
	for i, t := range types {
		s[i] = string(t)
	}
	return strings.Join(s, ", ")
}

func resolveCardHandle(ctx context.Context, client *kon.Client, identifier string) (string, cardservicecommon20.CardType, error) {
	// Try as card handle first
	card, err := client.GetCard(ctx, identifier)
	if err == nil {
		return card.CardHandle, card.CardType, nil
	}

	// Fall back to registration number (Telematik-ID)
	card, err = client.FindCardByRegistrationNumber(ctx, identifier)
	if err != nil {
		return "", "", fmt.Errorf("could not resolve %q as card handle or Telematik-ID: %w", identifier, err)
	}
	return card.CardHandle, card.CardType, nil
}

// spinner displays an animated waiting indicator on stderr.
type spinner struct {
	msg  string
	stop chan struct{}
	done sync.WaitGroup
}

func startSpinner(msg string) *spinner {
	s := &spinner{msg: msg, stop: make(chan struct{})}
	if !isTerminal() {
		return s
	}
	s.done.Go(func() {
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
	})
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
		Use:   "pin <card-handle-or-telematik-id> [pin-type]",
		Short: "Change PIN of a card",
		Long: "Change PIN of a card.\n" +
			"The first argument can be a card handle or a Telematik-ID (registration number).\n" +
			"The PIN type is optional when the card type has only one (e.g. SMC-B → PIN.SMC);\n" +
			"required when the card type supports multiple (e.g. HBA → PIN.CH or PIN.QES).\n" +
			"Valid PIN types: " + kon.PinTypValuesString(),
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: pinTypeCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadConnectorConfig()
			if err != nil {
				return err
			}
			userPinTyp, err := parseUserPinTyp(args)
			if err != nil {
				return err
			}
			return runChangePin(cmd.Context(), config, args[0], userPinTyp)
		},
	}
	addConnectorConfigFlag(cmd)
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

func runVerifyPin(ctx context.Context, config *kon.Dotkon, identifier string, userPinTyp kon.PinTyp) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	spin := startSpinner("Resolving card...")
	cardHandle, cardType, err := resolveCardHandle(ctx, client, identifier)
	spin.Stop()
	if err != nil {
		return err
	}

	pinTyp, err := resolvePinTyp(cardType, userPinTyp)
	if err != nil {
		return err
	}

	spin = startSpinner(fmt.Sprintf("Verifying %s. Follow instructions on card terminal.", pinTyp))
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

func runChangePin(ctx context.Context, config *kon.Dotkon, identifier string, userPinTyp kon.PinTyp) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	spin := startSpinner("Resolving card...")
	cardHandle, cardType, err := resolveCardHandle(ctx, client, identifier)
	spin.Stop()
	if err != nil {
		return err
	}

	pinTyp, err := resolvePinTyp(cardType, userPinTyp)
	if err != nil {
		return err
	}

	spin = startSpinner(fmt.Sprintf("Changing %s. Follow instructions on card terminal.", pinTyp))
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
