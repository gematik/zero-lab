package common

import (
	"context"
	"fmt"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
)

// ResolveCardHandle resolves an identifier that is either a card handle or a
// registration number (Telematik-ID) to a card handle and its card type.
func ResolveCardHandle(ctx context.Context, client *kon.Client, identifier string) (string, cardservicecommon20.CardType, error) {
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
