package common

import (
	"context"
	"fmt"
	"regexp"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
)

// ICCSN and Telematik-ID both have recognizable shapes, so we route by pattern
// rather than probing blindly: an ICCSN is 20 decimal digits (gemSpec), a
// Telematik-ID is 1-2 digits, a hyphen, then an arbitrary suffix. The two never
// overlap (the ICCSN has no hyphen). Anything else is a connector-assigned card
// handle. A pattern that matches but doesn't resolve still falls through to the
// handle lookup, so an unusual handle is never rejected on shape alone.
var (
	iccsnPattern       = regexp.MustCompile(`^\d{20}$`)
	telematikIDPattern = regexp.MustCompile(`^\d{1,2}-.+`)
)

// ResolveCardHandle resolves an identifier that is a card handle, a registration
// number (Telematik-ID), or an ICCSN to a card handle and its card type.
func ResolveCardHandle(ctx context.Context, client *kon.Client, identifier string) (string, cardservicecommon20.CardType, error) {
	switch {
	case iccsnPattern.MatchString(identifier):
		if card, err := findCardByICCSN(ctx, client, identifier); err == nil {
			return card.CardHandle, card.CardType, nil
		}
	case telematikIDPattern.MatchString(identifier):
		if card, err := client.FindCardByRegistrationNumber(ctx, identifier); err == nil {
			return card.CardHandle, card.CardType, nil
		}
	}

	card, err := client.GetCard(ctx, identifier)
	if err != nil {
		return "", "", fmt.Errorf("could not resolve %q as card handle, Telematik-ID, or ICCSN: %w", identifier, err)
	}
	return card.CardHandle, card.CardType, nil
}

func findCardByICCSN(ctx context.Context, client *kon.Client, iccsn string) (*kon.Card, error) {
	cards, err := client.GetAllCards(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing cards: %w", err)
	}
	for i := range cards {
		if cards[i].Iccsn == iccsn {
			return &cards[i], nil
		}
	}
	return nil, fmt.Errorf("no card with ICCSN %s", iccsn)
}
