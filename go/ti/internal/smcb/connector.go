package smcb

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservice81"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
	"github.com/gematik/zero-lab/go/ti/internal/common"
)

// FromConnector signs with the C.AUT key of an SMC-B behind the active
// Konnektor by routing each digest through ExternalAuthenticate. The card
// is the one named by cardIdentifier (handle, Telematik-ID or ICCSN) or,
// when empty, the first SMC-B inserted. The PIN is checked and, when the
// card asks for it, verified at the card terminal before the identity is
// handed out, so a signing failure later never means "forgot the PIN".
func FromConnector(ctx context.Context, cardIdentifier string) (*Identity, error) {
	config, err := common.LoadConnectorConfig()
	if err != nil {
		return nil, err
	}
	client, err := common.LoadClient(config)
	if err != nil {
		return nil, err
	}

	card, err := resolveCard(ctx, client, cardIdentifier)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Card %s (%s) ICCSN %s %s\n", card.CardHandle, card.CardType, card.Iccsn, card.CardHolderName)

	if err := ensurePIN(ctx, client, card.CardHandle); err != nil {
		return nil, err
	}

	cert, err := readAuthCert(ctx, client, card.CardHandle)
	if err != nil {
		return nil, fmt.Errorf("reading C.AUT cert: %w", err)
	}

	return &Identity{
		Sign: func(hash []byte) ([]byte, error) {
			return client.ExternalAuthenticate(ctx, card.CardHandle, hash, kon.SignatureTypeECDSA)
		},
		Cert:   func() (*x509.Certificate, error) { return cert, nil },
		Source: card.CardHandle,
	}, nil
}

// ensurePIN brings PIN.SMC to VERIFIED or explains why it cannot be.
func ensurePIN(ctx context.Context, client *kon.Client, cardHandle string) error {
	status, err := client.GetPinStatus(ctx, cardHandle, kon.PinTypSMC)
	if err != nil {
		return err
	}
	switch status.PinStatus {
	case cardservice81.PinStatusEnumVerified:
		fmt.Fprintln(os.Stderr, "PIN.SMC verified")
		return nil
	case cardservice81.PinStatusEnumVerifiable:
		spin := common.StartSpinner("Verifying PIN.SMC. Follow instructions on card terminal.")
		resp, err := client.VerifyPin(ctx, cardHandle, kon.PinTypSMC)
		spin.Stop()
		if err != nil {
			return err
		}
		common.PinResult("PIN.SMC verification", string(resp.PinResult), resp.LeftTries)
		if resp.PinResult != "OK" {
			return fmt.Errorf("PIN.SMC verification failed: %s", resp.PinResult)
		}
		return nil
	default:
		return fmt.Errorf("PIN.SMC of card %s is %s; run `ti connector change pin %s`", cardHandle, status.PinStatus, cardHandle)
	}
}

// resolveCard picks the card to sign with: an explicit identifier goes through
// the handle/Telematik-ID/ICCSN resolver, otherwise the first SMC-B inserted.
func resolveCard(ctx context.Context, client *kon.Client, identifier string) (*kon.Card, error) {
	if identifier != "" {
		handle, _, err := common.ResolveCardHandle(ctx, client, identifier)
		if err != nil {
			return nil, err
		}
		return client.GetCard(ctx, handle)
	}
	cards, err := client.GetCardsByType(ctx,
		cardservicecommon20.CardTypeSmcB,
		cardservicecommon20.CardTypeSmB,
	)
	if err != nil {
		return nil, fmt.Errorf("listing SMC-B cards: %w", err)
	}
	// GetCardsByType("SMC-B") and GetCardsByType("SM-B") often return the same
	// physical card under different aliases; dedup by handle so the
	// "multiple SMC-B" warning is accurate.
	seen := map[string]struct{}{}
	unique := cards[:0]
	for _, card := range cards {
		if _, ok := seen[card.CardHandle]; ok {
			continue
		}
		seen[card.CardHandle] = struct{}{}
		unique = append(unique, card)
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("no SMC-B card inserted; pass --%s to select one explicitly", CardFlag)
	}
	if len(unique) > 1 {
		slog.Warn("multiple SMC-B cards inserted; using the first one — pass --auth-card to select explicitly",
			"chosen", unique[0].CardHandle, "candidates", len(unique))
	}
	return &unique[0], nil
}

// readAuthCert reads the SMC-B C.AUT certificate, preferring ECC over RSA
// since the brainpool SignFunc path expects ECC.
func readAuthCert(ctx context.Context, client *kon.Client, cardHandle string) (*x509.Certificate, error) {
	for _, crypt := range []certificateservice601.CryptType{certificateservice601.CryptTypeEcc, certificateservice601.CryptTypeRsa} {
		certs, err := client.ReadCardCertificates(ctx, cardHandle, crypt, certificateservicecommon20.CertRefEnumCAut)
		if err != nil {
			slog.Debug("ReadCardCertificates failed", "crypt", crypt, "error", err)
			continue
		}
		for _, cc := range certs {
			if cc.X509 != nil {
				return cc.X509, nil
			}
		}
	}
	return nil, fmt.Errorf("no C.AUT certificate found on card %s", cardHandle)
}
