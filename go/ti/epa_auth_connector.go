package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
)

// connectorAuthMethod signs ePA traffic with an SMC-B's C.AUT key by routing
// the hash through the Konnektor's ExternalAuthenticate SOAP operation. The
// .kon config and card identity are taken from the same flags the rest of the
// ti CLI uses (-c, --card).
type connectorAuthMethod struct {
	cardIdentifier string // empty → auto-pick first SMC-B
}

func newConnectorAuthMethod() (AuthMethod, error) {
	return &connectorAuthMethod{cardIdentifier: authCardFlagVal}, nil
}

func (c *connectorAuthMethod) Name() string { return authMethodConnector }

func (c *connectorAuthMethod) SecurityFunctions(ctx context.Context) (*epa.SecurityFunctions, error) {
	config, err := loadConnectorConfig()
	if err != nil {
		return nil, err
	}
	client, err := loadClient(config)
	if err != nil {
		return nil, err
	}

	cardHandle, _, err := c.resolveCard(ctx, client)
	if err != nil {
		return nil, err
	}

	cert, err := readSMCBAuthCert(ctx, client, cardHandle)
	if err != nil {
		return nil, fmt.Errorf("reading C.AUT cert: %w", err)
	}

	signFn := brainpool.SignFunc(func(hash []byte) ([]byte, error) {
		return client.ExternalAuthenticate(ctx, cardHandle, hash, kon.SignatureTypeECDSA)
	})
	certFn := func() (*x509.Certificate, error) { return cert, nil }

	return &epa.SecurityFunctions{
		AuthnSignFunc:           signFn,
		AuthnCertFunc:           certFn,
		ClientAssertionSignFunc: signFn,
		ClientAssertionCertFunc: certFn,
		// ProvidePN, ProvideHCV intentionally nil — entitlement wired elsewhere.
	}, nil
}

// resolveCard returns the card handle to sign with. If --card was set, it goes
// through the existing handle/Telematik-ID resolver. Otherwise it picks the
// first SMC-B (or SM-B) inserted on the connector.
func (c *connectorAuthMethod) resolveCard(ctx context.Context, client *kon.Client) (string, cardservicecommon20.CardType, error) {
	if c.cardIdentifier != "" {
		return resolveCardHandle(ctx, client, c.cardIdentifier)
	}
	cards, err := client.GetCardsByType(ctx,
		cardservicecommon20.CardTypeSmcB,
		cardservicecommon20.CardTypeSmB,
	)
	if err != nil {
		return "", "", fmt.Errorf("listing SMC-B cards: %w", err)
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
		return "", "", fmt.Errorf("no SMC-B card inserted; pass --%s to select one explicitly", authCardFlag)
	}
	if len(unique) > 1 {
		slog.Warn("multiple SMC-B cards inserted; using the first one — pass --card to select explicitly",
			"chosen", unique[0].CardHandle, "candidates", len(unique))
	}
	return unique[0].CardHandle, unique[0].CardType, nil
}

// readSMCBAuthCert reads the SMC-B C.AUT certificate, preferring ECC over RSA
// since the brainpool SignFunc path expects ECC.
func readSMCBAuthCert(ctx context.Context, client *kon.Client, cardHandle string) (*x509.Certificate, error) {
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
