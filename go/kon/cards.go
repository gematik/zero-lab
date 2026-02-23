package kon

import (
	"context"
	"fmt"

	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservice81"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/connectorcontext20"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/eventservice72"
)

// CertificatesByCardType maps card types to the certificates available for them.
// This is used to determine which certificates to request for a given card type.
var CertificatesByCardType = map[cardservicecommon20.CardType][]certificateservicecommon20.CertRefEnum{
	cardservicecommon20.CardTypeHba: {
		certificateservicecommon20.CertRefEnumCAut,
		certificateservicecommon20.CertRefEnumCQes,
		certificateservicecommon20.CertRefEnumCEnc,
	},
	cardservicecommon20.CardTypeSmcB: {
		certificateservicecommon20.CertRefEnumCAut,
		certificateservicecommon20.CertRefEnumCSig,
		certificateservicecommon20.CertRefEnumCEnc,
	},
	cardservicecommon20.CardTypeSmcKt: {
		certificateservicecommon20.CertRefEnumCAut,
	},
}

func CertRefsForCardType(cardType cardservicecommon20.CardType) ([]certificateservicecommon20.CertRefEnum, error) {
	if cardType == cardservicecommon20.CardTypeHsmB || cardType == cardservicecommon20.CardTypeSmB {
		cardType = cardservicecommon20.CardTypeSmcB
	}
	certRefs, ok := CertificatesByCardType[cardType]
	if !ok {
		return nil, fmt.Errorf("unsupported card type: %s", cardType)
	}
	return certRefs, nil
}

// Card wraps cardservice81.Card and includes certificates read from the card.
type Card struct {
	cardservice81.Card
	Certificates []*CardCertificate `json:"certificates,omitempty"`
}

func (c *Client) GetCard(ctx context.Context, cardHandle string) (*Card, error) {
	return c.getCard(ctx, cardHandle, false)
}

func (c *Client) GetCardWithCertificates(ctx context.Context, cardHandle string) (*Card, error) {
	return c.getCard(ctx, cardHandle, true)
}

func (c *Client) getCard(ctx context.Context, cardHandle string, withCertificates bool) (*Card, error) {
	envelope := &eventservice72.GetResourceInformationEnvelope{
		GetResourceInformation: &eventservice72.GetResourceInformation{
			Context:    c.connectorContext(),
			CardHandle: cardHandle,
		},
	}

	var resp eventservice72.GetResourceInformationResponseEnvelope
	proxy, err := c.createLatestServiceProxy(ServiceNameEventService)
	if err != nil {
		return nil, err
	}
	if err := proxy.Call(ctx, &eventservice72.OperationGetResourceInformation, envelope, &resp); err != nil {
		return nil, fmt.Errorf("GetResourceInformation: %w", err)
	}

	if resp.Fault != nil {
		return nil, fmt.Errorf("GetResourceInformation SOAP fault: %s", resp.Fault.String)
	}
	if resp.GetResourceInformationResponse == nil {
		return nil, fmt.Errorf("GetResourceInformation: empty response")
	}
	if resp.GetResourceInformationResponse.Card == nil {
		return nil, fmt.Errorf("GetResourceInformation: no card in response")
	}

	card := &Card{
		Card: *resp.GetResourceInformationResponse.Card,
	}

	if withCertificates {
		certs, err := c.ReadAllCardCertificates(ctx, card)
		if err != nil {
			return nil, fmt.Errorf("reading card certificates: %w", err)
		}
		card.Certificates = certs
	}

	return card, nil
}

func (c *Client) GetAllCards(ctx context.Context) ([]Card, error) {
	return c.getCardsByType(ctx, nil)
}

func (c *Client) GetCardsByType(ctx context.Context, cardTypes ...cardservicecommon20.CardType) ([]Card, error) {
	return c.getCardsByType(ctx, cardTypes)
}

func (c *Client) getCardsByType(ctx context.Context, cardTypes []cardservicecommon20.CardType) ([]Card, error) {
	proxy, err := c.createLatestServiceProxy(ServiceNameEventService)
	if err != nil {
		return nil, err
	}

	if len(cardTypes) == 0 {
		cardTypes = []cardservicecommon20.CardType{""}
	}

	var cards []Card
	for _, cardType := range cardTypes {
		envelope := &eventservice72.GetCardsEnvelope{
			GetCards: &eventservice72.GetCards{
				Context:  c.connectorContext(),
				CardType: cardType,
			},
		}

		var resp eventservice72.GetCardsResponseEnvelope
		if err := proxy.Call(ctx, &eventservice72.OperationGetCards, envelope, &resp); err != nil {
			return nil, fmt.Errorf("GetCards(%s): %w", cardType, err)
		}
		if resp.Fault != nil {
			return nil, fmt.Errorf("GetCards(%s) SOAP fault: %s", cardType, resp.Fault.String)
		}
		if resp.GetCardsResponse == nil {
			continue
		}
		for _, rawCard := range resp.GetCardsResponse.Cards.Card {
			cards = append(cards, Card{Card: rawCard})
		}
	}

	return cards, nil
}

func (c *Client) FindCardByRegistrationNumber(ctx context.Context, registrationNumber string) (*Card, error) {
	cards, err := c.GetCardsByType(ctx,
		cardservicecommon20.CardTypeHba,
		cardservicecommon20.CardTypeSmB,
	)
	if err != nil {
		return nil, err
	}

	for _, card := range cards {
		certs, err := c.ReadAllCardCertificates(ctx, &card)
		if err != nil {
			continue
		}
		card.Certificates = certs
		for _, cert := range certs {
			if cert.Admission != nil && cert.Admission.RegistrationNumber == registrationNumber {
				return &card, nil
			}
		}
	}

	return nil, fmt.Errorf("no card found with registration number %s", registrationNumber)
}

func (c *Client) connectorContext() connectorcontext20.Context {
	return connectorcontext20.Context{
		MandantId:      c.Context.MandantId,
		ClientSystemId: c.Context.ClientSystemId,
		WorkplaceId:    c.Context.WorkplaceId,
		UserId:         c.Context.UserId,
	}
}

func (c *Client) createLatestServiceProxy(serviceName ServiceName) (*serviceProxy, error) {
	var bestService *Service
	var bestVersion *ServiceVersion
	var bestSemver int

	for i, s := range c.Services.ServiceInformation.Service {
		if s.Name == serviceName {
			for j, v := range s.Versions {
				sv := semverAsNumber(v.Version)
				if sv > bestSemver {
					bestService = &c.Services.ServiceInformation.Service[i]
					bestVersion = &c.Services.ServiceInformation.Service[i].Versions[j]
					bestSemver = sv
				}
			}
		}
	}

	if bestVersion == nil {
		return nil, fmt.Errorf("service not found: %s", serviceName)
	}

	return &serviceProxy{
		endpoint:       bestVersion.EndpointTLS.Location,
		client:         c,
		service:        bestService,
		serviceVersion: bestVersion,
	}, nil
}
