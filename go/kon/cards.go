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

func (c *Client) GetCard(ctx context.Context, cardHandle string) (*cardservice81.Card, []*CardCertificate, error) {
	envelope := &eventservice72.GetResourceInformationEnvelope{
		GetResourceInformation: &eventservice72.GetResourceInformation{
			Context:    c.connectorContext(),
			CardHandle: cardHandle,
		},
	}

	var resp eventservice72.GetResourceInformationResponseEnvelope
	proxy, err := c.createLatestServiceProxy(ServiceNameEventService)
	if err != nil {
		return nil, nil, err
	}
	if err := proxy.Call(ctx, &eventservice72.OperationGetResourceInformation, envelope, &resp); err != nil {
		return nil, nil, fmt.Errorf("GetResourceInformation: %w", err)
	}

	if resp.Fault != nil {
		return nil, nil, fmt.Errorf("GetResourceInformation SOAP fault: %s", resp.Fault.String)
	}
	if resp.GetResourceInformationResponse == nil {
		return nil, nil, fmt.Errorf("GetResourceInformation: empty response")
	}
	if resp.GetResourceInformationResponse.Card == nil {
		return nil, nil, fmt.Errorf("GetResourceInformation: no card in response")
	}

	card := resp.GetResourceInformationResponse.Card

	certs, err := c.ReadAllCardCertificates(ctx, card)
	if err != nil {
		return nil, nil, fmt.Errorf("reading card certificates: %w", err)
	}

	return card, certs, nil
}

func (c *Client) GetAllCards(ctx context.Context) ([]cardservice81.Card, error) {
	proxy, err := c.createLatestServiceProxy(ServiceNameEventService)
	if err != nil {
		return nil, err
	}

	envelope := &eventservice72.GetCardsEnvelope{
		GetCards: &eventservice72.GetCards{
			Context: c.connectorContext(),
		},
	}

	var resp eventservice72.GetCardsResponseEnvelope
	if err := proxy.Call(ctx, &eventservice72.OperationGetCards, envelope, &resp); err != nil {
		return nil, fmt.Errorf("GetCards: %w", err)
	}

	if resp.Fault != nil {
		return nil, fmt.Errorf("GetCards SOAP fault: %s", resp.Fault.String)
	}
	if resp.GetCardsResponse == nil {
		return nil, fmt.Errorf("GetCards: empty response")
	}

	return resp.GetCardsResponse.Cards.Card, nil
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
