package kon

import (
	"context"
	"fmt"

	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservice81"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/connectorcontext20"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/eventservice72"
)

func (c *Client) GetCards(ctx context.Context) ([]cardservice81.Card, error) {
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
