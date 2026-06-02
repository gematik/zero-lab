package kon

import (
	"context"
	"fmt"

	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/eventservice72"
)

func (c *Client) GetResourceInformation(ctx context.Context) (*eventservice72.GetResourceInformationResponse, error) {
	proxy, err := c.createLatestServiceProxy(ServiceNameEventService)
	if err != nil {
		return nil, err
	}

	envelope := &eventservice72.GetResourceInformationEnvelope{
		GetResourceInformation: &eventservice72.GetResourceInformation{
			Context: c.connectorContext(),
		},
	}

	var resp eventservice72.GetResourceInformationResponseEnvelope
	if err := proxy.Call(ctx, &eventservice72.OperationGetResourceInformation, envelope, &resp); err != nil {
		return nil, fmt.Errorf("GetResourceInformation: %w", err)
	}

	if resp.Fault != nil {
		return nil, fmt.Errorf("GetResourceInformation SOAP fault: %s", resp.Fault.String)
	}
	if resp.GetResourceInformationResponse == nil {
		return nil, fmt.Errorf("GetResourceInformation: empty response")
	}

	return resp.GetResourceInformationResponse, nil
}
