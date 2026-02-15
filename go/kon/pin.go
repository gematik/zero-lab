package kon

import (
	"context"
	"fmt"
	"strings"

	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservice81"
)

type PinTyp string

const (
	PinTypCH  PinTyp = "PIN.CH"
	PinTypQES PinTyp = "PIN.QES"
	PinTypSMC PinTyp = "PIN.SMC"
)

var AllPinTypes = []PinTyp{PinTypCH, PinTypQES, PinTypSMC}

func (p PinTyp) IsValid() bool {
	for _, v := range AllPinTypes {
		if p == v {
			return true
		}
	}
	return false
}

func PinTypValues() []string {
	s := make([]string, len(AllPinTypes))
	for i, v := range AllPinTypes {
		s[i] = string(v)
	}
	return s
}

func PinTypValuesString() string {
	return strings.Join(PinTypValues(), ", ")
}

func (c *Client) VerifyPin(ctx context.Context, cardHandle string, pinTyp PinTyp) (*cardservice81.VerifyPinResponse, error) {
	proxy, err := c.createLatestServiceProxy(ServiceNameCardService)
	if err != nil {
		return nil, err
	}

	envelope := &cardservice81.VerifyPinEnvelope{
		VerifyPin: &cardservice81.VerifyPin{
			Context:    c.connectorContext(),
			CardHandle: cardHandle,
			PinTyp:     string(pinTyp),
		},
	}

	var resp cardservice81.VerifyPinResponseEnvelope
	if err := proxy.Call(ctx, &cardservice81.OperationVerifyPin, envelope, &resp); err != nil {
		return nil, fmt.Errorf("VerifyPin: %w", err)
	}

	if resp.Fault != nil {
		return nil, fmt.Errorf("VerifyPin SOAP fault: %s", resp.Fault.String)
	}
	if resp.VerifyPinResponse == nil {
		return nil, fmt.Errorf("VerifyPin: empty response")
	}

	return resp.VerifyPinResponse, nil
}

func (c *Client) ChangePin(ctx context.Context, cardHandle string, pinTyp PinTyp) (*cardservice81.ChangePinResponse, error) {
	proxy, err := c.createLatestServiceProxy(ServiceNameCardService)
	if err != nil {
		return nil, err
	}

	envelope := &cardservice81.ChangePinEnvelope{
		ChangePin: &cardservice81.ChangePin{
			Context:    c.connectorContext(),
			CardHandle: cardHandle,
			PinTyp:     string(pinTyp),
		},
	}

	var resp cardservice81.ChangePinResponseEnvelope
	if err := proxy.Call(ctx, &cardservice81.OperationChangePin, envelope, &resp); err != nil {
		return nil, fmt.Errorf("ChangePin: %w", err)
	}

	if resp.Fault != nil {
		return nil, fmt.Errorf("ChangePin SOAP fault: %s", resp.Fault.String)
	}
	if resp.ChangePinResponse == nil {
		return nil, fmt.Errorf("ChangePin: empty response")
	}

	return resp.ChangePinResponse, nil
}
