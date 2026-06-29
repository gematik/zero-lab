package kon

import (
	"context"
	"fmt"
	"strings"

	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservice81"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/cardservicecommon20"
)

type PinTyp string

const (
	PinTypCH  PinTyp = "PIN.CH"
	PinTypQES PinTyp = "PIN.QES"
	PinTypSMC PinTyp = "PIN.SMC"
)

var AllPinTypes = []PinTyp{PinTypCH, PinTypQES, PinTypSMC}

// PinTypesByCardType maps card types to the PIN types accepted by VerifyPin/ChangePin.
// SM-B and HSM-B are normalized to SMC-B by PinTypesForCardType.
var PinTypesByCardType = map[cardservicecommon20.CardType][]PinTyp{
	cardservicecommon20.CardTypeHba:  {PinTypCH, PinTypQES},
	cardservicecommon20.CardTypeSmcB: {PinTypSMC},
	cardservicecommon20.CardTypeEgk:  {PinTypCH},
}

// PinTypesForCardType returns the PIN types supported by the given card type,
// or nil if the card type has no user-facing PINs (e.g. SMC-KT).
func PinTypesForCardType(cardType cardservicecommon20.CardType) []PinTyp {
	if cardType == cardservicecommon20.CardTypeHsmB || cardType == cardservicecommon20.CardTypeSmB {
		cardType = cardservicecommon20.CardTypeSmcB
	}
	return PinTypesByCardType[cardType]
}

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
