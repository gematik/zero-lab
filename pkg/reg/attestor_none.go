package reg

import (
	"errors"
	"fmt"
	"log/slog"
)

type attestorNone struct {
}

func (a *attestorNone) verifyMessageAttestation(message, data []byte, lastAttestation *AttestationEntity) (*AttestationEntity, error) {
	slog.Error("unsafe attestation format", "format", AttestationFormatNone)
	return &AttestationEntity{
		Format: AttestationFormatNone,
		Data:   nil,
	}, nil
}

func (a *attestorNone) validateClientPosture(client *ClientEntity) error {
	if client.Attestation.Format != AttestationFormatNone {
		return errors.New("invalid attestation format")
	}
	if client.Platform != ClientPlatformSoftware {
		return fmt.Errorf("invalid platform / attestation combination: '%s' / '%s'", client.Platform, client.Attestation.Format)
	}

	return nil
}
