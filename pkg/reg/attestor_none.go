package reg

import (
	"errors"
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

func (a *attestorNone) validateClientPosture(client *ClientEntity, attestation *AttestationEntity) (*AttestationEntity, error) {
	return nil, errors.New("not implemented")
}
