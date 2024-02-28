package reg

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gematik/zero-lab/pkg/attestation/dcappattest"
)

type attestorAppleAttestation struct {
}

func (a *attestorAppleAttestation) verifyMessageAttestation(message, attestationData []byte, lastAttestation *AttestationEntity) (*AttestationEntity, error) {
	messageHash := sha256.Sum256(message)
	attestation, err := dcappattest.ParseAttestation(attestationData, messageHash)
	if err != nil {
		slog.Error("unable to parse attestation", "message", string(message))
		return nil, fmt.Errorf("unable to parse attestation: %w", err)
	}
	slog.Info("Apple attestation is valid", "rpIdHash", base64.RawURLEncoding.EncodeToString(attestation.AuthenticatorData.RpidHash))
	return &AttestationEntity{
		Format: AttestationFormatAppleAttestation,
		Data:   attestation,
	}, nil
}

func (a *attestorAppleAttestation) validateClientPosture(client *ClientEntity, attestation *AttestationEntity) (*AttestationEntity, error) {
	return nil, errors.New("not implemented")
}

type attestorAppleAssertion struct {
}

func (a *attestorAppleAssertion) verifyMessageAttestation(message, attestationData []byte, lastAttestation *AttestationEntity) (*AttestationEntity, error) {
	messageHash := sha256.Sum256(message)
	attestation := lastAttestation.Data.(*dcappattest.Attestation)
	pubKey := attestation.AttestationStatement.CredCert.PublicKey
	counter := attestation.AuthenticatorData.Count
	assertion, err := dcappattest.ParseAssertion(attestationData, messageHash, pubKey, counter)
	if err != nil {
		slog.Error("unable to parse assertion", "message", string(message))
		return nil, fmt.Errorf("unable to parse assertion: %w", err)
	}
	// update counter
	attestation.AuthenticatorData.Count = assertion.AuthenticatorData.Count
	slog.Info("Apple assertion is valid", "count", assertion.AuthenticatorData.Count)
	return lastAttestation, nil
}

func (a *attestorAppleAssertion) validateClientPosture(client *ClientEntity, attestation *AttestationEntity) (*AttestationEntity, error) {
	return nil, errors.New("not implemented")
}
