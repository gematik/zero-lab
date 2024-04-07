package tpmattest

import (
	"crypto/x509"
	"fmt"

	"github.com/google/go-attestation/attest"
)

func CreateAttestationRequest(tpm *attest.TPM, ek attest.EK, ak *attest.AttestationParameters) (*AttestationRequest, error) {
	ekBytes, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return nil, fmt.Errorf("marshaling EK public key: %w", err)
	}

	ar := &AttestationRequest{
		TPMVersionString: TPMVersionString(tpm.Version()),
		EndorsementKey: EndorsementKey{
			Public: ekBytes,
		},
		AttestationParameters: attestationParameters{
			Public:                  ak.Public,
			UseTCSDActivationFormat: ak.UseTCSDActivationFormat,
			CreateData:              ak.CreateData,
			CreateAttestation:       ak.CreateAttestation,
			CreateSignature:         ak.CreateSignature,
		},
	}

	return ar, nil
}
