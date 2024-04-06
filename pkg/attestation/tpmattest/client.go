package tpmattest

import (
	"github.com/google/go-attestation/attest"
)

func CreateAttestationRequest(tpm *attest.TPM, eks []attest.EK, ak *attest.AttestationParameters) (*AttestationRequest, error) {
	ek := eks[0]

	ar := &AttestationRequest{
		TPMVersionString:   TPMVersionString(tpm.Version()),
		EndorsementCertRaw: ek.Certificate.Raw,
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
