package tpmattest

import (
	"fmt"

	"github.com/google/go-attestation/attest"
)

func CreateAttestationRequest(tpm *attest.TPM, eks []attest.EK, ak *attest.AttestationParameters) (*AttestationRequest, error) {
	tpmEks, err := tpm.EKCertificates()
	if err != nil {
		return nil, fmt.Errorf("reading EKs from TPM: %w", err)
	}

	endorsementKeys := make([]endorsementKey, len(tpmEks))
	for i, ek := range tpmEks {
		endorsementKeys[i] = endorsementKey{
			CertificateRaw: ek.Certificate.Raw,
			CertificateURL: ek.CertificateURL,
		}
	}

	ar := &AttestationRequest{
		TPMVersionString: TPMVersionString(tpm.Version()),
		EndorsementKeys:  endorsementKeys,
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
