package tpmattest

import (
	"fmt"

	"github.com/google/go-attestation/attest"
)

func CreateAttestationRequest(tpm *attest.TPM, ak *attest.AttestationParameters) (*AttestationRequest, error) {
	tpmEks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("reading EKs from TPM: %w", err)
	}

	eks := make([]endorsementKey, len(tpmEks))
	for i, ek := range tpmEks {
		eks[i] = endorsementKey{
			CertificateRaw: ek.Certificate.Raw,
			CertificateURL: ek.CertificateURL,
		}
	}

	ar := &AttestationRequest{
		TPMVersionString: TPMVersionString(tpm.Version()),
		EndorsementKeys:  eks,
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
