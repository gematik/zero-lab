package tpmattest

import (
	"github.com/gematik/zero-lab/pkg/nonce"
	"github.com/google/go-attestation/attest"
)

type Attestation struct {
	AKRaw            []byte `json:"ak"`
	AKPub            []byte `json:"ak_pub"`
	AKCertificateRaw []byte `json:"ak_certificate"`
	KeyRaw           []byte `json:"key"`
	CertRaw          []byte `json:"cert"`
}

type AttestationStore interface {
	SaveTPMAttestation(attestation *Attestation) error
	GetTPMAttestation(id string) (*Attestation, error)
}

func NewAttestationRequest(clientKey *attest.Key) *AttestationRequest {
	certParams := clientKey.CertificationParameters()
	return &AttestationRequest{
		CertificationParameters: CertificationParameters{
			Public:            certParams.Public,
			CreateData:        certParams.CreateData,
			CreateAttestation: certParams.CreateAttestation,
			CreateSignature:   certParams.CreateSignature,
		},
	}
}

// wrapper for go-attestation attest.CertificateParameters to be used in JSON
type CertificationParameters struct {
	Public            []byte `json:"public"`
	CreateData        []byte `json:"create_data"`
	CreateAttestation []byte `json:"create_attestation"`
	CreateSignature   []byte `json:"create_signature"`
}

type AttestationRequest struct {
	CertificationParameters CertificationParameters `json:"certification_parameters"`
}

type AttestationService struct {
	nonceService nonce.NonceService
}
