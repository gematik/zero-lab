package tpmattest

import (
	"crypto/x509"

	"github.com/gematik/zero-lab/go/libzero/nonce"
	"github.com/google/go-attestation/attest"
)

type Attestation struct {
	AttestationKeyRaw         []byte                  `json:"attestation_key"`
	AttestationCertificateRaw []byte                  `json:"attestation_certificate"`
	CertificationParameters   CertificationParameters `json:"certification_parameters"`
	ClientKeyRaw              []byte                  `json:"client_key"`
	ClientCertificateRaw      []byte                  `json:"client_certificate"`
	Csr                       []byte                  `json:"csr"`
}

type AttestationStore interface {
	SaveTPMAttestation(attestation *Attestation) error
	GetTPMAttestation(id string) (*Attestation, error)
}

func NewKeyAttestation(clientKey *attest.Key, ak *attest.AK, attestationCert *x509.Certificate) *AttestationRequest {
	certParams := clientKey.CertificationParameters()
	return &AttestationRequest{
		AttestationCertificateRaw: attestationCert.Raw,
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
	AttestationCertificateRaw []byte                  `json:"attestation_certificate"`
	Csr                       []byte                  `json:"csr"`
	CertificationParameters   CertificationParameters `json:"certification_parameters"`
}

type AttestationService struct {
	nonceService nonce.NonceService
}
