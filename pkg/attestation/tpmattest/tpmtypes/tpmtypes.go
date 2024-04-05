package tpmtypes

import (
	"fmt"

	"github.com/google/go-attestation/attest"
)

type EK struct {
	CertificateRaw []byte `json:"certificate" validate:"required"`
	CertificateURL string `json:"certificate_url,omitempty" validate:"omitempty"`
}

func NewEK(ek *attest.EK) *EK {
	return &EK{
		CertificateRaw: ek.Certificate.Raw,
		CertificateURL: ek.CertificateURL,
	}
}

func (j *EK) Certificate() (*attest.EK, error) {
	cert, err := attest.ParseEKCertificate(j.CertificateRaw)
	if err != nil {
		return nil, err
	}
	return &attest.EK{
		Certificate:    cert,
		CertificateURL: j.CertificateURL,
	}, nil
}

type AttestationParameters struct {
	Public                  []byte `json:"public" validate:"required"`
	UseTCSDActivationFormat bool   `json:"use_tcsd_activation_format" validate:"required"`
	CreateData              []byte `json:"create_data" validate:"required"`
	CreateAttestation       []byte `json:"create_attestation" validate:"required"`
	CreateSignature         []byte `json:"create_signature" validate:"required"`
}

func NewAttestationParameters(ak *attest.AttestationParameters) *AttestationParameters {
	return &AttestationParameters{
		Public:                  ak.Public,
		UseTCSDActivationFormat: ak.UseTCSDActivationFormat,
		CreateData:              ak.CreateData,
		CreateAttestation:       ak.CreateAttestation,
		CreateSignature:         ak.CreateSignature,
	}
}

func (j *AttestationParameters) AttestationParameters() *attest.AttestationParameters {
	return &attest.AttestationParameters{
		Public:                  j.Public,
		UseTCSDActivationFormat: j.UseTCSDActivationFormat,
		CreateData:              j.CreateData,
		CreateAttestation:       j.CreateAttestation,
		CreateSignature:         j.CreateSignature,
	}
}

type ActivationParameters struct {
	TPMVersion int                    `json:"tpm_version" validate:"required"`
	EK         *EK                    `json:"ek" validate:"required"`
	AK         *AttestationParameters `json:"ak" validate:"required"`
}

func (j *ActivationParameters) ActivationParameters() (*attest.ActivationParameters, error) {
	var version attest.TPMVersion
	switch j.TPMVersion {
	case 0:
		version = attest.TPMVersionAgnostic
	case 12:
		version = attest.TPMVersion12
	case 20:
		version = attest.TPMVersion20
	default:
		return nil, fmt.Errorf("unsupported TPM version: %d", j.TPMVersion)
	}

	ekCert, err := j.EK.Certificate()
	if err != nil {
		return nil, fmt.Errorf("failed to parse EK certificate: %v", err)
	}

	return &attest.ActivationParameters{
		TPMVersion: version,
		EK:         ekCert.Public,
		AK:         *j.AK.AttestationParameters(),
	}, nil
}
