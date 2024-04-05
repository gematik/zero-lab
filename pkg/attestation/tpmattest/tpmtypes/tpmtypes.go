package tpmtypes

import (
	"strings"

	"github.com/google/go-attestation/attest"
)

type EK struct {
	CertificateRaw []byte `json:"certificate" validate:"required"`
	CertificateURL string `json:"certificate_url,omitempty" validate:"omitempty"`
}

func NewEK(ek attest.EK) EK {
	return EK{
		CertificateRaw: ek.Certificate.Raw,
		CertificateURL: ek.CertificateURL,
	}
}

func (ek EK) AttestEK() (*attest.EK, error) {
	cert, err := attest.ParseEKCertificate(ek.CertificateRaw)
	if err != nil {
		return nil, err
	}
	return &attest.EK{
		Certificate:    cert,
		CertificateURL: ek.CertificateURL,
	}, nil
}

func (ek EK) String() string {
	sb := strings.Builder{}
	if string(ek.CertificateRaw) != "" {
		attestEK, err := ek.AttestEK()
		if err != nil {
			sb.WriteString(" Certificate:")
			sb.WriteString(err.Error())
		} else {
			if attestEK.Certificate.Subject.String() != "" {
				sb.WriteString(" Certificate.Subject:")
				sb.WriteString(attestEK.Certificate.Subject.String())
			}
			sb.WriteString(" Certificate.Issuer:")
			sb.WriteString(attestEK.Certificate.Issuer.String())
			sb.WriteString(" Certificate.PublicKeyAlgorithm:")
			sb.WriteString(attestEK.Certificate.PublicKeyAlgorithm.String())
			sb.WriteString(" Certificate.SignatureAlgorithm:")
			sb.WriteString(attestEK.Certificate.SignatureAlgorithm.String())
			sb.WriteString(" Certificate.SerialNumber:")
			sb.WriteString(attestEK.Certificate.SerialNumber.String())
			sb.WriteString(" Certificate.NotBefore:")
			sb.WriteString(attestEK.Certificate.NotBefore.String())
			sb.WriteString(" Certificate.NotAfter:")
			sb.WriteString(attestEK.Certificate.NotAfter.String())
		}
	}
	if ek.CertificateURL != "" {
		sb.WriteString(" CertificateURL:")
		sb.WriteString(ek.CertificateURL)
	}
	return strings.Trim(sb.String(), " ")
}

type AttestationParameters struct {
	Public                  []byte `json:"public" validate:"required"`
	UseTCSDActivationFormat bool   `json:"use_tcsd_activation_format" validate:"required"`
	CreateData              []byte `json:"create_data" validate:"required"`
	CreateAttestation       []byte `json:"create_attestation" validate:"required"`
	CreateSignature         []byte `json:"create_signature" validate:"required"`
}

func NewAttestationParameters(ak attest.AttestationParameters) AttestationParameters {
	return AttestationParameters{
		Public:                  ak.Public,
		UseTCSDActivationFormat: ak.UseTCSDActivationFormat,
		CreateData:              ak.CreateData,
		CreateAttestation:       ak.CreateAttestation,
		CreateSignature:         ak.CreateSignature,
	}
}

func (j *AttestationParameters) AttestationParameters() attest.AttestationParameters {
	return attest.AttestationParameters{
		Public:                  j.Public,
		UseTCSDActivationFormat: j.UseTCSDActivationFormat,
		CreateData:              j.CreateData,
		CreateAttestation:       j.CreateAttestation,
		CreateSignature:         j.CreateSignature,
	}
}

type ActivationRequest struct {
	TPMVersion string                `json:"tpm_version" validate:"required"`
	EKs        []EK                  `json:"endorsement_keys" validate:"required"`
	AK         AttestationParameters `json:"attestation_key" validate:"required"`
}

func (j *ActivationRequest) AttestTPMVersion() attest.TPMVersion {
	var version attest.TPMVersion
	switch j.TPMVersion {
	case "1.2":
		version = attest.TPMVersion12
	case "2.0":
		version = attest.TPMVersion20
	default:
		version = attest.TPMVersionAgnostic
	}
	return version
}

func TPMVersionString(version attest.TPMVersion) string {
	switch version {
	case attest.TPMVersion12:
		return "1.2"
	case attest.TPMVersion20:
		return "2.0"
	default:
		return "agnostic"
	}
}
