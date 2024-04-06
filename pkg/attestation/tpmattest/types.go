package tpmattest

import (
	"strings"

	"github.com/google/go-attestation/attest"
)

type endorsementKey struct {
	CertificateRaw []byte `json:"certificate" validate:"required"`
	CertificateURL string `json:"certificate_url,omitempty" validate:"omitempty"`
}

func (ek endorsementKey) convert() (*attest.EK, error) {
	cert, err := attest.ParseEKCertificate(ek.CertificateRaw)
	if err != nil {
		return nil, err
	}
	return &attest.EK{
		Public:         cert.PublicKey,
		Certificate:    cert,
		CertificateURL: ek.CertificateURL,
	}, nil
}

func (ek endorsementKey) String() string {
	sb := strings.Builder{}
	if string(ek.CertificateRaw) != "" {
		attestEK, err := ek.convert()
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

type attestationParameters struct {
	Public                  []byte `json:"public" validate:"required"`
	UseTCSDActivationFormat bool   `json:"use_tcsd_activation_format"`
	CreateData              []byte `json:"create_data" validate:"required"`
	CreateAttestation       []byte `json:"create_attestation" validate:"required"`
	CreateSignature         []byte `json:"create_signature" validate:"required"`
}

func (j *attestationParameters) convert() attest.AttestationParameters {
	return attest.AttestationParameters{
		Public:                  j.Public,
		UseTCSDActivationFormat: j.UseTCSDActivationFormat,
		CreateData:              j.CreateData,
		CreateAttestation:       j.CreateAttestation,
		CreateSignature:         j.CreateSignature,
	}
}

type AttestationRequest struct {
	TPMVersionString      string                `json:"tpm_version" validate:"required"`
	EndorsementKeys       []endorsementKey      `json:"endorsement_keys" validate:"required"`
	AttestationParameters attestationParameters `json:"attestation_key" validate:"required"`
}

func (ar *AttestationRequest) ConvertParameters() attest.AttestationParameters {
	return ar.AttestationParameters.convert()
}

func (ar *AttestationRequest) TPMVersion() attest.TPMVersion {
	var version attest.TPMVersion
	switch ar.TPMVersionString {
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

type EncryptedCredential struct {
	Credential []byte `json:"credential" validate:"required"`
	Secret     []byte `json:"secret" validate:"required"`
}

func (ec EncryptedCredential) Convert() *attest.EncryptedCredential {
	return &attest.EncryptedCredential{
		Credential: ec.Credential,
		Secret:     ec.Secret,
	}
}
