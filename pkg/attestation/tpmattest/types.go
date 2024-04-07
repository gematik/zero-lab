package tpmattest

import (
	"crypto/x509"
	"fmt"

	"github.com/google/go-attestation/attest"
)

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

type EndorsementKey struct {
	Public         []byte `json:"public_key" validate:"required"`
	CertificateRaw []byte `json:"certificate,omitempty"`
	CertificateURL string `json:"certificate_url,omitempty"`
}

type AttestationRequest struct {
	TPMVersionString      string                `json:"tpm_version" validate:"required"`
	EndorsementKey        EndorsementKey        `json:"endorsement_key" validate:"required"`
	AttestationParameters attestationParameters `json:"attestation_params" validate:"required"`
}

func (ar AttestationRequest) ConvertEK() (*attest.EK, error) {

	ekPuk, err := x509.ParsePKIXPublicKey(ar.EndorsementKey.Public)
	if err != nil {
		return nil, fmt.Errorf("parsing EK public key: %w", err)
	}

	ek := attest.EK{
		Public: ekPuk,
	}

	if len(ar.EndorsementKey.CertificateRaw) > 0 {
		cert, err := attest.ParseEKCertificate(ar.EndorsementKey.CertificateRaw)
		if err != nil {
			return nil, err
		}
		ek.Certificate = cert
	}

	return &ek, nil
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

type ChallengeStatus string

const (
	ChallengeStatusPending ChallengeStatus = "pending"
	ChallengeStatusValid   ChallengeStatus = "valid"
	ChallengeStatusInvalid ChallengeStatus = "invalid"
	ChallengeStatusExpired ChallengeStatus = "expired"
)

type AttestationChallenge struct {
	ID         string          `json:"id" validate:"required"`
	Credential []byte          `json:"credential" validate:"required"`
	Secret     []byte          `json:"secret" validate:"required"`
	Status     ChallengeStatus `json:"status" validate:"required"`
}

func (ac AttestationChallenge) EncryptedCredential() attest.EncryptedCredential {
	return attest.EncryptedCredential{
		Credential: ac.Credential,
		Secret:     ac.Secret,
	}
}

type AttestationChallengeResponse struct {
	DecryptedSecret []byte `json:"decrypted_secret" validate:"required"`
}
