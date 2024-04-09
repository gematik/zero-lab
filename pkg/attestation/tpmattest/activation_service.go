package tpmattest

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"

	"github.com/gematik/zero-lab/pkg/ca"
	"github.com/google/go-attestation/attest"
	"github.com/segmentio/ksuid"
)

type EndorsementKey struct {
	PublicKeyRaw   []byte `json:"public_key" validate:"required"`
	CertificateRaw []byte `json:"certificate,omitempty"`
	CertificateURL string `json:"certificate_url,omitempty"`
}

func (e *EndorsementKey) Convert() (*attest.EK, error) {
	ekPuk, err := x509.ParsePKIXPublicKey(e.PublicKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing EK public key: %w", err)
	}

	ek := attest.EK{
		Public: ekPuk,
	}

	if len(e.CertificateRaw) > 0 {
		cert, err := attest.ParseEKCertificate(e.CertificateRaw)
		if err != nil {
			return nil, err
		}
		ek.Certificate = cert
	}

	return &ek, nil
}

type AttestationParameters struct {
	Public                  []byte `json:"public" validate:"required"`
	UseTCSDActivationFormat bool   `json:"use_tcsd_activation_format"`
	CreateData              []byte `json:"create_data" validate:"required"`
	CreateAttestation       []byte `json:"create_attestation" validate:"required"`
	CreateSignature         []byte `json:"create_signature" validate:"required"`
}

// convert converts the JSON representation to go-attestation type
func (j *AttestationParameters) Convert() attest.AttestationParameters {
	return attest.AttestationParameters{
		Public:                  j.Public,
		UseTCSDActivationFormat: j.UseTCSDActivationFormat,
		CreateData:              j.CreateData,
		CreateAttestation:       j.CreateAttestation,
		CreateSignature:         j.CreateSignature,
	}
}

type ActivationRequest struct {
	TPMVersionString      string                `json:"tpm_version" validate:"required"`
	EndorsementKey        EndorsementKey        `json:"endorsement_key" validate:"required"`
	AttestationParameters AttestationParameters `json:"attestation_params" validate:"required"`
}

func (ar *ActivationRequest) TPMVersion() attest.TPMVersion {
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

type ActivationChallenge struct {
	ID         string          `json:"id" validate:"required"` // same ID as the session
	Credential []byte          `json:"credential" validate:"required"`
	Secret     []byte          `json:"secret" validate:"required"`
	Status     ChallengeStatus `json:"status" validate:"required"`
}

func (ac ActivationChallenge) EncryptedCredential() attest.EncryptedCredential {
	return attest.EncryptedCredential{
		Credential: ac.Credential,
		Secret:     ac.Secret,
	}
}

type ActivationChallengeResponse struct {
	DecryptedSecret []byte `json:"decrypted_secret" validate:"required"`
}

func NewActivationRequest(tpm *attest.TPM, ek attest.EK, ak *attest.AttestationParameters) (*ActivationRequest, error) {
	ekRaw, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return nil, fmt.Errorf("marshaling EK public key: %w", err)
	}

	ar := &ActivationRequest{
		TPMVersionString: TPMVersionString(tpm.Version()),
		EndorsementKey: EndorsementKey{
			PublicKeyRaw: ekRaw,
		},
		AttestationParameters: AttestationParameters{
			Public:                  ak.Public,
			UseTCSDActivationFormat: ak.UseTCSDActivationFormat,
			CreateData:              ak.CreateData,
			CreateAttestation:       ak.CreateAttestation,
			CreateSignature:         ak.CreateSignature,
		},
	}

	return ar, nil
}

type ChallengeVerificationResponse struct {
	ID             string          `json:"id"`
	Status         ChallengeStatus `json:"status"`
	EndorsementKey EndorsementKey  `json:"endorsement_key"`
	AKCertificate  []byte          `json:"ak_certificate"`
}

type ActivationSession struct {
	ID                  string `json:"id"`
	Secret              []byte `json:"secret"`
	EndorsementKey      EndorsementKey
	AttestationKeyRaw   []byte `json:"attestation_key"`
	ActivationChallenge ActivationChallenge
	AKCertificateRaw    []byte `json:"ak_certificate"`
}

type ActivationSessionStore interface {
	SaveActivationSession(session ActivationSession) error
	LoadActivationSession(id string) (*ActivationSession, error)
}

type ActivationService struct {
	store ActivationSessionStore
	ca    ca.CertificateAuthority
}

func (s *ActivationService) NewChallenge(request *ActivationRequest) (*ActivationChallenge, error) {
	slog.Info("Creating new activation session", "request", request)

	ek, err := request.EndorsementKey.Convert()
	if err != nil {
		return nil, fmt.Errorf("parsing EK certificate: %w", err)
	}

	params := attest.ActivationParameters{
		TPMVersion: request.TPMVersion(),
		EK:         ek.Public,
		AK:         request.AttestationParameters.Convert(),
	}

	akPublic, err := attest.ParseAKPublic(request.TPMVersion(), request.AttestationParameters.Public)
	if err != nil {
		return nil, fmt.Errorf("parsing AK public key: %w", err)
	}

	akPublicKeyRaw, err := x509.MarshalPKIXPublicKey(akPublic.Public)
	if err != nil {
		return nil, fmt.Errorf("marshaling AK public key: %w", err)
	}

	secret, encryptedCredential, err := params.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating activation challenge: %w", err)
	}
	id := ksuid.New().String()
	session := ActivationSession{
		ID:                id,
		Secret:            secret,
		EndorsementKey:    request.EndorsementKey,
		AttestationKeyRaw: akPublicKeyRaw,
		ActivationChallenge: ActivationChallenge{
			ID:         id,
			Credential: encryptedCredential.Credential,
			Secret:     encryptedCredential.Secret,
			Status:     ChallengeStatusPending,
		},
	}

	slog.Info("Created new activation session", "id", session.ID)

	s.store.SaveActivationSession(session)

	return &session.ActivationChallenge, nil

}

func (s *ActivationService) VerifyChallenge(id string, response ActivationChallengeResponse) (*ChallengeVerificationResponse, error) {
	slog.Info("Verifying challenge response", "id", id, "response", response)
	session, err := s.store.LoadActivationSession(id)
	if err != nil {
		return nil, fmt.Errorf("loading session: %w", err)
	}
	if bytes.Equal(session.Secret, response.DecryptedSecret) {
		session.ActivationChallenge.Status = ChallengeStatusValid
	} else {
		slog.Warn("Challenge response verification failed", "decrypted_secret", response.DecryptedSecret, "expected_secret", session.Secret)
		session.ActivationChallenge.Status = ChallengeStatusInvalid
	}

	s.store.SaveActivationSession(*session)
	slog.Info("Challenge response verified", "status", session.ActivationChallenge.Status)
	return &ChallengeVerificationResponse{
		ID:             id,
		Status:         session.ActivationChallenge.Status,
		EndorsementKey: session.EndorsementKey,
		AKCertificate:  session.AKCertificateRaw,
	}, nil

}

func NewActivationService() (*ActivationService, error) {
	ca, err := ca.NewMockCA(pkix.Name{
		CommonName: "Zero Trust TPM Activation CA",
	})
	if err != nil {
		return nil, fmt.Errorf("creating mock CA: %w", err)
	}
	return &ActivationService{
		store: &mockActivationSessionStore{
			sessions: make(map[string]ActivationSession),
		},
		ca: ca,
	}, nil
}
