package reg

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/pkg/attestation/dcappattest"
	"github.com/gematik/zero-lab/pkg/ca"
	"github.com/gematik/zero-lab/pkg/dpop"
	"github.com/gematik/zero-lab/pkg/nonce"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/oidf"
	"github.com/segmentio/ksuid"
)

type ClientError struct {
	StatusCode       int    `json:"-"`
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e *ClientError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
}

var ErrAttestationRequired = &ClientError{
	StatusCode:       http.StatusBadRequest,
	ErrorCode:        "attestation_required",
	ErrorDescription: "Attestation is required",
}

type RegistrationServiceOption func(*RegistrationService) error

func WithOIDFRelyingParty(rp *oidf.RelyingParty) RegistrationServiceOption {
	return func(s *RegistrationService) error {
		s.oidfRelyingParty = rp
		dpopMiddleware, err := dpop.NewMiddleware(dpop.WithNonce(s.NonceService))
		if err != nil {
			return fmt.Errorf("unable to create dpop middleware: %w", err)
		}
		s.dpopMiddleware = dpopMiddleware
		return nil
	}
}

type RegistrationService struct {
	NonceService     nonce.NonceService
	store            RegistrationStore
	clientsCA        ca.CertificateAuthority
	oidcClient       *oidc.Client
	oidfRelyingParty *oidf.RelyingParty
	dpopMiddleware   *dpop.Middleware
}

func NewRegistrationService(
	nonceService nonce.NonceService,
	store RegistrationStore,
	clientsCA ca.CertificateAuthority,
	opts ...RegistrationServiceOption,
) (*RegistrationService, error) {
	s := &RegistrationService{
		NonceService: nonceService,
		store:        store,
		clientsCA:    clientsCA,
	}

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, fmt.Errorf("unable to apply option: %w", err)
		}
	}

	return s, nil
}

func (s *RegistrationService) ValidateAttestation(message []byte, format AttestationFormat, data interface{}, slug string) (*AttestationEntity, error) {
	if format == AttestationFormatAppleAttestation {
		return s.validateAppleAttestation(message, data.([]byte))
	} else if format == AttestationFormatAppleAssertion {
		return s.validateAppleAssertion(message, data.([]byte), slug)
	} else {
		return nil, fmt.Errorf("unsupported attestation format: %s", format)
	}
}

func (s *RegistrationService) validateAppleAttestation(message []byte, data []byte) (*AttestationEntity, error) {
	messageHash := sha256.Sum256(message)
	attestation, err := dcappattest.ParseAttestation(data, messageHash)
	if err != nil {
		slog.Error("unable to parse attestation", "message", string(message))
		return nil, fmt.Errorf("unable to parse attestation: %w", err)
	}
	slog.Info("Apple attestation is valid", "rpIdHash", base64.RawURLEncoding.EncodeToString(attestation.AuthenticatorData.RpidHash))
	return &AttestationEntity{
		Format: AttestationFormatAppleAttestation,
		Value:  attestation,
	}, nil
}

func (s *RegistrationService) validateAppleAssertion(message []byte, data []byte, slug string) (*AttestationEntity, error) {
	reg, err := s.store.GetRegistration(slug)
	if err != nil {
		return nil, fmt.Errorf("unable to get registration: %w with id '%s'", err, slug)
	}
	messageHash := sha256.Sum256(message)
	attestation := reg.Attestation.Value.(*dcappattest.Attestation)
	pubKey := attestation.AttestationStatement.CredCert.PublicKey
	counter := attestation.AuthenticatorData.Count
	assertion, err := dcappattest.ParseAssertion(data, messageHash, pubKey, counter)
	if err != nil {
		slog.Error("unable to parse assertion", "message", string(message))
		return nil, fmt.Errorf("unable to parse assertion: %w", err)
	}
	// update counter
	attestation.AuthenticatorData.Count = assertion.AuthenticatorData.Count
	slog.Info("Apple assertion is valid", "count", assertion.AuthenticatorData.Count)
	return reg.Attestation, nil
}

func (s *RegistrationService) CreateRegistration(registration *RegistrationEntity) (*RegistrationEntity, error) {
	if registration.Attestation == nil {
		return nil, ErrAttestationRequired
	}
	registration.ID = ksuid.New().String()

	registration.Challenges = []*RegistrationChallengeEntity{}
	if s.oidcClient != nil {
		// add OIDC challenge
		// registration ID is used as OIDC nonce
		oidcAuthURL, err := s.AuthCodeURLOidc(registration.ID)
		if err != nil {
			return nil, err
		}
		oidcChallenge := &RegistrationChallengeEntity{
			Type:   RegistrationChallengeTypeOIDC,
			URL:    oidcAuthURL,
			Status: "pending",
		}
		registration.Challenges = append(registration.Challenges, oidcChallenge)
	} else {
		slog.Warn("no OIDC client configured")
	}

	var err error
	registration.JwkThumbprint, err = registration.Jwk.ThumbprintString(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("unable to calculate thumbprint: %w", err)
	}

	if err := s.store.UpsertRegistration(registration); err != nil {
		return nil, fmt.Errorf("unable to create registration: %w", err)
	}

	registration.Status = RegistrationStatusPending

	return registration, nil
}

func (s *RegistrationService) GetRegistration(id string) (*RegistrationEntity, error) {
	return s.store.GetRegistration(id)
}

func (s *RegistrationService) assertChallengesAndRegister(registration *RegistrationEntity) (*ClientEntity, error) {
	for _, c := range registration.Challenges {
		if c.Status != "valid" {
			slog.Info("challenge not valid", "type", c.Type, "status", c.Status)
			return nil, nil
		}
	}

	registration.Status = RegistrationStatusComplete
	if err := s.store.UpsertRegistration(registration); err != nil {
		return nil, fmt.Errorf("unable to update registration: %w", err)
	}

	clientID := ksuid.New().String()

	client := &ClientEntity{
		ID:          clientID,
		Name:        registration.Name,
		Jwk:         registration.Jwk,
		Attestation: registration.Attestation,
	}

	registration.ClientID = clientID

	if registration.Csr != nil {
		typedCsr, err := x509.ParseCertificateRequest(registration.Csr)
		if err != nil {
			return nil, fmt.Errorf("unable to parse CSR: %w", err)
		}
		cert, err := s.clientsCA.SignCertificateRequest(typedCsr, pkix.Name{CommonName: client.ID})
		if err != nil {
			return nil, fmt.Errorf("unable to issue certificate: %w", err)
		}

		client.Certificate = cert.Raw
		registration.ClientCertificate = cert.Raw
	}

	if err := s.store.UpsertClient(client); err != nil {
		return nil, fmt.Errorf("unable to store client: %w", err)
	}

	slog.Info("registration complete", "client", client.ID, "name", client.Name)
	return client, nil
}

/*
	if client.Csr != nil {
		typedCsr, err := x509.ParseCertificateRequest(client.Csr)
		if err != nil {
			return nil, fmt.Errorf("unable to parse CSR: %w", err)
		}
		cert, err := s.clientsCA.SignCertificateRequest(typedCsr, pkix.Name{CommonName: client.ID})
		if err != nil {
			return nil, fmt.Errorf("unable to issue certificate: %w", err)
		}

		client.Certificate = cert.Raw
	}
*/
