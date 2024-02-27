package reg

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"net/http"

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

func (s *RegistrationService) ValidateMessageAttestation(message []byte, format AttestationFormat, data []byte, lastAttestation *AttestationEntity) (*AttestationEntity, error) {
	slog.Info("validating message attestation", "format", format, "lastAttestation", lastAttestation)
	attestor := getAttestor(format)
	if attestor == nil {
		return nil, fmt.Errorf("unsupported attestation format: %s", format)
	}
	return attestor.verifyMessageAttestation(message, data, lastAttestation)
}

func (s *RegistrationService) CreateRegistration(registration *RegistrationEntity) (*RegistrationEntity, error) {
	var err error

	if registration.Attestation == nil {
		return nil, ErrAttestationRequired
	}

	thumbprint, err := registration.Jwk.ThumbprintString(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("unable to calculate thumbprint: %w", err)
	}

	reg, err := s.store.FindRegistrationByThumbprint(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("unable to find registration: %w", err)
	} else if reg != nil {
		return nil, &ClientError{
			StatusCode:       http.StatusConflict,
			ErrorCode:        "registration_exists",
			ErrorDescription: "Registration already exists",
		}
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

	registration.JwkThumbprint, err = registration.Jwk.ThumbprintString(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("unable to calculate thumbprint: %w", err)
	}

	registration.Status = RegistrationStatusPending

	if err := s.store.UpsertRegistration(registration); err != nil {
		return nil, fmt.Errorf("unable to create registration: %w", err)
	}

	s.assertChallengesAndRegister(registration)

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
		subject := pkix.Name{CommonName: fmt.Sprintf("id:%s attestation-format:%s", clientID, registration.Attestation.Format)}
		cert, err := s.clientsCA.SignCertificateRequest(typedCsr, subject)
		if err != nil {
			return nil, fmt.Errorf("unable to issue certificate: %w", err)
		}

		client.Certificate = cert.Raw
		registration.ClientCertificate = cert.Raw

		slog.Info("issued client certificate", "client", client.ID, "name", client.Name, "subject", cert.Subject)
	}

	if err := s.store.UpsertClient(client); err != nil {
		return nil, fmt.Errorf("unable to store client: %w", err)
	}

	slog.Info("registration complete", "client", client.ID, "name", client.Name)
	return client, nil
}
