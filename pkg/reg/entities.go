package reg

import (
	"errors"
	"time"

	"github.com/gematik/zero-lab/pkg/util"
)

type AccountEntity struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

type ClientType string

const (
	ClientTypeAndroid ClientType = "android"
	ClientTypeApple   ClientType = "apple"
)

type AttestationFormat string

const (
	AttestationFormatAndroidKeyID     AttestationFormat = "android-key-id"
	AttestationFormatAppleAttestation AttestationFormat = "apple-attestation"
	AttestationFormatAppleAssertion   AttestationFormat = "apple-assertion"
)

func ParseAttestationFormat(s string) (AttestationFormat, error) {
	switch s {
	case "apple-attestation":
		return AttestationFormatAppleAttestation, nil
	case "apple-assertion":
		return AttestationFormatAppleAssertion, nil
	default:
		return "", errors.New("unknown attestation format")
	}
}

type ClientEntity struct {
	ID          string             `json:"id"`
	Thumbprint  string             `json:"thumbprint"`
	Name        string             `json:"name"`
	AccountID   string             `json:"accountId"`
	DateAdded   time.Time          `json:"dateAdded"`
	Type        ClientType         `json:"type"`
	Jwk         *util.Jwk          `json:"jwk"`
	Csr         []byte             `json:"csr,omitempty"`
	Certificate []byte             `json:"certificate,omitempty"`
	Attestation *AttestationEntity `json:"attestation"`
}

type RegistrationStatus string

const (
	RegistrationStatusPending  RegistrationStatus = "pending"
	RegisterStatusError        RegistrationStatus = "error"
	RegisterStatusCancelled    RegistrationStatus = "cancelled"
	RegistrationStatusComplete RegistrationStatus = "complete"
)

type RegistrationChallengeType string

const (
	RegistrationChallengeTypeOIDC RegistrationChallengeType = "oidc"
)

type RegistrationChallengeEntity struct {
	Type   RegistrationChallengeType `json:"type"`
	URL    string                    `json:"url"`
	Status string                    `json:"status"`
}

type RegistrationEntity struct {
	ID                string                         `json:"id"`
	JwkThumbprint     string                         `json:"jkt"`
	Name              string                         `json:"name"`
	Status            RegistrationStatus             `json:"status"`
	Csr               []byte                         `json:"csr,omitempty"`
	Jwk               *util.Jwk                      `json:"jwk"`
	Attestation       *AttestationEntity             `json:"attestation"`
	Challenges        []*RegistrationChallengeEntity `json:"challenges"`
	ClientID          string                         `json:"clientId,omitempty"`
	ClientCertificate []byte                         `json:"clientCertificate,omitempty"`
}

type AuthSessionEntity struct {
	Idp          string `json:"idp"`
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
}

type AttestationEntity struct {
	Format AttestationFormat
	Value  interface{}
}

type ClientDescriptorEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}
