package reg

import (
	"errors"
	"time"

	"github.com/gematik/zero-lab/go/libzero/util"
)

type AccountEntity struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

type ClientPlatform string

const (
	ClientPlatformAndroid  ClientPlatform = "android"
	ClientPlatformApple    ClientPlatform = "apple"
	ClientPlatformSoftware ClientPlatform = "software"
)

func ParseClientPlatform(s string) (ClientPlatform, error) {
	switch s {
	case "android":
		return ClientPlatformAndroid, nil
	case "apple":
		return ClientPlatformApple, nil
	case "software":
		return ClientPlatformSoftware, nil
	default:
		return "", errors.New("unknown client platform")
	}
}

type AttestationFormat string

const (
	AttestationFormatAndroidKeyID     AttestationFormat = "android-key-id"
	AttestationFormatAppleAttestation AttestationFormat = "apple-attestation"
	AttestationFormatAppleAssertion   AttestationFormat = "apple-assertion"
	AttestationFormatNone             AttestationFormat = "none"
	AttestationFormatGempki           AttestationFormat = "gempki"
)

func ParseAttestationFormat(s string) (AttestationFormat, error) {
	switch s {
	case "apple-attestation":
		return AttestationFormatAppleAttestation, nil
	case "apple-assertion":
		return AttestationFormatAppleAssertion, nil
	case "android-key-id":
		return AttestationFormatAndroidKeyID, nil
	case "none":
		return AttestationFormatNone, nil
	case "gempki":
		return AttestationFormatGempki, nil
	default:
		return "", errors.New("unknown attestation format")
	}
}

type ClientEntity struct {
	ID                    string             `json:"id"`
	Thumbprint            string             `json:"thumbprint"`
	Name                  string             `json:"name"`
	AccountID             string             `json:"accountId"`
	RegistrationTimestamp time.Time          `json:"registrationTimestamp"`
	Platform              ClientPlatform     `json:"platform"`
	Jwk                   *util.Jwk          `json:"jwk"`
	Csr                   []byte             `json:"csr,omitempty"`
	Certificate           []byte             `json:"certificate,omitempty"`
	Attestation           *AttestationEntity `json:"attestation"`
	Posture               interface{}        `json:"posture"`
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
	RegistrationChallengeTypeOIDC    RegistrationChallengeType = "oidc"
	RegistrationChallengeTypeOIDF    RegistrationChallengeType = "oidf"
	RegistrationChallengeTypeOffband RegistrationChallengeType = "offband"
)

type RegistrationChallengeEntity struct {
	Type   RegistrationChallengeType `json:"type"`
	URL    string                    `json:"url"`
	Status string                    `json:"status"`
}

type RegistrationEntity struct {
	ID            string                         `json:"id"`
	JwkThumbprint string                         `json:"jkt"`
	Iss           string                         `json:"iss,omitempty"`
	Status        RegistrationStatus             `json:"status"`
	Challenges    []*RegistrationChallengeEntity `json:"challenges"`
	Client        *ClientEntity                  `json:"client"`
}

type AuthSessionEntity struct {
	Iss          string `json:"idp"`
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
}

type AttestationEntity struct {
	Format AttestationFormat
	Data   interface{}
}

type ClientDescriptorEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type PostureSoftware struct {
	OS        string `json:"os" validate:"required"`
	OSVersion string `json:"osVersion" validate:"required"`
	Arch      string `json:"arch" validate:"required"`
}
