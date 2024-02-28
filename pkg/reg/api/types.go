package api

import "github.com/gematik/zero-lab/pkg/reg"

type RegistrationResponse struct {
	ID                string                   `json:"id"`
	Status            reg.RegistrationStatus   `json:"status"`
	Challenges        []*RegistrationChallenge `json:"challenges"`
	ClientID          string                   `json:"clientId,omitempty"`
	ClientUrl         string                   `json:"clientUrl,omitempty"`
	ClientCertificate []byte                   `json:"clientCertificate,omitempty"`
}

type RegistrationChallenge struct {
	Type   reg.RegistrationChallengeType `json:"type"`
	URL    string                        `json:"url"`
	Status string                        `json:"status"`
}

type RegistrationRequest struct {
	Name     string      `json:"name" validate:"required"`
	Iss      string      `json:"iss,omitempty"`
	Csr      []byte      `json:"csr,omitempty"`
	Platform string      `json:"platform"`
	Posture  interface{} `json:"posture"`
}
