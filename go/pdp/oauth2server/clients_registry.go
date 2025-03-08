package oauth2server

import (
	"fmt"
)

type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

type ClientMetadata struct {
	Type             ClientType `yaml:"type" json:"type" validate:"required,oneof=confidential public"`
	ClientID         string     `yaml:"client_id" json:"client_id" validate:"required"`
	ClientSecretHash string     `yaml:"client_secret_hash" json:"client_secret_hash"`
	RedirectURIs     []string   `yaml:"redirect_uris" json:"redirect_uris"`
	Scopes           []string   `yaml:"scopes" json:"scopes"`
	ClientName       string     `yaml:"client_name" json:"client_name"`
	LogoURI          string     `yaml:"logo_uri" json:"logo_uri"`
}

type ClientsRegistry interface {
	GetClientMetadata(clientID string) (*ClientMetadata, error)
}

type StaticClientsRegistry struct {
	// list of clients
	Clients []ClientMetadata `yaml:"clients" json:"clients" validate:"required,dive,required"`
}

func (r *StaticClientsRegistry) GetClientMetadata(clientID string) (*ClientMetadata, error) {
	if r.Clients == nil {
		return nil, fmt.Errorf("no clients configured")
	}
	for _, client := range r.Clients {
		if client.ClientID == clientID {
			return &client, nil
		}
	}
	return nil, fmt.Errorf("client not found: '%s'", clientID)
}

func (m *ClientMetadata) IsAllowedRedirectURI(redirectURI string) bool {
	for _, uri := range m.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

func (m *ClientMetadata) IsAllowedScope(scope string) bool {
	for _, s := range m.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (m *ClientMetadata) IsAllowedScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !m.IsAllowedScope(scope) {
			return false
		}
	}
	return true
}
