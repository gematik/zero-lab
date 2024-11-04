package authzserver

import (
	"fmt"
)

type ClientMetadata struct {
	ClientID     string   `yaml:"client_id" json:"client_id" validate:"required"`
	ClientSecret string   `yaml:"client_secret" json:"client_secret"`
	RedirectURIs []string `yaml:"redirect_uris" json:"redirect_uris"`
}

type ClientsRegistry interface {
	GetClientMetadata(clientID string) (*ClientMetadata, error)
}

type StaticClientsRegistry struct {
	// list of clients
	Clients []*ClientMetadata `yaml:"clients" json:"clients" validate:"required,dive,required"`
}

func (r *StaticClientsRegistry) GetClientMetadata(clientID string) (*ClientMetadata, error) {
	for _, client := range r.Clients {
		if client.ClientID == clientID {
			return client, nil
		}
	}
	return nil, fmt.Errorf("client not found: '%s'", clientID)
}

func (m *ClientMetadata) AllowedRedirectURI(redirectURI string) bool {
	for _, uri := range m.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}
