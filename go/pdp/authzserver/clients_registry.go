// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package authzserver

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// Client is a registered instance of a Product. A product may have many client instances; each
// authenticates with private_key_jwt (RFC 7523), proving itself with a client_assertion verified
// against PublicJWK. Redirect-URI and scope policy live on the Product the client belongs to.
type Client struct {
	ClientID  string `yaml:"client_id" json:"client_id"`
	ProductID string `yaml:"product_id" json:"product_id"`
	// PublicJWK is the client's assertion-verification key as a nested JWK object. It is parsed into
	// a key once at registry-build time (see Key).
	PublicJWK map[string]any `yaml:"public_jwk" json:"public_jwk"`

	key *jose.JSONWebKey
}

// Key returns the parsed public JWK used to verify the client's assertions.
func (c *Client) Key() *jose.JSONWebKey { return c.key }

// ClientsRegistry resolves a client_id to its registered Client. GetClient returns an error for an unknown
// client.
type ClientsRegistry interface {
	GetClient(clientID string) (*Client, error)
}

// StaticClientsRegistry is a ClientsRegistry over a fixed list of clients from the configuration.
type StaticClientsRegistry struct {
	clients map[string]*Client
}

// NewStaticClientsRegistry parses each client's public JWK and indexes the clients by client_id.
func NewStaticClientsRegistry(clients []Client) (*StaticClientsRegistry, error) {
	indexed := make(map[string]*Client, len(clients))
	for i := range clients {
		c := clients[i]
		key, err := parsePublicJWK(c.PublicJWK)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", c.ClientID, err)
		}
		c.key = key
		indexed[c.ClientID] = &c
	}
	return &StaticClientsRegistry{clients: indexed}, nil
}

// GetClient returns the client registered under clientID, or an error if there is none.
func (r *StaticClientsRegistry) GetClient(clientID string) (*Client, error) {
	if c, ok := r.clients[clientID]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("client not found: %q", clientID)
}

func parsePublicJWK(raw map[string]any) (*jose.JSONWebKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing public_jwk")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal public_jwk: %w", err)
	}
	key, err := oidc.ParseKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse public_jwk: %w", err)
	}
	return key, nil
}
