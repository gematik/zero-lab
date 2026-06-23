package authzserver

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Client is a registered instance of a Product. A product may have many client instances; each
// authenticates with private_key_jwt (RFC 7523), proving itself with a client_assertion verified
// against PublicJWK. Redirect-URI and scope policy live on the Product the client belongs to.
type Client struct {
	ClientID  string `yaml:"client_id" json:"client_id" validate:"required"`
	ProductID string `yaml:"product_id" json:"product_id" validate:"required"`
	// PublicJWK is the client's assertion-verification key as a nested JWK object. It is parsed into
	// a jwk.Key once at registry-build time (see Key).
	PublicJWK map[string]any `yaml:"public_jwk" json:"public_jwk" validate:"required"`

	key jwk.Key
}

// Key returns the parsed public JWK used to verify the client's assertions.
func (c *Client) Key() jwk.Key { return c.key }

type ClientsRegistry interface {
	GetClient(clientID string) (*Client, error)
}

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

func (r *StaticClientsRegistry) GetClient(clientID string) (*Client, error) {
	if c, ok := r.clients[clientID]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("client not found: %q", clientID)
}

func parsePublicJWK(raw map[string]any) (jwk.Key, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("missing public_jwk")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal public_jwk: %w", err)
	}
	key, err := jwk.ParseKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse public_jwk: %w", err)
	}
	return key, nil
}
