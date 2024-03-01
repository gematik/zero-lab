package zas

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ClientsPolicy struct {
	Clients []*ClientPolicy `yaml:"clients"`
}

type ClientPolicy struct {
	ProductID            string      `yaml:"product_id"`
	ProductName          string      `yaml:"product_name"`
	ManufacturerID       string      `yaml:"manufacturer_id"`
	ManufacturerName     string      `yaml:"manufacturer_name"`
	Platform             string      `yaml:"platform"`
	PlatformProductID    interface{} `yaml:"platform_product_id"`
	AuthIntermediaryURIs []string    `yaml:"auth_intermediary_uris"`
	PushGateway          interface{} `yaml:"push_gateway"`
}

func LoadClientsPolicy(path string) (*ClientsPolicy, error) {
	yamlData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file '%s': %w", path, err)
	}
	var policy ClientsPolicy
	err = yaml.Unmarshal(yamlData, &policy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy file '%s': %w", path, err)
	}
	return &policy, nil
}

func (p *ClientsPolicy) AllowedAuthIntermediaryURL(clientID, url string) bool {
	for _, client := range p.Clients {
		if client.ProductID == clientID {
			for _, allowedURL := range client.AuthIntermediaryURIs {
				if url == allowedURL {
					return true
				}
			}
		}
	}
	return false
}

func (p *ClientsPolicy) AllowedClient(clientID string) bool {
	for _, client := range p.Clients {
		if client.ProductID == clientID {
			return true
		}
	}
	return false
}
