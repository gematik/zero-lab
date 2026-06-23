package authzserver

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// Product is an application registered with the authorization server. It owns the redirect-URI and
// scope policy that all of its client instances share. Products are loaded inline from the config
// (products:) and/or from a gematik clients-policy file (clients_policy_path).
type Product struct {
	ProductID          string   `yaml:"product_id" json:"product_id" validate:"required"`
	ProductName        string   `yaml:"product_name" json:"product_name"`
	ManufacturerID     string   `yaml:"manufacturer_id" json:"manufacturer_id"`
	ManufacturerName   string   `yaml:"manufacturer_name" json:"manufacturer_name"`
	Platform           string   `yaml:"platform" json:"platform"`
	PlatformProductID  any      `yaml:"platform_product_id" json:"platform_product_id"`
	RedirectURIs       []string `yaml:"redirect_uris" json:"redirect_uris"`
	Scopes             []string `yaml:"scopes" json:"scopes"`
	OPIntermediaryURIs []string `yaml:"op_intermediary_redirect_uris" json:"op_intermediary_redirect_uris"`
	PushGateway        any      `yaml:"push_gateway" json:"push_gateway"`
}

func (p *Product) IsAllowedRedirectURI(redirectURI string) bool {
	return slices.Contains(p.RedirectURIs, redirectURI)
}

func (p *Product) IsAllowedScope(scope string) bool {
	return slices.Contains(p.Scopes, scope)
}

func (p *Product) IsAllowedScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !p.IsAllowedScope(scope) {
			return false
		}
	}
	return true
}

func (p *Product) IsOPIntermediaryRedirectURIAllowed(url string) bool {
	return slices.Contains(p.OPIntermediaryURIs, url)
}

type ProductsRegistry struct {
	products map[string]*Product
}

func NewProductsRegistry(products []*Product) *ProductsRegistry {
	indexed := make(map[string]*Product, len(products))
	for _, p := range products {
		indexed[p.ProductID] = p
	}
	return &ProductsRegistry{products: indexed}
}

func (r *ProductsRegistry) GetProduct(productID string) (*Product, error) {
	if p, ok := r.products[productID]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("product not found: %q", productID)
}

// LoadProductsFile reads a gematik clients-policy file, whose top-level key is `clients`.
func LoadProductsFile(path string) ([]*Product, error) {
	yamlData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read products file '%s': %w", path, err)
	}
	var doc struct {
		Products []*Product `yaml:"clients"`
	}
	if err := yaml.Unmarshal(yamlData, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal products file '%s': %w", path, err)
	}
	return doc.Products, nil
}
