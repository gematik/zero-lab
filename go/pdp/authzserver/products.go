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
	ProductID         string   `yaml:"product_id" json:"product_id" validate:"required"`
	ProductName       string   `yaml:"product_name" json:"product_name"`
	ManufacturerID    string   `yaml:"manufacturer_id" json:"manufacturer_id"`
	ManufacturerName  string   `yaml:"manufacturer_name" json:"manufacturer_name"`
	Platform          string   `yaml:"platform" json:"platform"`
	PlatformProductID any      `yaml:"platform_product_id" json:"platform_product_id"`
	RedirectURIs      []string `yaml:"redirect_uris" json:"redirect_uris"`
	Scopes            []string `yaml:"scopes" json:"scopes"`
	// ASRedirectURIs are the redirect_uri(s) the upstream IdP sends the user back to the AS at (gematik
	// redirect_uri_as), instead of the default /op-callback — so the IdP redirects straight to the AS with
	// no app-side intermediary popup. Registered into the OIDF entity statement (see initRelyingParty).
	ASRedirectURIs []string `yaml:"as_redirect_uris" json:"as_redirect_uris"`
	PushGateway    any      `yaml:"push_gateway" json:"push_gateway"`
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

// AllASRedirectURIs returns the deduplicated as_redirect_uris across every product — the redirect URIs the
// upstream IdP may send the user back to the AS at. They are injected into the OIDF entity statement.
func (r *ProductsRegistry) AllASRedirectURIs() []string {
	var uris []string
	seen := make(map[string]struct{})
	for _, p := range r.products {
		for _, u := range p.ASRedirectURIs {
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			uris = append(uris, u)
		}
	}
	return uris
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
