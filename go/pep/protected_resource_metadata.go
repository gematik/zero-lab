package pep

const ProtectedResourceMetadataUriPath = "/.well-known/oauth-protected-resource"

// Implementation of protected resource metadata
// according to https://www.ietf.org/archive/id/draft-ietf-oauth-resource-metadata-01.html
type ProtectedResourceMetadata struct {
	Resource                             string   `json:"resource"`                                           // REQUIRED
	AuthorizationServers                 []string `json:"authorization_servers,omitempty"`                    // OPTIONAL
	JwksURI                              string   `json:"jwks_uri,omitempty"`                                 // OPTIONAL
	ScopesSupported                      []string `json:"scopes_supported,omitempty"`                         // RECOMMENDED
	BearerMethodsSupported               []string `json:"bearer_methods_supported,omitempty"`                 // OPTIONAL
	ResourceSigningAlgValuesSupported    []string `json:"resource_signing_alg_values_supported,omitempty"`    // OPTIONAL
	ResourceEncryptionAlgValuesSupported []string `json:"resource_encryption_alg_values_supported,omitempty"` // OPTIONAL
	ResourceEncryptionEncValuesSupported []string `json:"resource_encryption_enc_values_supported,omitempty"` // OPTIONAL
	ResourceDocumentation                string   `json:"resource_documentation,omitempty"`                   // OPTIONAL
	ResourcePolicyURI                    string   `json:"resource_policy_uri,omitempty"`                      // OPTIONAL
	ResourceTosURI                       string   `json:"resource_tos_uri,omitempty"`                         // OPTIONAL
}
