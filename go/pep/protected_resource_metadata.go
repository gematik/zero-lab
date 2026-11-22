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

package pep

import (
	"encoding/json/jsontext"
	"errors"
	"net/url"
	"reflect"
	"strings"
)

// ProtectedResourceMetadataURIPath is the well-known path a resource serves ProtectedResourceMetadata at.
const ProtectedResourceMetadataURIPath = "/.well-known/oauth-protected-resource"

// ProtectedResourceMetadata is the metadata document of a protected resource (RFC 9728 Section 2).
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
	// Extra holds the members a deployment or profile adds (RFC 9728 Section 2 allows them), such as gematik's
	// zeta_asl_use. A name of a typed member above is refused when the document is encoded, so a deployment
	// cannot override what the configuration says; json.Deterministic orders them.
	Extra map[string]jsontext.Value `json:",embed"`
}

// IsProtectedResourceMetadataMember reports whether name is a typed member of ProtectedResourceMetadata, which
// Extra must not carry.
func IsProtectedResourceMetadataMember(name string) bool {
	_, typed := typedMetadataMembers[name]
	return typed
}

// typedMetadataMembers are the JSON names of ProtectedResourceMetadata's fields, read from the type itself so that
// a member added there is refused in Extra without a second list.
var typedMetadataMembers = func() map[string]struct{} {
	names := map[string]struct{}{}
	for field := range reflect.TypeFor[ProtectedResourceMetadata]().Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name != "" {
			names[name] = struct{}{}
		}
	}
	return names
}()

// ProtectedResourceMetadataURL is the URL of the metadata of the resource identified by resource (RFC 9728 Section
// 3.1): the well-known path inserted between the host and the resource's path and query, a terminating slash
// after the host removed first. The resource must be an absolute http or https URL without user information or
// fragment (Section 1.2). The result is checked to fit in a quoted-string, since it goes into a challenge.
func ProtectedResourceMetadataURL(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil {
		return "", errors.New("resource is not a URL")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return "", errors.New("resource is not an absolute http or https URL without user information and fragment")
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	metadata := u.Scheme + "://" + u.Host + ProtectedResourceMetadataURIPath + path
	if u.RawQuery != "" || u.ForceQuery {
		metadata += "?" + u.RawQuery
	}
	if err := checkChallengeURL(metadata); err != nil {
		return "", err
	}
	return metadata, nil
}

// checkChallengeURL refuses a URL that a quoted-string (RFC 9110 Section 5.6.4) could carry only escaped: it is
// written into WWW-Authenticate as it is, so only visible ASCII without '"' and '\' passes.
func checkChallengeURL(raw string) error {
	for i := range len(raw) {
		if c := raw[i]; c <= 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return errors.New("resource metadata URL has a character a challenge parameter cannot carry")
		}
	}
	return nil
}

// withResourceMetadata adds the resource_metadata parameter (RFC 9728 Section 5.1) to challenge, a single
// challenge of one scheme: after the scheme when it has no parameters yet, after its last parameter otherwise
// (RFC 9110 Section 11.6.1, auth-param list).
func withResourceMetadata(challenge, metadataURL string) string {
	if challenge == "" || metadataURL == "" {
		return challenge
	}
	param := `resource_metadata="` + metadataURL + `"`
	if !strings.Contains(challenge, " ") {
		return challenge + " " + param
	}
	return challenge + ", " + param
}
