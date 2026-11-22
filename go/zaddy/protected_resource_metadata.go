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

package zaddy

import (
	"encoding/json/jsontext"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(ProtectedResourceMetadataHandler{})
	httpcaddyfile.RegisterHandlerDirective("protected_resource_metadata", parseCaddyfileProtectedResourceMetadata)
}

// ProtectedResourceMetadataHandler is the Caddy HTTP handler protected_resource_metadata: pep's handler of the
// metadata of the resource the app "zero" protects (RFC 9728 Section 3), built from the app's configuration, so
// that resource and authorization server are stated in one place.
type ProtectedResourceMetadataHandler struct {
	handler http.Handler
}

// CaddyModule registers the handler under the module ID "http.handlers.protected_resource_metadata".
func (ProtectedResourceMetadataHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.protected_resource_metadata",
		New: func() caddy.Module { return new(ProtectedResourceMetadataHandler) },
	}
}

// Provision builds the handler from the app "zero"; it fails if that app is not configured.
func (h *ProtectedResourceMetadataHandler) Provision(ctx caddy.Context) error {
	app, err := getZeroApp(ctx)
	if err != nil {
		return err
	}
	h.handler, err = pep.NewProtectedResourceMetadataHandler(app.protectedResourceMetadata())
	return err
}

// ServeHTTP ends the chain: the document, or the 405 of another method, is the response.
func (h ProtectedResourceMetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	h.handler.ServeHTTP(w, r)
	return nil
}

// protectedResourceMetadata is the resource's metadata document (RFC 9728 Section 2): resource, the authorization
// server, the header as the one way a token is presented (the enforcers read no other), the scopes and the
// members the deployment adds.
func (a *App) protectedResourceMetadata() pep.ProtectedResourceMetadata {
	doc := pep.ProtectedResourceMetadata{
		Resource:               a.Resource,
		ScopesSupported:        a.ScopesSupported,
		BearerMethodsSupported: []string{"header"},
	}
	if a.AuthorizationServer != "" {
		doc.AuthorizationServers = []string{a.AuthorizationServer}
	}
	if len(a.MetadataMembers) > 0 {
		doc.Extra = make(map[string]jsontext.Value, len(a.MetadataMembers))
		for name, value := range a.MetadataMembers {
			doc.Extra[name] = jsontext.Value(value)
		}
	}
	return doc
}

func parseCaddyfileProtectedResourceMetadata(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next()
	if h.NextArg() || h.NextBlock(0) {
		return nil, h.Err("protected_resource_metadata takes no arguments: the document comes from the global pep block")
	}
	return &ProtectedResourceMetadataHandler{}, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*ProtectedResourceMetadataHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ProtectedResourceMetadataHandler)(nil)
)
