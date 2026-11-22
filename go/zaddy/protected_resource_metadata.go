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
	"encoding/json/v2"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/gematik/zero-lab/go/pep"
)

func init() {
	caddy.RegisterModule(ProtectedResourceMetadataHandler{})
	httpcaddyfile.RegisterHandlerDirective("protected_resource_metadata", parseCaddyfileProtectedResourceMetadata)
}

// ProtectedResourceMetadataHandler is the Caddy HTTP handler protected_resource_metadata: it answers with the
// metadata of the resource the app "zero" protects (RFC 9728 Section 3), built from the app's configuration, so
// that resource and authorization server are stated in one place.
type ProtectedResourceMetadataHandler struct {
	document []byte
}

// CaddyModule registers the handler under the module ID "http.handlers.protected_resource_metadata".
func (ProtectedResourceMetadataHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.protected_resource_metadata",
		New: func() caddy.Module { return new(ProtectedResourceMetadataHandler) },
	}
}

// Provision encodes the metadata of the app "zero" once; it fails if that app is not configured.
func (h *ProtectedResourceMetadataHandler) Provision(ctx caddy.Context) error {
	app, err := getZeroApp(ctx)
	if err != nil {
		return err
	}
	h.document, err = app.protectedResourceMetadata()
	return err
}

// ServeHTTP answers GET and HEAD with the metadata as application/json (RFC 9728 Section 3.2), and any other method
// with 405 and Allow (servers.md rule 28, method and path). It ends the chain: the document is the response.
func (h ProtectedResourceMetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(h.document)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return nil
	}
	_, err := w.Write(h.document)
	return err
}

// protectedResourceMetadata is the resource's metadata document (RFC 9728 Section 2): resource, the authorization
// server, the header as the one way a token is presented (the enforcers read no other), the scopes and the
// members the deployment adds, encoded deterministically so that every replica serves the same bytes.
func (a *App) protectedResourceMetadata() ([]byte, error) {
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
	return json.Marshal(doc, json.Deterministic(true))
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
