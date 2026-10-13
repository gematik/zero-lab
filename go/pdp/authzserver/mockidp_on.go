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

//go:build mockidp

package authzserver

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/pdp/authzserver/mockidp"
)

// mockHost adapts *Server to mockidp.Host so the subpackage never imports authzserver (no import cycle).
type mockHost struct{ s *Server }

func (h mockHost) IssuerBaseURL() string { return h.s.Metadata.Issuer }
func (h mockHost) OPCallbackURL() string {
	return strings.TrimRight(h.s.Metadata.Issuer, "/") + h.s.endpointPaths.OPCallback
}
func (h mockHost) AddProvider(c oidc.Client) { h.s.openidProviders = append(h.s.openidProviders, c) }

// registerMockProviders mounts the co-hosted mock OP and registers it as a normal provider. Compiled only
// with `-tags mockidp`; the !mockidp build is a no-op and never imports the mockidp package.
func (s *Server) registerMockProviders(mux *http.ServeMux) {
	id := mockidp.Identity{
		Subject: "X110000001",
		Claims:  map[string]any{"name": "Test User", "email": "test@example.com"},
	}
	if err := mockidp.Register(mockHost{s}, mux, id); err != nil {
		slog.Error("mock IdP registration failed", "error", err)
		return
	}
	slog.Warn("mock IdP registered — built with -tags mockidp, NON-PRODUCTION ONLY")
}
