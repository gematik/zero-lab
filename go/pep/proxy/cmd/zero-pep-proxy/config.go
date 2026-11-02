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

package main

import (
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/idpd"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oauth/providers"
	"github.com/gematik/zero-lab/go/oidf"
)

// loadProviders builds the providers from openid-providers.yaml. An oidc or idpd entry uses
// <public>/oauth2/callback unless it sets its own redirect_uri; the idpd client is always the gematik
// Authenticator deep-link flow.
func loadProviders(path, publicURL string) (*providers.Set, error) {
	return providers.Load(path, providers.Env{RedirectURI: publicURL + "/oauth2/callback"}, providers.Kinds{
		"oidc": providers.OIDC,
		"idpd": idpd.Kind(func(c *idpd.ClientConfig) { c.AuthenticatorMode = true }),
		"oidf": oidf.Kind(nil),
	})
}

// providersFromEnv builds a single provider of each type from the PEP_* env vars — the simple path used
// when no openid-providers.yaml is present.
func providersFromEnv(publicURL string) *providers.Set {
	var clients []oidc.Client
	var federation providers.Federation
	callback := publicURL + "/oauth2/callback"

	if issuer := os.Getenv("PEP_OIDC_ISSUER"); issuer != "" {
		var skew time.Duration
		if v := os.Getenv("PEP_OIDC_ACCEPTABLE_SKEW"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				log.Fatalf("invalid PEP_OIDC_ACCEPTABLE_SKEW %q: %v", v, err) //nolint:gosec // %q escapes a value from the operator's environment; start-up log, no request data
			}
			skew = d
		}
		client, err := oidc.NewClient(oidc.Config{
			Issuer:         issuer,
			ClientID:       os.Getenv("PEP_OIDC_CLIENT_ID"),
			ClientSecret:   oidc.NewSecretString(os.Getenv("PEP_OIDC_CLIENT_SECRET")),
			RedirectURI:    callback,
			Scopes:         fieldsOr(os.Getenv("PEP_OIDC_SCOPES"), "openid email profile"),
			Name:           orDefault(os.Getenv("PEP_OIDC_NAME"), "OpenID Connect"),
			LogoURI:        os.Getenv("PEP_OIDC_LOGO_URI"),
			AcceptableSkew: skew,
		})
		if err != nil {
			log.Fatalf("create oidc client: %v", err)
		}
		clients = append(clients, client)
		slog.Info("configured openid provider", "type", "oidc", "name", orDefault(os.Getenv("PEP_OIDC_NAME"), "OpenID Connect"), "issuer", issuer, "client_id", os.Getenv("PEP_OIDC_CLIENT_ID"))
	}

	if rpPath := os.Getenv("PEP_OIDF_RP_CONFIG_PATH"); rpPath != "" {
		rp, err := oidf.NewRelyingPartyFromConfigFile(rpPath)
		if err != nil {
			log.Fatalf("load oidf relying party: %v", err)
		}
		federation = rp
		slog.Info("configured openid provider", "type", "oidf-rp", "iss", rp.ClientID())
	}

	if clientID := os.Getenv("PEP_IDPD_CLIENT_ID"); clientID != "" {
		redirect := callback
		if v := os.Getenv("PEP_IDPD_REDIRECT_URI"); v != "" {
			redirect = v
		}
		client, err := idpd.NewClientFromConfig(idpd.ClientConfig{
			Environment:       idpd.NewEnvironment(os.Getenv("PEP_IDPD_ENV")),
			BaseURL:           os.Getenv("PEP_IDPD_BASE_URL"),
			ClientID:          clientID,
			RedirectURI:       redirect,
			Scopes:            fieldsOr(os.Getenv("PEP_IDPD_REDIRECT_SCOPES"), "openid"),
			Name:              orDefault(os.Getenv("PEP_IDPD_NAME"), "gematik IDP-Dienst"),
			LogoURI:           os.Getenv("PEP_IDPD_LOGO_URI"),
			AuthenticatorMode: true, // idpd is always the gematik Authenticator deep-link flow
			UserAgent:         os.Getenv("PEP_IDPD_USER_AGENT"),
			TrustBundlePath:   os.Getenv("PEP_IDPD_TRUST_BUNDLE_PATH"),
			TrustFetch:        os.Getenv("PEP_IDPD_TRUST_FETCH") == "true",
		})
		if err != nil {
			log.Fatalf("create idpd client: %v", err)
		}
		clients = append(clients, client)
		slog.Info("configured openid provider", "type", "idpd", "name", orDefault(os.Getenv("PEP_IDPD_NAME"), "gematik IDP-Dienst"), "issuer", client.Issuer(), "client_id", clientID)
	}

	return providers.New(federation, clients...)
}

func fieldsOr(s, def string) []string {
	if strings.TrimSpace(s) == "" {
		s = def
	}
	return strings.Fields(s)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
