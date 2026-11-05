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
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/idpd"
	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/openid"
	"github.com/gematik/zero-lab/go/openid/providers"
)

// oidfDevAPIKeyEnv holds the key of gematik's development federation; a value, not a file, see
// docs/conventions/naming-and-config.md.
const oidfDevAPIKeyEnv = "PEP_OIDF_DEV_API_KEY" //nolint:gosec // the name of the variable, not a key

// loadProviders builds the providers from openid-providers.yaml. An oidc or idpd entry uses
// <public>/oauth2/callback unless it sets its own redirect_uri; the idpd client is always the gematik
// Authenticator deep-link flow.
func loadProviders(path, publicURL string) (*providers.Set, error) {
	entries, err := providerEntries(path)
	if err != nil {
		return nil, err
	}
	env := providers.Env{BaseDir: filepath.Dir(path), RedirectURI: publicURL + "/oauth2/callback"}
	set, err := providers.Build(entries, env, providers.Kinds{
		"oidc": providers.OIDC,
		"idpd": idpd.Kind(func(c *idpd.ClientConfig) { c.AuthenticatorMode = true }),
		"oidf": oidf.Kind(os.Getenv(oidfDevAPIKeyEnv), nil),
	})
	if err != nil {
		return nil, fmt.Errorf("providers %q: %w", path, err)
	}
	return set, nil
}

// providersFromEnv builds a single provider of each type from the PEP_* env vars — the simple path used
// when no openid-providers.yaml is present.
func providersFromEnv(publicURL string) *providers.Set {
	var configured []providers.Provider
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
		client, err := openid.NewClient(openid.Config{
			Issuer:         issuer,
			ClientID:       os.Getenv("PEP_OIDC_CLIENT_ID"),
			ClientSecret:   openid.NewSecretString(os.Getenv("PEP_OIDC_CLIENT_SECRET")),
			RedirectURI:    callback,
			Scopes:         fieldsOr(os.Getenv("PEP_OIDC_SCOPES"), "openid email profile"),
			Name:           orDefault(os.Getenv("PEP_OIDC_NAME"), "OpenID Connect"),
			LogoURI:        os.Getenv("PEP_OIDC_LOGO_URI"),
			AcceptableSkew: skew,
		})
		if err != nil {
			log.Fatalf("create oidc client: %v", err)
		}
		configured = append(configured, providers.Provider{
			Issuer:  client.Issuer(),
			Name:    orDefault(os.Getenv("PEP_OIDC_NAME"), "OpenID Connect"),
			LogoURI: os.Getenv("PEP_OIDC_LOGO_URI"),
			Type:    providers.TypeOIDC,
			Client:  client,
		})
		slog.Info("configured openid provider", "type", "oidc", "name", orDefault(os.Getenv("PEP_OIDC_NAME"), "OpenID Connect"), "issuer", issuer, "client_id", os.Getenv("PEP_OIDC_CLIENT_ID"))
	}

	if rpPath := os.Getenv("PEP_OIDF_RP_CONFIG_PATH"); rpPath != "" {
		config := new(oidf.RelyingPartyConfig)
		if err := loadYAML(rpPath, config); err != nil {
			log.Fatalf("load oidf relying party: %v", err)
		}
		config.APIKey = os.Getenv(oidfDevAPIKeyEnv)
		rp, err := oidf.NewRelyingParty(config, filepath.Dir(rpPath))
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
		configured = append(configured, client.Provider())
		slog.Info("configured openid provider", "type", "idpd", "name", orDefault(os.Getenv("PEP_IDPD_NAME"), "gematik IDP-Dienst"), "issuer", client.Issuer(), "client_id", clientID)
	}

	return providers.New(federation, configured...)
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
