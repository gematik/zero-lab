package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/pep/proxy"
	"gopkg.in/yaml.v3"
)

// openidProviders is the openid-providers.yaml schema (flat) — several providers of each kind, each reusing
// its package config type (oauth/oidc.Config, gemidp.ClientConfig, oidf.RelyingPartyConfig). The same file
// format is what pdp references by path, so the two stay in sync without a shared package.
type openidProviders struct {
	OIDC   []oidc.Config            `yaml:"oidc"`
	Gemidp []gemidp.ClientConfig    `yaml:"gemidp"`
	OIDF   *oidf.RelyingPartyConfig `yaml:"oidf"`
}

// loadProviders builds the provider options from openid-providers.yaml. Each OIDC/gemidp uses
// <public>/oauth2/callback unless it sets its own redirect_uri; the OIDF config's relative key paths resolve
// against the providers file's directory.
func loadProviders(path, publicURL string) ([]proxy.ProviderOption, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read providers %q: %w", path, err)
	}
	// Expand ${VAR} placeholders from the environment (incl. the .env loaded from the workdir).
	var op openidProviders
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &op); err != nil {
		return nil, fmt.Errorf("parse providers %q: %w", path, err)
	}
	callback := publicURL + "/oauth2/callback"

	var clients []oidc.Client
	for i := range op.OIDC {
		c := op.OIDC[i]
		if c.RedirectURI == "" {
			c.RedirectURI = callback
		}
		client, err := oidc.NewClient(c)
		if err != nil {
			return nil, fmt.Errorf("openid_providers.oidc[%d] (%s): %w", i, c.Issuer, err)
		}
		clients = append(clients, client)
		slog.Info("configured openid provider", "type", "oidc", "name", orDefault(c.Name, "OpenID Connect"), "issuer", c.Issuer, "client_id", c.ClientID)
	}
	for i := range op.Gemidp {
		c := op.Gemidp[i]
		if c.RedirectURI == "" {
			c.RedirectURI = callback
		}
		c.AuthenticatorMode = true // gemidp is always the gematik Authenticator deep-link flow
		client, err := gemidp.NewClientFromConfig(c)
		if err != nil {
			return nil, fmt.Errorf("openid_providers.gemidp[%d] (%s): %w", i, c.ClientID, err)
		}
		clients = append(clients, client)
		slog.Info("configured openid provider", "type", "gemidp", "name", orDefault(c.Name, "gematik IDP-Dienst"), "issuer", client.Issuer(), "client_id", c.ClientID)
	}

	var opts []proxy.ProviderOption
	if len(clients) > 0 {
		opts = append(opts, proxy.WithOIDCClients(clients...))
	}
	if op.OIDF != nil {
		op.OIDF.BaseDir = filepath.Dir(path)
		rp, err := oidf.NewRelyingPartyFromConfig(op.OIDF)
		if err != nil {
			return nil, fmt.Errorf("openid_providers.oidf: %w", err)
		}
		opts = append(opts, proxy.WithRelyingParty(rp))
		slog.Info("configured openid provider", "type", "oidf-rp", "name", op.OIDF.RelyingParty.ClientName, "iss", rp.ClientID())
	}
	if len(opts) == 0 {
		return nil, fmt.Errorf("providers file %q configured no providers", path)
	}
	return opts, nil
}

// providersFromEnv builds a single provider of each type from the PEP_* env vars — the simple path used
// when no openid-providers.yaml is present.
func providersFromEnv(publicURL string) []proxy.ProviderOption {
	var opts []proxy.ProviderOption
	callback := publicURL + "/oauth2/callback"

	if issuer := os.Getenv("PEP_OIDC_ISSUER"); issuer != "" {
		var skew time.Duration
		if v := os.Getenv("PEP_OIDC_ACCEPTABLE_SKEW"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				log.Fatalf("invalid PEP_OIDC_ACCEPTABLE_SKEW %q: %v", v, err)
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
		opts = append(opts, proxy.WithOIDCClients(client))
		slog.Info("configured openid provider", "type", "oidc", "name", orDefault(os.Getenv("PEP_OIDC_NAME"), "OpenID Connect"), "issuer", issuer, "client_id", os.Getenv("PEP_OIDC_CLIENT_ID"))
	}

	if rpPath := os.Getenv("PEP_OIDF_RP_CONFIG_PATH"); rpPath != "" {
		rp, err := oidf.NewRelyingPartyFromConfigFile(rpPath)
		if err != nil {
			log.Fatalf("load oidf relying party: %v", err)
		}
		opts = append(opts, proxy.WithRelyingParty(rp))
		slog.Info("configured openid provider", "type", "oidf-rp", "iss", rp.ClientID())
	}

	if clientID := os.Getenv("PEP_GEMIDP_CLIENT_ID"); clientID != "" {
		redirect := callback
		if v := os.Getenv("PEP_GEMIDP_REDIRECT_URI"); v != "" {
			redirect = v
		}
		client, err := gemidp.NewClientFromConfig(gemidp.ClientConfig{
			Environment:       gemidp.NewEnvironment(os.Getenv("PEP_GEMIDP_ENV")),
			BaseURL:           os.Getenv("PEP_GEMIDP_BASE_URL"),
			ClientID:          clientID,
			RedirectURI:       redirect,
			Scopes:            fieldsOr(os.Getenv("PEP_GEMIDP_REDIRECT_SCOPES"), "openid"),
			Name:              orDefault(os.Getenv("PEP_GEMIDP_NAME"), "gematik IDP-Dienst"),
			LogoURI:           os.Getenv("PEP_GEMIDP_LOGO_URI"),
			AuthenticatorMode: true, // gemidp is always the gematik Authenticator deep-link flow
			UserAgent:         os.Getenv("PEP_GEMIDP_USER_AGENT"),
		})
		if err != nil {
			log.Fatalf("create gemidp client: %v", err)
		}
		opts = append(opts, proxy.WithOIDCClients(client))
		slog.Info("configured openid provider", "type", "gemidp", "name", orDefault(os.Getenv("PEP_GEMIDP_NAME"), "gematik IDP-Dienst"), "issuer", client.Issuer(), "client_id", clientID)
	}

	return opts
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
