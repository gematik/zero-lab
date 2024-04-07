package zas

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/oidf"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type ErrorTolerance bool

const (
	UseMockIfNotAvailable ErrorTolerance = true
	FailIfNotAvailable    ErrorTolerance = false
)

func WithSigningKey(sigPrK jwk.Key) Option {
	return func(s *Server) error {
		s.sigPrK = sigPrK
		return nil
	}
}

func WithOpenidProvider(oidcClient oidc.Client) Option {
	return func(s *Server) error {
		s.identityIssuers = append(s.identityIssuers, oidcClient)
		slog.Info("Using OIDC client", "issuer", oidcClient.Issuer(), "client_id", oidcClient.ClientID())
		return nil
	}
}

func WithEncryptionKey(encPuK jwk.Key) Option {
	return func(s *Server) error {
		s.encPuK = encPuK
		return nil
	}
}

func WithSigningKeyFromJWK(path string, tolerance ErrorTolerance) Option {
	return func(s *Server) error {
		data, err := os.ReadFile(path)
		if err != nil {
			if tolerance == UseMockIfNotAvailable {
				slog.Warn("Failed to read key file", "path", path, "error", err)
				return WithRandomSigningKey()(s)
			} else {
				return fmt.Errorf("unable to read key file: %w", err)
			}
		}
		privateKey, err := jwk.ParseKey(data)
		if err != nil {
			if tolerance == UseMockIfNotAvailable {
				slog.Warn("Failed to parse key file", "path", path, "error", err)
				return WithRandomSigningKey()(s)
			} else {
				return fmt.Errorf("unable to parse key file: %w", err)
			}
		}
		return WithSigningKey(privateKey)(s)
	}
}

func WithRandomSigningKey() Option {
	return func(s *Server) error {
		sigPrK, err := util.RandomJWK()
		if err != nil {
			return fmt.Errorf("unable to generate keys: %w", err)
		}
		sigPrK.Set(jwk.KeyUsageKey, "sig")

		thumbprint, err := sigPrK.Thumbprint(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("unable to generate keys: %w", err)
		}

		sigPrK.Set(jwk.KeyIDKey, base64.RawURLEncoding.EncodeToString(thumbprint))

		sigPuK, err := sigPrK.PublicKey()
		if err != nil {
			return fmt.Errorf("unable to generate keys: %w", err)
		}

		slog.Debug("Generated random signing key for ACCESS_TOKEN", "kid", sigPuK.KeyID())

		s.sigPrK = sigPrK
		s.jwks = jwk.NewSet()
		s.jwks.AddKey(sigPuK)
		return nil
	}
}

func WithSessionStore(sessionStore SessionStore) Option {
	return func(s *Server) error {
		s.sessionStore = sessionStore
		return nil
	}
}

func WithClientsPolicy(clientsPolicy *ClientsPolicy) Option {
	return func(s *Server) error {
		s.clientsPolicy = clientsPolicy
		for _, client := range clientsPolicy.Clients {
			slog.Info("Using client policy", "product_id", client.ProductID)
		}
		return nil
	}
}

func WithMockSessionStore() Option {
	return func(s *Server) error {
		s.sessionStore = newMockSessionStore()
		return nil
	}
}

func WithOIDFRelyingPartyFromConfigFile(path string, tolerance ErrorTolerance) Option {
	return func(s *Server) error {
		oidfRelyingParty, err := oidf.NewRelyingPartyFromConfigFile(path)
		if err != nil {
			if tolerance == UseMockIfNotAvailable {
				slog.Warn("Failed to read OIDF config file", "path", path, "error", err)
				return nil
			} else {
				return fmt.Errorf("unable to read OIDF config file: %w", err)
			}
		}
		s.oidfRelyingParty = oidfRelyingParty
		slog.Info("Using OIDF relying party", "federation", oidfRelyingParty.Federation().FederationMasterURL(), "client_id", oidfRelyingParty.ClientID())
		return nil
	}
}
