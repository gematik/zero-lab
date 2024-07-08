package pep

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/pkg/oauth2server"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type PEP struct {
	httpClient    http.Client
	authzIssuer   string
	authzMetadata *oauth2server.Metadata
	jwksCache     *jwk.Cache
}

func (p *PEP) reloadMetadata(ctx context.Context) error {
	// fetch metadata from authzIssuer
	metadata, err := fetchAuthzMetadata(p.authzIssuer)
	if err != nil {
		return fmt.Errorf("fetch metadata: %w", err)
	}

	slog.Info("Fetched authz metadata", "metadata", metadata)

	// update metadata
	p.authzMetadata = metadata

	jwksCache := jwk.NewCache(ctx)
	jwksCache.Register(
		p.authzMetadata.JwksURI,
		jwk.WithMinRefreshInterval(15*time.Minute),
		jwk.WithHTTPClient(&p.httpClient),
	)
	// refresh signing keys
	_, err = jwksCache.Refresh(ctx, p.authzMetadata.JwksURI)
	if err != nil {
		return fmt.Errorf("failed to fetch signing keys: %w", err)
	}

	slog.Info("Fetched signing keys", "jwks_uri", p.authzMetadata.JwksURI)

	p.jwksCache = jwksCache

	return nil

}

func fetchAuthzMetadata(authzIssuer string) (*oauth2server.Metadata, error) {
	// fetch metadata from authzIssuer
	metadataURL := authzIssuer + "/.well-known/oauth-authorization-server"
	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	var metadata oauth2server.Metadata
	err = json.NewDecoder(resp.Body).Decode(&metadata)
	if err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}

	return &metadata, nil
}
