package pep

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/libzero/oauth2server"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// reloads metadata periodically in the given interval.
// if error occures use exponential backoff from 1 second to 10 minutes
func (p *PEP) periodicMetadataReload(ctx context.Context, interval time.Duration) {
	slog.Info("Starting periodic metadata reload", "interval", interval)

	backoff := 1 * time.Second
	for {
		err := p.reloadMetadata(ctx)
		if err != nil {
			slog.Error("Failed to reload metadata", "error", err)
			time.Sleep(backoff)
			backoff = backoff * 2
			if backoff > 10*time.Minute {
				backoff = 10 * time.Minute
			}
			continue
		}
		time.Sleep(interval)
	}
}

func (p *PEP) reloadMetadata(ctx context.Context) error {
	p.authzMetadataMutex.Lock()
	defer p.authzMetadataMutex.Unlock()
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
