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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
	"github.com/gematik/zero-lab/go/pep"
)

const (
	// authorizationServerMetadataPath is RFC 8414's well-known path, openIDConfigurationPath the one of OpenID
	// Connect Discovery 1.0 Section 4, asked when the first is absent.
	authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	openIDConfigurationPath         = "/.well-known/openid-configuration"
	// maxMetadataBytes and maxJWKSBytes bound what is read of a response before it is parsed (servers.md rule 28).
	// Metadata documents and key sets are a few KiB; a set with certificate chains stays far below.
	maxMetadataBytes = 64 << 10
	maxJWKSBytes     = 256 << 10
	// keysFetchTimeout bounds one fetch of metadata and key set together (servers.md rule 24).
	keysFetchTimeout = 10 * time.Second
	// keysRefetchInterval is the least time between two fetches a token's unknown kid asks for. A client picks the
	// kid, so without the bound every request could make zaddy call the authorization server.
	keysRefetchInterval = time.Minute
	// keysRefreshPeriod is how often the set is fetched in the background, outside the request path (servers.md
	// rule 8), so a key the authorization server withdraws leaves the set without a restart.
	keysRefreshPeriod = 15 * time.Minute
)

// authorizationServerKeys is the key set of the authorization server, read from the jwks_uri of its metadata
// (RFC 8414 Section 2) through the egress client. It is pep's KeySource: a fetched set that verifies replaces the
// one in force as a whole, and a failed fetch keeps it (servers.md rule 8).
type authorizationServerKeys struct {
	issuer   string
	client   *http.Client
	now      func() time.Time
	interval time.Duration

	keys atomic.Pointer[jose.JSONWebKeySet]
	// mu serialises fetches, so that requests arriving with the same new kid wait for one fetch and then take its set.
	mu        sync.Mutex
	lastFetch time.Time
}

// newAuthorizationServerKeys fetches the key set of issuer once; an error means the PEP has no keys and must not
// start (servers.md rule 17). Redirects are refused: the metadata and the keys come from where the configuration
// and the issuer's metadata say, not from where a response points (servers.md rule 28, outbound responses).
func newAuthorizationServerKeys(ctx context.Context, issuer string, client *http.Client, now func() time.Time) (*authorizationServerKeys, error) {
	noRedirects := *client
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	k := &authorizationServerKeys{issuer: issuer, client: &noRedirects, now: now, interval: keysRefetchInterval}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, err := k.refreshLocked(ctx); err != nil {
		return nil, err
	}
	return k, nil
}

// Keys returns the set in force.
func (k *authorizationServerKeys) Keys() (*jose.JSONWebKeySet, error) {
	return k.keys.Load(), nil
}

// Refresh fetches the set again unless the last fetch was less than the interval ago, and returns the set to verify
// with: the fetched one, or the one in force when it declined. The fetch does not end with the request that asked
// for it, so a client that hangs up does not use up the interval with a fetch it cancelled.
func (k *authorizationServerKeys) Refresh(ctx context.Context) (*jose.JSONWebKeySet, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.now().Sub(k.lastFetch) < k.interval {
		return k.keys.Load(), nil
	}
	return k.refreshLocked(context.WithoutCancel(ctx))
}

// run fetches the set every period until ctx ends; a failed fetch keeps the set in force and is logged.
func (k *authorizationServerKeys) run(ctx context.Context, period time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			k.mu.Lock()
			_, err := k.refreshLocked(ctx)
			k.mu.Unlock()
			if err != nil {
				logger.Error("Keys of the authorization server not refreshed, the set in force is kept", "issuer", k.issuer, "error", err)
			}
		}
	}
}

// refreshLocked fetches and installs the set; k.mu is held.
func (k *authorizationServerKeys) refreshLocked(ctx context.Context) (*jose.JSONWebKeySet, error) {
	k.lastFetch = k.now()
	ctx, cancel := context.WithTimeout(ctx, keysFetchTimeout)
	defer cancel()
	set, err := k.fetch(ctx)
	if err != nil {
		return nil, err
	}
	k.keys.Store(set)
	return set, nil
}

// fetch reads the issuer's metadata, checks that it names the issuer configured (RFC 8414 Section 3.3) and an https
// jwks_uri, and reads the key set from there.
func (k *authorizationServerKeys) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	jwksURI, err := k.jwksURI(ctx)
	if err != nil {
		return nil, err
	}
	body, err := k.get(ctx, jwksURI, maxJWKSBytes, "application/json", "application/jwk-set+json")
	if err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}
	if err := openid.CheckJSONObject(body, openid.PayloadDepth, openid.PayloadMembers); err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}
	set, err := pep.ParseJWKSet(body)
	if err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("jwks_uri: the key set holds no key")
	}
	// A private key in the published set means the authorization server leaks its signing key; such a set is not
	// one to trust.
	for i := range set.Keys {
		if !set.Keys[i].Valid() || !set.Keys[i].IsPublic() {
			return nil, errors.New("jwks_uri: the key set holds a key that is not a valid public key")
		}
	}
	return set, nil
}

// authorizationServerMetadata is the part of the metadata (RFC 8414 Section 2) zaddy reads.
type authorizationServerMetadata struct {
	Issuer  string `json:"issuer"`
	JwksURI string `json:"jwks_uri"`
}

// jwksURI reads the metadata from RFC 8414's well-known URL, or from OpenID Connect Discovery's when the first
// answers 404, and returns its jwks_uri.
func (k *authorizationServerKeys) jwksURI(ctx context.Context) (string, error) {
	location, err := authorizationServerMetadataURL(k.issuer)
	if err != nil {
		return "", err
	}
	body, err := k.get(ctx, location, maxMetadataBytes, "application/json")
	if errors.Is(err, errNotFound) {
		// OpenID Connect Discovery 1.0 Section 4.1 appends its path to the issuer, a terminating slash removed.
		location = strings.TrimSuffix(k.issuer, "/") + openIDConfigurationPath
		body, err = k.get(ctx, location, maxMetadataBytes, "application/json")
	}
	if err != nil {
		return "", fmt.Errorf("authorization server metadata: %w", err)
	}
	var metadata authorizationServerMetadata
	if err := openid.UnmarshalObject(body, openid.PayloadDepth, openid.PayloadMembers, &metadata); err != nil {
		return "", fmt.Errorf("authorization server metadata: %w", err)
	}
	if metadata.Issuer != k.issuer {
		return "", errors.New("authorization server metadata names another issuer than authorization_server (RFC 8414 Section 3.3)")
	}
	if err := checkHTTPSURL(metadata.JwksURI); err != nil {
		return "", fmt.Errorf("authorization server metadata: jwks_uri: %w", err)
	}
	return metadata.JwksURI, nil
}

// authorizationServerMetadataURL is RFC 8414 Section 3.1's URL of issuer's metadata: the well-known path inserted
// between the host and the issuer's path, a terminating slash after the host removed first.
func authorizationServerMetadataURL(issuer string) (string, error) {
	if err := checkIssuer(issuer); err != nil {
		return "", err
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	return "https://" + u.Host + authorizationServerMetadataPath + path, nil
}

// checkIssuer takes an issuer identifier as RFC 8414 Section 2 has it: an https URL without query or fragment.
func checkIssuer(issuer string) error {
	if err := checkHTTPSURL(issuer); err != nil {
		return err
	}
	u, _ := url.Parse(issuer)
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("an issuer has no query (RFC 8414 Section 2)")
	}
	return nil
}

// checkHTTPSURL takes an absolute https URL with a host and without user information or fragment (servers.md rule
// 28, values): keys must not travel without TLS, and the egress client refuses plain http anyway.
func checkHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" ||
		strings.HasSuffix(raw, "#") {
		return errors.New("not an https URL with a host and without user information or fragment")
	}
	return nil
}

// errNotFound is a 404, the one status that makes zaddy ask OpenID Connect Discovery's location instead.
var errNotFound = errors.New("not found")

// get reads location with GET and returns its body: status 200, a Content-Type of one of types with no charset but
// UTF-8, and at most limit bytes (servers.md rule 28, outbound responses).
func (k *authorizationServerKeys) get(ctx context.Context, location string, limit int64, types ...string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, http.NoBody)
	if err != nil {
		return nil, errors.New("no request can be built for the URL")
	}
	request.Header.Set("Accept", strings.Join(types, ", "))
	response, err := k.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errNotFound
	default:
		return nil, fmt.Errorf("status %d", response.StatusCode)
	}
	mediaType, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !slices.Contains(types, mediaType) {
		return nil, errors.New("content type is not one of " + strings.Join(types, ", "))
	}
	if charset, ok := params["charset"]; ok && !strings.EqualFold(charset, "utf-8") {
		return nil, errors.New("charset is not UTF-8")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, errors.New("the body could not be read")
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return body, nil
}
