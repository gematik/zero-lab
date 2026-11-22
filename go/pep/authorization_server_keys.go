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

package pep

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
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
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

const (
	// AuthorizationServerMetadataPath is RFC 8414's well-known path of an authorization server's metadata.
	AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	// OpenIDConfigurationPath is OpenID Connect Discovery 1.0's (Section 4), asked when the first answers 404.
	OpenIDConfigurationPath = "/.well-known/openid-configuration"
	// DefaultKeysRefetchInterval is the least time between two fetches an unknown kid asks for, unless the
	// configuration names another.
	DefaultKeysRefetchInterval = time.Minute

	// maxMetadataBytes and maxJWKSBytes bound what is read of a response before it is parsed (servers.md rule 28).
	// Metadata documents and key sets are a few KiB; a set with certificate chains stays far below.
	maxMetadataBytes = 64 << 10
	maxJWKSBytes     = 256 << 10
	// maxFetchedDepth and maxFetchedMembers bound the nesting and member count of a fetched document before it is
	// decoded; a JWK with x5c is three levels deep.
	maxFetchedDepth   = 16
	maxFetchedMembers = 4096
	// keysFetchTimeout bounds one fetch of metadata and key set together (servers.md rule 24).
	keysFetchTimeout = 10 * time.Second
)

// AuthorizationServerKeysConfig configures AuthorizationServerKeys.
type AuthorizationServerKeysConfig struct {
	// Issuer is the authorization server's issuer identifier (RFC 8414 Section 2): an https URL without query or
	// fragment.
	Issuer string
	// HTTPClient reaches the authorization server; the host's egress client (servers.md rule 30). Required. Its
	// redirects are not followed.
	HTTPClient *http.Client
	// Logger receives a line when a fetched set replaces the one in force; nil logs nothing.
	Logger *slog.Logger
	// Now is the clock the refetch interval is measured with; nil means time.Now.
	Now func() time.Time
	// RefetchInterval is the least time between two fetches Refresh makes; zero means DefaultKeysRefetchInterval.
	RefetchInterval time.Duration
}

// AuthorizationServerKeys is the key set of an authorization server, read from the jwks_uri of its metadata (RFC
// 8414 Section 2), and a KeySource for Builder.WithKeySource. A fetched set replaces the one in force as a whole, and
// a failed fetch keeps it (servers.md rule 8). It starts no goroutine: the host fetches the first set with Fetch
// before it serves, and refreshes it in the background by calling Fetch again.
type AuthorizationServerKeys struct {
	issuer   string
	client   *http.Client
	logger   *slog.Logger
	now      func() time.Time
	interval time.Duration

	keys atomic.Pointer[jose.JSONWebKeySet]
	// mu serialises fetches, so that requests arriving with the same new kid wait for one fetch and then take its set.
	mu        sync.Mutex
	lastFetch time.Time
}

// NewAuthorizationServerKeys checks the configuration; it fetches nothing. Redirects are refused: the metadata
// and the keys come from where the configuration and the issuer's metadata say, not from where a response points
// (servers.md rule 28, outbound responses).
func NewAuthorizationServerKeys(config AuthorizationServerKeysConfig) (*AuthorizationServerKeys, error) {
	if err := CheckIssuer(config.Issuer); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	if config.HTTPClient == nil {
		return nil, errors.New("no HTTP client: the host hands its egress client")
	}
	if config.RefetchInterval < 0 {
		return nil, errors.New("refetch interval must not be negative")
	}
	noRedirects := *config.HTTPClient
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	k := &AuthorizationServerKeys{
		issuer:   config.Issuer,
		client:   &noRedirects,
		logger:   config.Logger,
		now:      config.Now,
		interval: config.RefetchInterval,
	}
	if k.logger == nil {
		k.logger = slog.New(slog.DiscardHandler)
	}
	if k.now == nil {
		k.now = time.Now
	}
	if k.interval == 0 {
		k.interval = DefaultKeysRefetchInterval
	}
	return k, nil
}

// Keys returns the set in force, or an error before a fetch succeeded.
func (k *AuthorizationServerKeys) Keys() (*jose.JSONWebKeySet, error) {
	set := k.keys.Load()
	if set == nil {
		return nil, errors.New("the authorization server's keys have not been fetched")
	}
	return set, nil
}

// Fetch reads the set now, whenever it was read last, and returns it; for the host's first fetch and its
// background refresh. An error keeps the set in force.
func (k *AuthorizationServerKeys) Fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.fetchLocked(ctx)
}

// Refresh fetches the set again unless the last fetch was less than the refetch interval ago, and returns the set
// to verify with: the fetched one, or the one in force when it declined. A client picks the kid that makes the PEP
// call it, hence the bound. The fetch does not end with the request that asked for it, so a client that hangs up
// does not use up the interval with a fetch it cancelled.
func (k *AuthorizationServerKeys) Refresh(ctx context.Context) (*jose.JSONWebKeySet, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.lastFetch.IsZero() && k.now().Sub(k.lastFetch) < k.interval {
		return k.Keys()
	}
	return k.fetchLocked(context.WithoutCancel(ctx))
}

// fetchLocked fetches and installs the set; k.mu is held.
func (k *AuthorizationServerKeys) fetchLocked(ctx context.Context) (*jose.JSONWebKeySet, error) {
	k.lastFetch = k.now()
	ctx, cancel := context.WithTimeout(ctx, keysFetchTimeout)
	defer cancel()
	set, err := k.fetch(ctx)
	if err != nil {
		return nil, err
	}
	k.keys.Store(set)
	k.logger.Info("Keys of the authorization server in force", "issuer", k.issuer, "keys", len(set.Keys))
	return set, nil
}

// fetch reads the issuer's metadata, checks that it names the issuer configured (RFC 8414 Section 3.3) and an https
// jwks_uri, and reads the key set from there.
func (k *AuthorizationServerKeys) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	jwksURI, err := k.jwksURI(ctx)
	if err != nil {
		return nil, err
	}
	body, err := k.get(ctx, jwksURI, maxJWKSBytes, "application/json", "application/jwk-set+json")
	if err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}
	if err := checkJSONObject(body); err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}
	set, err := ParseJWKSet(body)
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

// authorizationServerMetadata is the part of the metadata (RFC 8414 Section 2) read here.
type authorizationServerMetadata struct {
	Issuer  string `json:"issuer"`
	JwksURI string `json:"jwks_uri"`
}

// jwksURI reads the metadata from RFC 8414's well-known URL, or from OpenID Connect Discovery's when the first
// answers 404, and returns its jwks_uri.
func (k *AuthorizationServerKeys) jwksURI(ctx context.Context) (string, error) {
	location, err := AuthorizationServerMetadataURL(k.issuer)
	if err != nil {
		return "", err
	}
	body, err := k.get(ctx, location, maxMetadataBytes, "application/json")
	if errors.Is(err, errNotFound) {
		// OpenID Connect Discovery 1.0 Section 4.1 appends its path to the issuer, a terminating slash removed.
		location = strings.TrimSuffix(k.issuer, "/") + OpenIDConfigurationPath
		body, err = k.get(ctx, location, maxMetadataBytes, "application/json")
	}
	if err != nil {
		return "", fmt.Errorf("authorization server metadata: %w", err)
	}
	if err := checkJSONObject(body); err != nil {
		return "", fmt.Errorf("authorization server metadata: %w", err)
	}
	// Someone else's format: members not read here are ignored (RFC 8414 Section 3.2).
	var metadata authorizationServerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return "", errors.New("authorization server metadata: a member is not of its type")
	}
	if metadata.Issuer != k.issuer {
		return "", errors.New("authorization server metadata names another issuer than the configured one (RFC 8414 Section 3.3)")
	}
	if err := checkHTTPSURL(metadata.JwksURI); err != nil {
		return "", fmt.Errorf("authorization server metadata: jwks_uri: %w", err)
	}
	return metadata.JwksURI, nil
}

// AuthorizationServerMetadataURL is RFC 8414 Section 3.1's URL of issuer's metadata: the well-known path inserted
// between the host and the issuer's path, a terminating slash after the host removed first.
func AuthorizationServerMetadataURL(issuer string) (string, error) {
	if err := CheckIssuer(issuer); err != nil {
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
	return "https://" + u.Host + AuthorizationServerMetadataPath + path, nil
}

// CheckIssuer takes an issuer identifier as RFC 8414 Section 2 has it: an https URL with a host and without user
// information, query or fragment.
func CheckIssuer(issuer string) error {
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
// 28, values): keys must not travel without TLS.
func checkHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" ||
		strings.HasSuffix(raw, "#") {
		return errors.New("not an https URL with a host and without user information or fragment")
	}
	return nil
}

// errNotFound is a 404, the one status that makes the metadata be asked at OpenID Connect Discovery's location.
var errNotFound = errors.New("not found")

// get reads location with GET and returns its body: status 200, a Content-Type of one of types with no charset but
// UTF-8, and at most limit bytes (servers.md rule 28, outbound responses).
func (k *AuthorizationServerKeys) get(ctx context.Context, location string, limit int64, types ...string) ([]byte, error) {
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

// checkJSONObject takes one JSON object of valid UTF-8, nested at most maxFetchedDepth deep, with at most
// maxFetchedMembers members in all its objects together and no member named twice in any (servers.md rule 28). It walks the tokens
// with jsontext before anything is decoded, so the bounds hold before anything grows with the input; jsontext's
// errors quote the input, so they are replaced by a reason.
func checkJSONObject(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON refused: not UTF-8")
	}
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	if decoder.PeekKind() != '{' {
		return errors.New("JSON refused: not an object")
	}
	members := 0
	for {
		// Inside an object, a name comes at every even position.
		if kind, length := decoder.StackIndex(decoder.StackDepth()); kind == '{' && length%2 == 0 && decoder.PeekKind() != '}' {
			if members++; members > maxFetchedMembers {
				return fmt.Errorf("JSON refused: more than %d members", maxFetchedMembers)
			}
		}
		if _, err := decoder.ReadToken(); err != nil {
			if errors.Is(err, jsontext.ErrDuplicateName) {
				return errors.New("JSON refused: a member named twice")
			}
			return errors.New("JSON refused: not JSON")
		}
		if decoder.StackDepth() > maxFetchedDepth {
			return fmt.Errorf("JSON refused: nested deeper than %d", maxFetchedDepth)
		}
		if decoder.StackDepth() == 0 {
			break
		}
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		return errors.New("JSON refused: data after the object")
	}
	return nil
}
