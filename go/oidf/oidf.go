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

// Package oidf implements the relying party of the gematik OpenID Federation: its signed entity statement,
// the verified fetches from the federation master, and logins at the federated OpenID providers.
package oidf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

const (
	defaultHTTPTimeout = 30 * time.Second
	// statementClockTolerance is added to the clock a signed federation document is judged at. Having nbf and iat
	// in the future by that much is tolerated, and exp is met that much earlier.
	statementClockTolerance = 90 * time.Second
	// maxFederationResponseBytes bounds what a federation member can make a relying party read.
	maxFederationResponseBytes = 1 << 20
)

var (
	// trustAnchorKeys refuses an anchor that does not state its alg: it is the operator's configuration, and nothing
	// vouches for it.
	trustAnchorKeys = openid.VerifyOptions{RequireKeyAlgorithm: true}
	// memberKeys accepts keys without alg, as RFC 7517 section 4.4 does and members of the reference federation publish
	// them. A chain from the anchor vouches for them, and their type and curve still fix the algorithm.
	memberKeys = openid.VerifyOptions{}
)

// errRedirectRefused is what a federation fetch that is redirected ends in. A URL is checked before a fetch, so a
// redirect would lead past the check, and with the relying party's client it would present the mTLS key elsewhere.
var errRedirectRefused = errors.New("redirect refused")

func refuseRedirect(*http.Request, []*http.Request) error {
	return errRedirectRefused
}

// checkFederationURL lets through what a federation document may send a fetch to: an https URL, with a host and no
// credentials. It holds tests too, whose stubs serve TLS, so that no plain path exists to be left open.
func checkFederationURL(location string) error {
	parsed, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("%q is no URL", location)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("%q is not an https URL", location)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%q has credentials or a fragment", location)
	}
	return nil
}

// checkEntityIdentifier is checkFederationURL for an entity identifier, which comes without a query since a path is
// appended to it. The issuer asked for comes from the request's idp_iss.
func checkEntityIdentifier(iss string) error {
	if err := checkFederationURL(iss); err != nil {
		return err
	}
	if strings.Contains(iss, "?") {
		return fmt.Errorf("%q has a query", iss)
	}
	return nil
}

// readBounded reads a federation response, and fails rather than cut it off at the limit.
func readBounded(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxFederationResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxFederationResponseBytes {
		return nil, fmt.Errorf("response larger than %d bytes", maxFederationResponseBytes)
	}
	return body, nil
}

// verifyStatement verifies a signed federation document against keys and checks its lifetime, returning its claims.
func verifyStatement(signed []byte, keys *jose.JSONWebKeySet, options openid.VerifyOptions, now time.Time) ([]byte, error) {
	payload, err := openid.VerifyJWS(bytes.TrimSpace(signed), keys, options)
	if err != nil {
		return nil, err
	}
	if err := openid.ValidateLifetime(payload, now.Add(statementClockTolerance), 0); err != nil {
		return nil, err
	}
	return payload, nil
}

// transportOrDefault returns http.DefaultTransport when rt is nil, so a decorated client always
// has a concrete base transport to wrap.
func transportOrDefault(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		return http.DefaultTransport
	}
	return rt
}

// OpenidFederation is a client of one federation master, holding the trust anchor that everything fetched from
// the master is verified against.
type OpenidFederation struct {
	fedMasterURL string
	jwks         *jose.JSONWebKeySet
	httpClient   *http.Client
	clock        func() time.Time
	documents    Documents
	logger       *slog.Logger

	mu       sync.Mutex
	inflight map[string]*flight
}

// flight is one resolution of a document that concurrent callers wait for instead of fetching it too.
type flight struct {
	done   chan struct{}
	signed []byte
	err    error
}

// now is the time the federation judges statements at.
func (f *OpenidFederation) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}

// OpenidProvider names an OpenID provider by its issuer.
type OpenidProvider struct {
	Issuer string
}

// IdentityProviderInfo is one entry of the federation master's IdP list.
type IdentityProviderInfo struct {
	Issuer           string   `json:"iss"`
	LogoURI          string   `json:"logo_uri"`
	OrganizationName string   `json:"organization_name"`
	IsPkv            bool     `json:"pkv"`
	UserType         UserType `json:"user_type_supported"`
}

// Option configures an OpenidFederation.
type Option func(*federationOptions)

type federationOptions struct {
	httpClient *http.Client
	apiKey     string
	clock      func() time.Time
	documents  Documents
	logger     *slog.Logger
}

// WithClock sets the time statements are judged at; the default is the system clock.
func WithClock(now func() time.Time) Option {
	return func(o *federationOptions) {
		o.clock = now
	}
}

// WithAPIKey supplies the key for the gematik environments that gate on one; see [AddAPIKeyTransport].
func WithAPIKey(apiKey string) Option {
	return func(o *federationOptions) {
		o.apiKey = apiKey
	}
}

// WithHTTPClient supplies the base HTTP client; the federation API key and the refusal of redirects are layered onto a
// copy of it. When unset, a client with a default timeout is created.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(o *federationOptions) {
		o.httpClient = httpClient
	}
}

// WithDocuments supplies the store of signed federation documents. It is required.
func WithDocuments(documents Documents) Option {
	return func(o *federationOptions) {
		o.documents = documents
	}
}

// WithLogger supplies the logger a failing document store is reported to. Without one such failures cost only a
// fetch and are not reported.
func WithLogger(logger *slog.Logger) Option {
	return func(o *federationOptions) {
		o.logger = logger
	}
}

// NewOpenidFederation resolves the master's entity statement from fedMasterURL, verifies it against the trust
// anchor jwks and returns a client of that master. It fails if the statement does not verify or names no
// federation_entity metadata, or if no document store is given.
func NewOpenidFederation(ctx context.Context, fedMasterURL string, jwks *jose.JSONWebKeySet, opts ...Option) (*OpenidFederation, error) {
	o := &federationOptions{}
	for _, opt := range opts {
		opt(o)
	}
	if o.documents == nil {
		return nil, errors.New("a store of federation documents is required")
	}

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// layer the federation API key onto the chosen client without mutating the caller's
	decorated := *httpClient
	decorated.Transport = AddAPIKeyTransport(transportOrDefault(httpClient.Transport), o.apiKey)
	decorated.CheckRedirect = refuseRedirect

	federation := &OpenidFederation{
		fedMasterURL: fedMasterURL,
		jwks:         jwks,
		httpClient:   &decorated,
		clock:        o.clock,
		documents:    o.documents,
		logger:       o.logger,
		inflight:     make(map[string]*flight),
	}
	if _, err := federation.masterEntity(ctx); err != nil {
		return nil, err
	}
	return federation, nil
}

// get is the one way a fetch leaves this package: location is checked, whoever chose it.
func (f *OpenidFederation) get(ctx context.Context, location string) (*http.Response, error) {
	if err := checkFederationURL(location); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil) //nolint:gosec // checkFederationURL let location through: https, from the operator's fed_master_url or a statement that verified along the chain from the trust anchor
	if err != nil {
		return nil, err
	}
	return f.httpClient.Do(request) //nolint:gosec // checkFederationURL let the URL through, and the client refuses redirects
}

// fetch reads the signed document at location. A refusal the member explains in an OAuth error body is returned as
// *Error.
func (f *OpenidFederation) fetch(ctx context.Context, location string) ([]byte, error) {
	response, err := f.get(ctx, location)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := readBounded(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		var oidcErr Error
		if err := json.Unmarshal(body, &oidcErr); err != nil || oidcErr.ErrorCode == "" {
			return nil, fmt.Errorf("http error %d", response.StatusCode)
		}
		return nil, fmt.Errorf("http error %d: %w", response.StatusCode, &oidcErr)
	}
	return body, nil
}

// document returns what check reads from the signed document at location, once it verified against keys with
// options and lies within its lifetime. A document kept in the store is judged exactly like a fetched one; one that
// no longer passes, having expired or been altered, is fetched again and replaces the kept one (servers.md rule 12).
func document[T any](ctx context.Context, f *OpenidFederation, location string, keys *jose.JSONWebKeySet, options openid.VerifyOptions, check func(payload []byte) (T, error)) (T, error) {
	read := func(signed []byte) (T, []byte, error) {
		var zero T
		payload, err := verifyStatement(signed, keys, options, f.now())
		if err != nil {
			return zero, nil, err
		}
		value, err := check(payload)
		return value, payload, err
	}
	signed, err := f.signedDocument(ctx, location, func(signed []byte) ([]byte, error) {
		_, payload, err := read(signed)
		return payload, err
	})
	if err != nil {
		var zero T
		return zero, err
	}
	value, _, err := read(signed)
	return value, err
}

// signedDocument resolves the document at location once per process at a time: a caller that finds a resolution
// under way waits for it, as long as its own context lets it, and judges the result itself. Each caller judges with
// its own keys, so a result is never trusted for having passed another caller's judgement (servers.md rule 12,
// protection against stampedes).
func (f *OpenidFederation) signedDocument(ctx context.Context, location string, judge func(signed []byte) ([]byte, error)) ([]byte, error) {
	if err := checkFederationURL(location); err != nil {
		return nil, err
	}
	for {
		f.mu.Lock()
		call, waiting := f.inflight[location]
		if !waiting {
			call = &flight{done: make(chan struct{})}
			f.inflight[location] = call
		}
		f.mu.Unlock()

		if !waiting {
			f.lead(ctx, location, call, judge)
			return call.signed, call.err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-call.done:
		}
		// The leader's context ended, not this caller's: resolve again rather than fail a login for another's.
		if (errors.Is(call.err, context.Canceled) || errors.Is(call.err, context.DeadlineExceeded)) && ctx.Err() == nil {
			continue
		}
		if call.err != nil {
			return nil, call.err
		}
		if _, err := judge(call.signed); err != nil {
			return nil, err
		}
		return call.signed, nil
	}
}

// lead resolves the document for everyone waiting on call and releases them, also when judge panics.
func (f *OpenidFederation) lead(ctx context.Context, location string, call *flight, judge func(signed []byte) ([]byte, error)) {
	defer func() {
		f.mu.Lock()
		delete(f.inflight, location)
		f.mu.Unlock()
		close(call.done)
	}()
	// Stays the result for the waiters if resolve panics.
	call.err = errors.New("resolution did not finish")
	call.signed, call.err = f.resolve(ctx, location, judge)
}

// resolve takes the kept document if it passes judge, and otherwise fetches one and keeps it if it passes. A store
// that fails costs a fetch, never the result.
func (f *OpenidFederation) resolve(ctx context.Context, location string, judge func(signed []byte) ([]byte, error)) ([]byte, error) {
	kept, found, err := f.documents.Get(ctx, location)
	switch {
	case err != nil:
		f.report(ctx, "reading a kept federation document failed", location, err)
	case found:
		if _, err := judge(kept); err == nil {
			return kept, nil
		}
	}

	signed, err := f.fetch(ctx, location)
	if err != nil {
		return nil, err
	}
	payload, err := judge(signed)
	if err != nil {
		return nil, err
	}
	// A document without exp is not kept: nothing would bound how long it stays.
	if until, ok := expiresAt(payload); ok {
		if err := f.documents.Keep(ctx, location, signed, until); err != nil {
			f.report(ctx, "keeping a federation document failed", location, err)
		}
	}
	return signed, nil
}

// expiresAt reads exp of a verified payload, if it is an integer number of seconds.
func expiresAt(payload []byte) (time.Time, bool) {
	var claims struct {
		ExpiresAt *json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.ExpiresAt == nil {
		return time.Time{}, false
	}
	seconds, err := claims.ExpiresAt.Int64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}

// report hands a failure of the document store to the logger, if there is one.
func (f *OpenidFederation) report(ctx context.Context, message, location string, err error) {
	if f.logger != nil {
		f.logger.WarnContext(ctx, message, "url", location, "error", err)
	}
}

// masterEntity is the federation_entity metadata of the master's own statement, which is resolved like any other
// document, so endpoints come from a statement that has not expired.
func (f *OpenidFederation) masterEntity(ctx context.Context) (*FederationEntityMetadata, error) {
	location := f.fedMasterURL + "/.well-known/openid-federation"
	es, err := document(ctx, f, location, f.jwks, trustAnchorKeys, func(payload []byte) (*EntityStatement, error) {
		es, err := parseEntityStatement(payload)
		if err != nil {
			return nil, err
		}
		if es.Issuer != f.fedMasterURL || es.Subject != f.fedMasterURL {
			return nil, fmt.Errorf("the master's statement names iss %q and sub %q, not %q", es.Issuer, es.Subject, f.fedMasterURL)
		}
		if es.Metadata == nil || es.Metadata.FederationEntity == nil {
			return nil, errors.New("no federation entity found in master entity statement")
		}
		return es, nil
	})
	if err != nil {
		return nil, fmt.Errorf("the master's entity statement from '%s': %w", location, err)
	}
	return es.Metadata.FederationEntity, nil
}

// FetchIdpList returns the master's IdP list, verified against the trust anchor.
func (f *OpenidFederation) FetchIdpList(ctx context.Context) ([]IdentityProviderInfo, error) {
	entity, err := f.masterEntity(ctx)
	if err != nil {
		return nil, err
	}
	idps, err := document(ctx, f, entity.IdpListEndpoint, f.jwks, trustAnchorKeys, func(payload []byte) ([]IdentityProviderInfo, error) {
		var claims struct {
			IdpEntity *[]IdentityProviderInfo `json:"idp_entity"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			return nil, fmt.Errorf("unable to read idp_entity from token: %w", err)
		}
		if claims.IdpEntity == nil {
			return nil, errors.New("unable to get idp_entity from token: no such claim")
		}
		return *claims.IdpEntity, nil
	})
	if err != nil {
		return nil, fmt.Errorf("idp list from '%s': %w", entity.IdpListEndpoint, err)
	}
	return idps, nil
}

// FetchEntityStatement returns the self-signed entity statement of the issuer iss, verified with the keys that
// the master's statement about iss vouches for.
func (f *OpenidFederation) FetchEntityStatement(ctx context.Context, iss string) (*EntityStatement, error) {
	if err := checkEntityIdentifier(iss); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	entity, err := f.masterEntity(ctx)
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Add("iss", f.fedMasterURL)
	query.Add("sub", iss)
	location := entity.FederationFetchEndpoint + "?" + query.Encode()

	fromMaster, err := document(ctx, f, location, f.jwks, trustAnchorKeys, func(payload []byte) (*EntityStatement, error) {
		es, err := parseEntityStatement(payload)
		if err != nil {
			return nil, err
		}
		if es.Jwks == nil {
			return nil, fmt.Errorf("the master's statement about '%s' vouches for no keys", iss)
		}
		if es.Issuer != f.fedMasterURL || es.Subject != iss {
			return nil, fmt.Errorf("asked the master about '%s', its statement names iss %q and sub %q", iss, es.Issuer, es.Subject)
		}
		return es, nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %w", location, err)
	}

	selfSigned, err := document(ctx, f, iss+"/.well-known/openid-federation", fromMaster.Jwks.Keys, memberKeys, func(payload []byte) (*EntityStatement, error) {
		es, err := parseEntityStatement(payload)
		if err != nil {
			return nil, err
		}
		if es.Issuer != iss || es.Subject != iss {
			return nil, fmt.Errorf("the statement of '%s' names iss %q and sub %q", iss, es.Issuer, es.Subject)
		}
		return es, nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %w", iss, err)
	}
	return selfSigned, nil
}

// FederationMasterURL returns the URL given to NewOpenidFederation.
func (f *OpenidFederation) FederationMasterURL() string {
	return f.fedMasterURL
}

// FetchSignedJwks returns the key set published at op's signed_jwks_uri, verified against the keys of op's
// entity statement, so op has to be a statement FetchEntityStatement verified.
func (f *OpenidFederation) FetchSignedJwks(ctx context.Context, op *EntityStatement) (*jose.JSONWebKeySet, error) {
	if op.Metadata == nil || op.Metadata.OpenidProvider == nil {
		return nil, errors.New("no openid provider found in entity statement")
	}
	if op.Jwks == nil {
		return nil, errors.New("no keys found in entity statement")
	}

	jwksURL := op.Metadata.OpenidProvider.SignedJwksURI
	jwks, err := document(ctx, f, jwksURL, op.Jwks.Keys, memberKeys, func(payload []byte) (*jose.JSONWebKeySet, error) {
		if err := requireExpiry(payload); err != nil {
			return nil, err
		}
		jwks, err := openid.ParseKeySet(payload)
		if err != nil {
			return nil, fmt.Errorf("parsing jwks failed: %w", err)
		}
		return jwks, nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch jwks from '%s': %w", jwksURL, err)
	}
	return jwks, nil
}

// requireExpiry refuses a signed key set without exp. The federation specification leaves exp optional, while server
// rule 15 makes it mandatory here: without one, a key set an OP has since replaced could be replayed for ever.
func requireExpiry(payload []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return err
	}
	if _, ok := members["exp"]; !ok {
		return errors.New("a signed key set has to state its exp")
	}
	return nil
}
