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
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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

// errFederationURL is a URL a fetch is refused for. It names no URL: one may come from a request.
var errFederationURL = errors.New("federation URL refused")

// checkFederationURL lets through what a federation document may send a fetch to: an https URL of at most
// maxEntityIdentifierBytes printable ASCII characters, with a host and no credentials or fragment. It holds tests too,
// whose stubs serve TLS, so that no plain path exists to be left open.
func checkFederationURL(location string) error {
	if len(location) > maxEntityIdentifierBytes {
		return fmt.Errorf("%w: longer than %d characters", errFederationURL, maxEntityIdentifierBytes)
	}
	for _, c := range []byte(location) {
		if c <= 0x20 || c >= 0x7f {
			return fmt.Errorf("%w: a character outside printable ASCII", errFederationURL)
		}
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("%w: no URL", errFederationURL)
	}
	if !strings.HasPrefix(location, "https://") || parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("%w: not an https URL", errFederationURL)
	}
	if parsed.User != nil || strings.Contains(location, "#") {
		return fmt.Errorf("%w: credentials or a fragment", errFederationURL)
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
	// excludedReported is the digest of the last IdP list whose excluded entries were reported.
	excludedReported atomic.Pointer[[sha256.Size]byte]
}

// flight is one fetch of a document that concurrent callers wait for instead of fetching it too. It carries the
// fetched bytes or the fetch's error, never a judgement.
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
		return nil, parseErrorResponse(&openid.Response{Status: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body})
	}
	return body, nil
}

// document returns what check reads from the signed document at location, once it verified against keys with
// options and lies within its lifetime. A document kept in the store is judged exactly like a fetched one; one that
// no longer passes, having expired or been altered, is fetched again and replaces the kept one (servers.md rule 12).
// Every caller judges with its own keys and checks, once per document it reads, so no caller takes a document for
// having passed another caller's judgement. fresh skips the store, for a caller that knows the kept document to be
// outdated although it still verifies (gemSpec_IDP_FD A_22861).
func document[T any](ctx context.Context, f *OpenidFederation, location string, fresh bool, keys *jose.JSONWebKeySet, options openid.VerifyOptions, check func(payload []byte) (T, error)) (T, error) {
	var zero T
	read := func(signed []byte) (T, []byte, error) {
		payload, err := verifyStatement(signed, keys, options, f.now())
		if err != nil {
			return zero, nil, err
		}
		value, err := check(payload)
		return value, payload, err
	}
	if err := checkFederationURL(location); err != nil {
		return zero, err
	}

	if !fresh {
		kept, found, err := f.documents.Get(ctx, location)
		switch {
		case err != nil:
			f.report(ctx, "reading a kept federation document failed", location, err)
		case found:
			if value, _, err := read(kept); err == nil {
				return value, nil
			}
		}
	}

	var value T
	var readErr error
	signed, led, err := f.fetchOnce(ctx, location, func(signed []byte) {
		var payload []byte
		value, payload, readErr = read(signed)
		if readErr == nil {
			f.keep(ctx, location, signed, payload)
		}
	})
	if err != nil {
		return zero, err
	}
	if led {
		return value, readErr
	}
	value, _, err = read(signed)
	return value, err
}

// fetchOnce fetches the document at location once per process at a time (servers.md rule 12, protection against
// stampedes). The caller that fetches leads: it runs lead on what it fetched before the others are released, so a
// document it keeps is in the store by then. The others wait as long as their own context lets them and get the
// fetched bytes, or the fetch's error, to judge themselves.
func (f *OpenidFederation) fetchOnce(ctx context.Context, location string, lead func(signed []byte)) (signed []byte, led bool, err error) {
	for {
		f.mu.Lock()
		call, waiting := f.inflight[location]
		if !waiting {
			call = &flight{done: make(chan struct{})}
			f.inflight[location] = call
		}
		f.mu.Unlock()

		if !waiting {
			f.fetchFor(ctx, location, call, lead)
			return call.signed, true, call.err
		}
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-call.done:
		}
		// The leader's context ended, not this caller's: fetch again rather than fail a login for another's.
		if (errors.Is(call.err, context.Canceled) || errors.Is(call.err, context.DeadlineExceeded)) && ctx.Err() == nil {
			continue
		}
		return call.signed, false, call.err
	}
}

// fetchFor fetches for everyone waiting on call and releases them, also when lead panics.
func (f *OpenidFederation) fetchFor(ctx context.Context, location string, call *flight, lead func(signed []byte)) {
	defer func() {
		f.mu.Lock()
		delete(f.inflight, location)
		f.mu.Unlock()
		close(call.done)
	}()
	// Stays the result for the waiters if the fetch or lead panics.
	call.err = errors.New("fetch did not finish")
	signed, err := f.fetch(ctx, location)
	if err == nil {
		lead(signed)
	}
	call.signed, call.err = signed, err
}

// keep stores a document that passed its judgement until its exp. A document without exp is not kept: nothing would
// bound how long it stays. A store that fails costs a later fetch, never the result.
func (f *OpenidFederation) keep(ctx context.Context, location string, signed, payload []byte) {
	until, ok := expiresAt(payload)
	if !ok {
		return
	}
	if err := f.documents.Keep(ctx, location, signed, until); err != nil {
		f.report(ctx, "keeping a federation document failed", location, err)
	}
}

// expiresAt reads exp of a verified payload, if it is an integer number of seconds.
func expiresAt(payload []byte) (time.Time, bool) {
	var claims struct {
		ExpiresAt *int64 `json:"exp"`
	}
	if err := openid.UnmarshalObject(payload, openid.PayloadDepth, openid.PayloadMembers, &claims); err != nil || claims.ExpiresAt == nil {
		return time.Time{}, false
	}
	return time.Unix(*claims.ExpiresAt, 0), true
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
	es, err := document(ctx, f, location, false, f.jwks, trustAnchorKeys, func(payload []byte) (*EntityStatement, error) {
		es, err := parseEntityStatement(payload)
		if err != nil {
			return nil, err
		}
		if es.Issuer != f.fedMasterURL || es.Subject != f.fedMasterURL {
			return nil, errors.New("the master's statement names another iss or sub than the master")
		}
		if es.Metadata == nil || es.Metadata.FederationEntity == nil {
			return nil, errors.New("no federation entity found in master entity statement")
		}
		return es, nil
	})
	if err != nil {
		return nil, fmt.Errorf("the master's entity statement: %w", err)
	}
	return es.Metadata.FederationEntity, nil
}

// FetchIdpList returns the master's IdP list, verified against the trust anchor.
func (f *OpenidFederation) FetchIdpList(ctx context.Context) ([]IdentityProviderInfo, error) {
	entity, err := f.masterEntity(ctx)
	if err != nil {
		return nil, err
	}
	// The list is kept no longer than its exp, like every document (keep).
	idps, err := document(ctx, f, entity.IdpListEndpoint, false, f.jwks, trustAnchorKeys, func(payload []byte) ([]IdentityProviderInfo, error) {
		var claims struct {
			Issuer string `json:"iss"`
		}
		if err := openid.UnmarshalObject(payload, openid.PayloadDepth, openid.PayloadMembers, &claims); err != nil || claims.Issuer != f.fedMasterURL {
			return nil, errors.New("the IdP list is not the master's: iss names another")
		}
		idps, excluded, err := parseIdpList(payload)
		if err == nil && excluded > 0 {
			f.reportExcluded(ctx, payload, excluded)
		}
		return idps, err
	})
	if err != nil {
		return nil, fmt.Errorf("the IdP list: %w", err)
	}
	return idps, nil
}

// maxIdps bounds the entries of the IdP list; the federation has a few dozen.
const maxIdps = 512

// parseIdpList reads the idp_entity member of the master's verified IdP list (gemSpec_IDP_FedMaster Tabelle 8). The
// list as a whole is refused when it is no JSON object within bounds, states no exp, has no idp_entity array or more
// than maxIdps entries. An entry outside the grammar is excluded and the rest kept: every entry needs an iss that is
// an entity identifier, and its informational members text within bounds. Excluding is rejection, not repair: the
// master signed the whole list, admission compares issuers byte for byte, and an excluded issuer is never admitted.
// excluded counts the entries left out, for the operator; what they held is not reported.
func parseIdpList(payload []byte) (idps []IdentityProviderInfo, excluded int, err error) {
	var members map[string]jsontext.Value
	if err := openid.UnmarshalObject(payload, openid.PayloadDepth, openid.PayloadMembers, &members); err != nil {
		return nil, 0, fmt.Errorf("the IdP list: %w", err)
	}
	if err := requireExpiry(payload); err != nil {
		return nil, 0, fmt.Errorf("the IdP list: %w", err)
	}
	var entries []jsontext.Value
	raw, ok := members["idp_entity"]
	if !ok {
		return nil, 0, errors.New("the IdP list has no idp_entity")
	}
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return nil, 0, errors.New("the IdP list's idp_entity is no array")
	}
	if len(entries) > maxIdps {
		return nil, 0, fmt.Errorf("the IdP list has more than %d entries", maxIdps)
	}
	idps = make([]IdentityProviderInfo, 0, len(entries))
	for _, raw := range entries {
		var entry map[string]jsontext.Value
		if json.Unmarshal(raw, &entry) != nil {
			excluded++
			continue
		}
		idp, err := parseIdpEntry(entry)
		if err != nil {
			excluded++
			continue
		}
		idps = append(idps, idp)
	}
	return idps, excluded, nil
}

// reportExcluded tells the logger, if there is one, how many entries of the IdP list were excluded, once per list:
// the list is judged on every admission.
func (f *OpenidFederation) reportExcluded(ctx context.Context, payload []byte, excluded int) {
	if f.logger == nil {
		return
	}
	sum := sha256.Sum256(payload)
	if previous := f.excludedReported.Swap(&sum); previous != nil && *previous == sum {
		return
	}
	f.logger.WarnContext(ctx, "entries of the IdP list excluded for being outside their grammar", "excluded", excluded)
}

func parseIdpEntry(entry map[string]jsontext.Value) (IdentityProviderInfo, error) {
	var idp IdentityProviderInfo
	if entry == nil {
		return idp, errors.New("not an object")
	}
	iss, present, err := textMember(entry, "iss", maxEntityIdentifierBytes)
	if err != nil || !present {
		return idp, errors.New("iss is no text")
	}
	if err := checkEntityIdentifier(iss); err != nil {
		return idp, errors.New("iss is no entity identifier")
	}
	idp.Issuer = iss
	if idp.OrganizationName, _, err = textMember(entry, "organization_name", maxTextBytes); err != nil {
		return idp, fmt.Errorf("organization_name: %w", err)
	}
	if idp.LogoURI, _, err = textMember(entry, "logo_uri", maxEntityIdentifierBytes); err != nil {
		return idp, fmt.Errorf("logo_uri: %w", err)
	}
	if raw, ok := entry["pkv"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &idp.IsPkv); err != nil {
			return idp, errors.New("pkv is no boolean")
		}
	}
	userType, err := userTypeMember(entry)
	if err != nil {
		return idp, err
	}
	idp.UserType = userType
	return idp, nil
}

// userTypeMember reads user_type_supported, which Tabelle 8 types [string] and masters have served as a string; a
// list of one is read as that one, a longer list as none, since IdentityProviderInfo holds one. None is harmless while
// nothing filters by user type (TASK-297).
func userTypeMember(entry map[string]jsontext.Value) (UserType, error) {
	raw, ok := entry["user_type_supported"]
	if !ok || string(raw) == "null" {
		return "", nil
	}
	if single, _, err := textMember(entry, "user_type_supported", maxTextBytes); err == nil {
		return UserType(single), nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return "", errors.New("user_type_supported is neither text nor a list of text")
	}
	for _, value := range list {
		if err := checkText(value, maxTextBytes); err != nil {
			return "", fmt.Errorf("user_type_supported: %w", err)
		}
	}
	if len(list) == 1 {
		return UserType(list[0]), nil
	}
	return "", nil
}

// FetchEntityStatement returns the self-signed entity statement of the issuer iss, verified with the keys that
// the master's statement about iss vouches for.
func (f *OpenidFederation) FetchEntityStatement(ctx context.Context, iss string) (*EntityStatement, error) {
	return f.entityStatement(ctx, iss, false)
}

// entityStatement is FetchEntityStatement; fresh fetches the master's statement about iss and the statement of iss
// past the store.
func (f *OpenidFederation) entityStatement(ctx context.Context, iss string, fresh bool) (*EntityStatement, error) {
	if err := checkEntityIdentifier(iss); err != nil {
		return nil, err
	}
	entity, err := f.masterEntity(ctx)
	if err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Add("iss", f.fedMasterURL)
	query.Add("sub", iss)
	location := entity.FederationFetchEndpoint + "?" + query.Encode()

	fromMaster, err := document(ctx, f, location, fresh, f.jwks, trustAnchorKeys, func(payload []byte) (*EntityStatement, error) {
		es, err := parseEntityStatement(payload)
		if err != nil {
			return nil, err
		}
		if es.Jwks == nil {
			return nil, errors.New("the master's statement about the issuer vouches for no keys")
		}
		if es.Issuer != f.fedMasterURL || es.Subject != iss {
			return nil, errors.New("the master's statement about the issuer names another iss or sub")
		}
		return es, nil
	})
	if err != nil {
		return nil, fmt.Errorf("the master's statement about the issuer: %w", err)
	}

	selfSigned, err := document(ctx, f, iss+"/.well-known/openid-federation", fresh, fromMaster.Jwks.Keys, memberKeys, func(payload []byte) (*EntityStatement, error) {
		es, err := parseEntityStatement(payload)
		if err != nil {
			return nil, err
		}
		if es.Issuer != iss || es.Subject != iss {
			return nil, errors.New("the issuer's statement names another iss or sub")
		}
		return es, nil
	})
	if err != nil {
		return nil, fmt.Errorf("the issuer's entity statement: %w", err)
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
	return f.signedJwks(ctx, op, false)
}

// signedJwks is FetchSignedJwks; fresh fetches past the store.
func (f *OpenidFederation) signedJwks(ctx context.Context, op *EntityStatement, fresh bool) (*jose.JSONWebKeySet, error) {
	if op.Metadata == nil || op.Metadata.OpenidProvider == nil {
		return nil, errors.New("no openid provider found in entity statement")
	}
	if op.Jwks == nil {
		return nil, errors.New("no keys found in entity statement")
	}

	jwksURL := op.Metadata.OpenidProvider.SignedJwksURI
	jwks, err := document(ctx, f, jwksURL, fresh, op.Jwks.Keys, memberKeys, func(payload []byte) (*jose.JSONWebKeySet, error) {
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
		return nil, fmt.Errorf("the signed JWKS: %w", err)
	}
	return jwks, nil
}

// requireExpiry refuses a signed key set without exp. The federation specification leaves exp optional, while server
// rule 15 makes it mandatory here: without one, a key set an OP has since replaced could be replayed for ever.
func requireExpiry(payload []byte) error {
	var members map[string]jsontext.Value
	if err := openid.UnmarshalObject(payload, openid.PayloadDepth, openid.PayloadMembers, &members); err != nil {
		return err
	}
	if _, ok := members["exp"]; !ok {
		return errors.New("a signed key set or IdP list has to state its exp")
	}
	return nil
}
