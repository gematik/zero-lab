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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth/oidc"
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
	trustAnchorKeys = oidc.VerifyOptions{RequireKeyAlgorithm: true}
	// memberKeys accepts keys without alg, as RFC 7517 section 4.4 does and members of the reference federation publish
	// them. A chain from the anchor vouches for them, and their type and curve still fix the algorithm.
	memberKeys = oidc.VerifyOptions{}
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
func verifyStatement(r io.Reader, keys *jose.JSONWebKeySet, options oidc.VerifyOptions) ([]byte, error) {
	signed, err := readBounded(r)
	if err != nil {
		return nil, err
	}
	payload, err := oidc.VerifyJWS(bytes.TrimSpace(signed), keys, options)
	if err != nil {
		return nil, err
	}
	if err := oidc.ValidateLifetime(payload, time.Now().Add(statementClockTolerance), 0); err != nil {
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
	entity       *FederationEntityMetadata
	httpClient   *http.Client
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
}

// WithHTTPClient supplies the base HTTP client; the federation API key and the refusal of redirects are layered onto a
// copy of it. When unset, a client with a default timeout is created.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(o *federationOptions) {
		o.httpClient = httpClient
	}
}

// NewOpenidFederation fetches the master's entity statement from fedMasterURL, verifies it against the trust
// anchor jwks and returns a client of that master. It fails if the statement does not verify or names no
// federation_entity metadata.
func NewOpenidFederation(fedMasterURL string, jwks *jose.JSONWebKeySet, opts ...Option) (*OpenidFederation, error) {
	o := &federationOptions{}
	for _, opt := range opts {
		opt(o)
	}

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// layer the federation API key onto the chosen client without mutating the caller's
	decorated := *httpClient
	decorated.Transport = AddAPIKeyTransport(transportOrDefault(httpClient.Transport))
	decorated.CheckRedirect = refuseRedirect

	federation := &OpenidFederation{
		fedMasterURL: fedMasterURL,
		jwks:         jwks,
		httpClient:   &decorated,
	}
	es, err := federation.fetchMasterEntityStatement()
	if err != nil {
		return nil, err
	}

	if es.Issuer != fedMasterURL || es.Subject != fedMasterURL {
		return nil, fmt.Errorf("the master's statement names iss %q and sub %q, not %q", es.Issuer, es.Subject, fedMasterURL)
	}
	if es.Metadata == nil || es.Metadata.FederationEntity == nil {
		return nil, errors.New("no federation entity found in master entity statement")
	}
	federation.entity = es.Metadata.FederationEntity
	return federation, nil
}

// get is the one way a fetch leaves this package: location is checked, whoever chose it.
func (f *OpenidFederation) get(location string) (*http.Response, error) {
	if err := checkFederationURL(location); err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodGet, location, nil) //nolint:gosec // checkFederationURL let location through: https, from the operator's fed_master_url or a statement that verified along the chain from the trust anchor
	if err != nil {
		return nil, err
	}
	return f.httpClient.Do(request) //nolint:gosec // checkFederationURL let the URL through, and the client refuses redirects
}

// FetchIdpList fetches the master's IdP list and verifies it against the trust anchor. Each call goes to the
// network.
func (f *OpenidFederation) FetchIdpList() ([]IdentityProviderInfo, error) {
	r, err := f.get(f.entity.IdpListEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch idp list from '%s': %w", f.entity.IdpListEndpoint, err)
	}
	defer r.Body.Close()

	payload, err := verifyStatement(r.Body, f.jwks, trustAnchorKeys)
	if err != nil {
		return nil, err
	}

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
}

func (f *OpenidFederation) fetchMasterEntityStatement() (*EntityStatement, error) {
	resp, err := f.get(f.fedMasterURL + "/.well-known/openid-federation")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %s", f.fedMasterURL, resp.Status)
	}

	payload, err := verifyStatement(resp.Body, f.jwks, trustAnchorKeys)
	if err != nil {
		return nil, err
	}

	return parseEntityStatement(payload)
}

func (f *OpenidFederation) fetchAndVerify(url string, jwks *jose.JSONWebKeySet, options oidc.VerifyOptions) (*EntityStatement, error) {
	resp, err := f.get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := readBounded(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("http error %d", resp.StatusCode)
		}
		var oidcErr Error
		if err := json.Unmarshal(body, &oidcErr); err != nil {
			return nil, fmt.Errorf("http error %d", resp.StatusCode)
		}
		return nil, &oidcErr
	}

	payload, err := verifyStatement(resp.Body, jwks, options)
	if err != nil {
		return nil, err
	}

	return parseEntityStatement(payload)
}

// FetchEntityStatement returns the self-signed entity statement of the issuer iss, verified with the keys that
// the master's statement about iss vouches for.
func (f *OpenidFederation) FetchEntityStatement(iss string) (*EntityStatement, error) {
	if err := checkEntityIdentifier(iss); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}

	query := url.Values{}
	query.Add("iss", f.fedMasterURL)
	query.Add("sub", iss)

	url := f.entity.FederationFetchEndpoint + "?" + query.Encode()

	// fetch the entity statement from the fed master first to get the trusted keys
	fromMaster, err := f.fetchAndVerify(url, f.jwks, trustAnchorKeys)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %w", url, err)
	}

	if fromMaster.Jwks == nil {
		return nil, fmt.Errorf("the master's statement about '%s' vouches for no keys", iss)
	}
	if fromMaster.Issuer != f.fedMasterURL || fromMaster.Subject != iss {
		return nil, fmt.Errorf("asked the master about '%s', its statement names iss %q and sub %q", iss, fromMaster.Issuer, fromMaster.Subject)
	}

	selfSigned, err := f.fetchAndVerify(iss+"/.well-known/openid-federation", fromMaster.Jwks.Keys, memberKeys)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %w", iss, err)
	}
	if selfSigned.Issuer != iss || selfSigned.Subject != iss {
		return nil, fmt.Errorf("the statement of '%s' names iss %q and sub %q", iss, selfSigned.Issuer, selfSigned.Subject)
	}

	return selfSigned, nil
}

// FederationMasterURL returns the URL given to NewOpenidFederation.
func (f *OpenidFederation) FederationMasterURL() string {
	return f.fedMasterURL
}

// FetchSignedJwks returns the key set published at op's signed_jwks_uri, verified against the keys of op's
// entity statement, so op has to be a statement FetchEntityStatement verified.
func (f *OpenidFederation) FetchSignedJwks(op *EntityStatement) (*jose.JSONWebKeySet, error) {
	if op.Metadata == nil || op.Metadata.OpenidProvider == nil {
		return nil, errors.New("no openid provider found in entity statement")
	}
	if op.Jwks == nil {
		return nil, errors.New("no keys found in entity statement")
	}

	jwksURL := op.Metadata.OpenidProvider.SignedJwksURI

	resp, err := f.get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch jwks from '%s': %w", jwksURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to fetch jwks from '%s': %s", jwksURL, resp.Status)
	}

	jwksBytes, err := verifyStatement(resp.Body, op.Jwks.Keys, memberKeys)
	if err != nil {
		return nil, fmt.Errorf("unable to verify jwks: %w", err)
	}
	if err := requireExpiry(jwksBytes); err != nil {
		return nil, fmt.Errorf("unable to verify jwks: %w", err)
	}

	jwks, err := oidc.ParseKeySet(jwksBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing jwks failed: %w", err)
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
