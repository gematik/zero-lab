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

package oidf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

// RelyingPartyClient is an openid.Client for one OpenID provider of the federation; [RelyingParty.Client] creates it.
// It is safe for concurrent use and may be cached: every call re-checks that the provider is on the master's IdP list
// and that the documents it was resolved from are still valid, and resolves them anew from the store, or fetches them
// once the kept ones no longer verify.
type RelyingPartyClient struct {
	rp          *RelyingParty
	issuer      string
	scopes      []string
	redirectURI string
	// current is what the provider published when it was last resolved; a refetch replaces it whole.
	current atomic.Pointer[provider]
}

// provider is an OpenID provider as resolved: its verified entity statement, the openid_provider metadata in it and
// its signed JWKS.
type provider struct {
	op       *EntityStatement
	metadata *OpenIDProviderMetadata
	jwks     *jose.JSONWebKeySet
}

// provider is what the client resolved last.
func (c *RelyingPartyClient) provider() *provider {
	return c.current.Load()
}

// resolve judges the provider anew for one call: admitted by the master's IdP list (gemSpec_IDP_FedMaster Tabelle 8),
// and its statement and signed JWKS verified along the chain from the trust anchor. Documents come from the store while
// they verify, so a call costs no fetch until the kept ones expire.
func (c *RelyingPartyClient) resolve(ctx context.Context) (*provider, error) {
	if err := c.rp.admit(ctx, c.issuer); err != nil {
		return nil, err
	}
	resolved, err := c.rp.resolveProvider(ctx, c.issuer, false)
	if err != nil {
		return nil, err
	}
	c.current.Store(resolved)
	return resolved, nil
}

// AuthenticationURL pushes the authorization request (PAR) and gives the URL that carries its request_uri. The
// provider is judged anew first (see [RelyingPartyClient]). The login's values are checked before anything is sent to
// it: state and nonce, the code_verifier, scopes within the scope the relying
// party registered, which the IDP compares the request against, acr values, claims the IDP lists in its
// claims_supported if it lists any (gemSpec_IDP_Sek A_24403), and the redirect URI, byte for byte one the relying
// party's served statement registers (RFC 9700 section 4.1.3). The PAR response has to come with status 201 and be
// declared as JSON before it is read (RFC 9126 section 2.2).
func (c *RelyingPartyClient) AuthenticationURL(ctx context.Context, login openid.Login) (string, error) {
	form, err := openid.AuthorizationQuery(c.rp.ClientID(), c.redirectURI, c.scopes, login)
	if err != nil {
		return "", err
	}
	scopes := c.scopes
	if len(login.Scopes) > 0 {
		scopes = login.Scopes
	}
	current, err := c.resolve(ctx)
	if err != nil {
		return "", err
	}
	if err := checkLogin(login, scopes, c.rp.registered().scope, current.metadata.ClaimsSupported); err != nil {
		return "", err
	}
	if err := checkRedirectURI(login.RedirectFor(c.redirectURI), c.rp.registered().redirectURIs); err != nil {
		return "", err
	}
	if len(login.ACRValues) == 0 {
		form.Set("acr_values", LoAHigh)
	}

	response, err := openid.PostForm(ctx, c.rp.httpClient, current.metadata.PushedAuthorizationRequestEndpoint, form)
	if err != nil {
		return "", fmt.Errorf("unable to do PAR request: %w", err)
	}
	if response.Status != http.StatusCreated {
		return "", fmt.Errorf("PAR: %w", parseErrorResponse(response))
	}
	if err := response.CheckJSON(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrPARResponse, err)
	}
	pushed, err := parsePARResponse(response.Body)
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Add("request_uri", pushed.RequestURI)
	params.Add("client_id", c.rp.ClientID())
	return current.metadata.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// Exchange implements openid.Client with [RelyingPartyClient.ExchangeIdentity], dropping the identity.
func (c *RelyingPartyClient) Exchange(ctx context.Context, login openid.Login, code string) (*openid.TokenResponse, error) {
	_, response, err := c.ExchangeIdentity(ctx, login, code)
	return response, err
}

// Why an ID token is refused before its claims are read.
var (
	// ErrIDTokenVersion is an ID token whose version the relying party does not publish or the IDP does not list.
	ErrIDTokenVersion = errors.New("ID token version refused")
	// ErrIDTokenKey is an ID token signed under a kid the IDP's signed JWKS does not name, also after a refetch.
	ErrIDTokenKey = errors.New("ID token key unknown")
)

// ExchangeIdentity redeems the authorization code over mutual TLS and returns who logged in. The login has to be the
// one given to AuthenticationURL, with the same Scopes, ACRValues and Claims, which the host keeps in its login
// session: the acr is judged against ACRValues, and without Claims the essential claims cannot be checked. The ID
// token is
//   - decrypted through the ID token key (A_23194, A_23195), its JWE header naming a version both sides support;
//   - verified with the IDP's signed JWKS (A_23049);
//   - checked as OIDC Core 3.1.3.7 has it: issuer, audience, nonce of this login, lifetime (A_23049);
//   - judged by its acr and amr (A_28484) and auth_time, and required to hold the claims the login asked for as
//     essential (A_22860-02).
//
// The acr is taken when it is no lower than the lowest of the login's ACRValues, high when it names none. Asking for
// gematik-ehealth-loa-high and -substantial thus admits substantial with or without the person's consent to it for
// data of high protection need, which the host tells by the identity's Consent (ID token 2.0.0) or by amr
// urn:telematik:auth:mEW (1.0.0).
//
// An unknown kid, or a version the IDP's statement does not list, refetches the IDP's statement and signed JWKS past
// the store once (A_22861; A_23207 Hinweis 3): at most once a minute per IDP, with concurrent exchanges waiting for
// the refetch in flight, and from the store when the minute has not passed. A signature that does not verify under a
// known kid refetches nothing. A provider's refusal is returned as *Error.
//
// Before the token request leaves, the code is held to RFC 6749 Appendix A.11 and the redirect URI to the ones the
// served statement registers, as for the authorization request, and the provider is judged anew (see
// [RelyingPartyClient]). The response has to come with status 200, be declared
// as JSON and hold an ID token in compact JWE form before anything parses it.
func (c *RelyingPartyClient) ExchangeIdentity(ctx context.Context, login openid.Login, code string) (*Identity, *openid.TokenResponse, error) {
	if err := checkStateOrNonce(ErrNonce, login.Nonce); err != nil {
		return nil, nil, err
	}
	if err := checkVerifier(login.Verifier); err != nil {
		return nil, nil, err
	}
	if err := openid.CheckAuthorizationCode(code); err != nil {
		return nil, nil, err
	}
	redirectURI := login.RedirectFor(c.redirectURI)
	if err := checkRedirectURI(redirectURI, c.rp.registered().redirectURIs); err != nil {
		return nil, nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.rp.ClientID())
	form.Set("code_verifier", login.Verifier)

	current, err := c.resolve(ctx)
	if err != nil {
		return nil, nil, err
	}
	response, err := openid.PostForm(ctx, c.rp.httpClient, current.metadata.TokenEndpoint, form)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to do token request: %w", err)
	}
	if response.Status != http.StatusOK {
		return nil, nil, fmt.Errorf("token request: %w", parseErrorResponse(response))
	}
	if err := response.CheckJSON(); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", openid.ErrTokenResponse, err)
	}
	tokenResponse, err := openid.ParseTokenResponse(response.Body)
	if err != nil {
		return nil, nil, err
	}
	// The relying party registers an encrypted ID token (id_token_encrypted_response_alg), so only a JWE will do.
	if tokenResponse.IDTokenRaw == "" || strings.Count(tokenResponse.IDTokenRaw, ".") != 4 {
		return nil, nil, fmt.Errorf("%w: id_token is no compact JWE", openid.ErrTokenResponse)
	}

	signed, version, err := c.decryptIDToken(tokenResponse.IDTokenRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decrypt id_token: %w", err)
	}
	tokenResponse.IDTokenRaw = string(signed)

	refetched := false
	if current, err = c.checkVersion(ctx, current, version, &refetched); err != nil {
		return nil, nil, err
	}
	payload, err := c.verifyIDToken(ctx, current, signed, &refetched)
	if err != nil {
		return nil, nil, err
	}
	now := c.rp.now()
	checks := openid.IDTokenChecks{Issuer: c.issuer, ClientID: c.rp.ClientID(), Nonce: login.Nonce, Now: now, Skew: idTokenSkew}
	if err := checks.Validate(payload); err != nil {
		return nil, nil, fmt.Errorf("unable to parse token: %w", err)
	}
	identity, err := parseIdentity(payload, c.issuer, version)
	if err != nil {
		return nil, nil, err
	}
	if err := checkIdentity(identity, payload, login, c.rp.ClientID(), now); err != nil {
		return nil, nil, err
	}
	asked := c.scopes
	if len(login.Scopes) > 0 {
		asked = login.Scopes
	}
	identity.Scopes = grantedScopes(tokenResponse.Scope, asked)
	return identity, tokenResponse, nil
}

// decryptIDToken takes only what buildMetadata registers the relying party for: id_token_encrypted_response_alg
// ECDH-ES and id_token_encrypted_response_enc A256GCM. The content key is agreed through the ID token key's
// KeyAgreement, the key the header's kid names (A_23195). It returns the signed token and the version its protected
// header names.
func (c *RelyingPartyClient) decryptIDToken(raw string) ([]byte, string, error) {
	if err := openid.CheckProtectedHeader(raw); err != nil {
		return nil, "", err
	}
	encrypted, err := jose.ParseEncryptedCompact(raw, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		// go-jose's message quotes the header's alg and enc, which come from outside.
		return nil, "", fmt.Errorf("%w: no compact JWE of ECDH-ES and A256GCM", ErrIDTokenEncryption)
	}
	// go-jose reports every failure of the key as one cryptographic error, so the kid is checked here as well to say why.
	if kid := encrypted.Header.KeyID; kid != "" && kid != c.rp.keys.DecryptKID {
		return nil, "", fmt.Errorf("%w: kid names another key", ErrIDTokenEncryption)
	}
	version, err := idTokenVersion(encrypted.Header)
	if err != nil {
		return nil, "", err
	}
	signed, err := encrypted.Decrypt(opaqueDecrypter{agreement: c.rp.keys.Decrypt, kid: c.rp.keys.DecryptKID})
	return signed, version, err
}

// defaultIDTokenVersion is the version of an ID token whose header names none, and of a party that lists none
// (gemSpec_IDP_FD A_23207 Hinweis 1 and 2).
const defaultIDTokenVersion = "1.0.0"

// idTokenVersion reads the version member of the JWE protected header (gemSpec_IDP_Sek A_27713-01), one of the
// versions A_27505 allows.
func idTokenVersion(header jose.Header) (string, error) {
	value, present := header.ExtraHeaders["version"]
	if !present {
		return defaultIDTokenVersion, nil
	}
	version, ok := value.(string)
	if !ok || !slices.Contains(idTokenVersions, version) {
		return "", fmt.Errorf("%w: the header names no version of A_27505", ErrIDTokenVersion)
	}
	return version, nil
}

// supportedVersions are the versions a ti_features_supported member lists, the default when there is none.
func supportedVersions(features *TIFeatures) []string {
	if features == nil || len(features.IDTokenVersionSupported) == 0 {
		return []string{defaultIDTokenVersion}
	}
	return features.IDTokenVersionSupported
}

// checkVersion takes a version the relying party publishes, since the IDP picks the highest both support
// (gemSpec_IDP_Sek A_27598), and that the IDP's statement lists. A version the statement does not list may mean the
// statement kept is outdated (A_23207 Hinweis 3), so the statement is refetched once. It returns the provider as
// resolved after that.
func (c *RelyingPartyClient) checkVersion(ctx context.Context, current *provider, version string, refetched *bool) (*provider, error) {
	if !slices.Contains(c.rp.registered().idTokenVersions, version) {
		return nil, fmt.Errorf("%w: the relying party does not publish it", ErrIDTokenVersion)
	}
	if slices.Contains(supportedVersions(current.metadata.TIFeaturesSupported), version) {
		return current, nil
	}
	current, err := c.refetch(ctx, refetched)
	if err != nil {
		return nil, fmt.Errorf("%w: the IDP does not list it: %w", ErrIDTokenVersion, err)
	}
	if !slices.Contains(supportedVersions(current.metadata.TIFeaturesSupported), version) {
		return nil, fmt.Errorf("%w: the IDP does not list it", ErrIDTokenVersion)
	}
	return current, nil
}

// verifyIDToken verifies the signed ID token with the IDP's signed JWKS and returns its payload. Only ES256 is taken,
// the id_token_signed_response_alg the relying party registers. A kid the JWKS does not name refetches it once
// (A_22861).
func (c *RelyingPartyClient) verifyIDToken(ctx context.Context, current *provider, signed []byte, refetched *bool) ([]byte, error) {
	if err := openid.CheckProtectedHeader(string(signed)); err != nil {
		return nil, err
	}
	parsed, err := jose.ParseSignedCompact(string(signed), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, errors.New("unable to parse token: no compact JWS signed with ES256")
	}
	kid := parsed.Signatures[0].Protected.KeyID
	if kid != "" && len(current.jwks.Key(kid)) == 0 {
		if current, err = c.refetch(ctx, refetched); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrIDTokenKey, err)
		}
		if len(current.jwks.Key(kid)) == 0 {
			return nil, ErrIDTokenKey
		}
	}
	payload, err := openid.VerifyJWS(signed, current.jwks, memberKeys)
	if err != nil {
		return nil, fmt.Errorf("unable to parse token: %w", err)
	}
	return payload, nil
}

// refetch resolves the IDP's statement and signed JWKS anew, once per exchange, and makes the result the client's.
func (c *RelyingPartyClient) refetch(ctx context.Context, refetched *bool) (*provider, error) {
	if *refetched {
		return nil, errors.New("refetched already")
	}
	*refetched = true
	resolved, err := c.rp.refetchProvider(ctx, c.issuer)
	if err != nil {
		return nil, err
	}
	c.current.Store(resolved)
	return resolved, nil
}

// Issuer returns the provider's issuer, which its entity statement and its openid_provider metadata name.
func (c *RelyingPartyClient) Issuer() string {
	return c.issuer
}
