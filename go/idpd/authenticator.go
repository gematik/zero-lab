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

package idpd

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/gematik/zero-lab/go/openid"
)

// challengeSkew is the clock skew tolerated on a challenge's time claims, as in ti-idpd's profile.
const challengeSkew = time.Minute

// ChallengeSignerFunc signs an IDP-Dienst challenge and returns the compact JWS that nests it. Being a
// function, it lets the key stay in hardware.
type ChallengeSignerFunc func(challenge Challenge) (string, error)

// Challenge sent from the gematik IDP-Dienst to the authenticator
type Challenge struct {
	Challenge   string      `json:"challenge"`
	UserConsent UserConsent `json:"user_consent"`
}

// UserConsent is the consent part of the challenge sent from the gematik IDP-Dienst to the authenticator.
type UserConsent struct {
	RequestedScopes map[string]string `json:"requested_scopes"`
	RequestedClaims map[string]string `json:"requested_claims"`
}

// Njwt holds the nested JWT claim of the challenge response.
type Njwt struct {
	Njwt string `json:"njwt"`
}

// ChallengePayload is the payload of the signed challenge token sent from the gematik IDP-Dienst to the
// authenticator.
type ChallengePayload struct {
	Iss                 string `json:"iss"`
	Iat                 int64  `json:"iat"`
	Exp                 int64  `json:"exp"`
	TokenType           string `json:"token_type"`
	Jti                 string `json:"jti"`
	Snc                 string `json:"snc"`
	Scope               string `json:"scope"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ResponseType        string `json:"response_type"`
	RedirectURI         string `json:"redirect_uri"`
	ClientID            string `json:"client_id"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
}

// Authenticator answers the IDP-Dienst's challenge on behalf of a user, as the gematik Authenticator app
// does, signing with the configured ChallengeSignerFunc.
type Authenticator struct {
	Environment Environment
	Metadata    Metadata
	baseURL     string
	signerFunc  ChallengeSignerFunc
	httpClient  *http.Client
	trust       CertificateTrust
}

// AuthenticatorConfig selects the IDP-Dienst instance and the signer of an Authenticator.
type AuthenticatorConfig struct {
	IDP        IDP
	SignerFunc ChallengeSignerFunc
	// Trust decides about the IDP-Dienst's certificates; required (IDPV-003).
	Trust CertificateTrust

	// HTTPClient is used for metadata and key fetches; a redirect-suppressing copy of it drives the
	// challenge flow. When nil, a client with a default timeout is created.
	HTTPClient *http.Client
}

// NewAuthenticator creates a new Authenticator
func NewAuthenticator(config AuthenticatorConfig) (*Authenticator, error) {
	if config.Trust == nil {
		return nil, errors.New("no trust for the IDP-Dienst's certificates")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	baseURL := config.IDP.baseURL
	metadata, err := fetchMetadata(baseURL, httpClient, config.Trust)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		Environment: config.IDP.environment,
		Metadata:    *metadata,
		baseURL:     baseURL,
		signerFunc:  config.SignerFunc,
		httpClient:  httpClient,
		trust:       config.Trust,
	}, nil
}

// CodeRedirectURL is the URL to which the user is redirected after authenticating
type CodeRedirectURL struct {
	*url.URL
	Code  string
	State string
}

// Authenticate authenticates the user with the gematik IDP-Dienst
// and returns the URL to which the user is redirected after authenticating.
// The challenge from the gematik IDP-Dienst is signed using the
// signer function in the AuthenticatorConfig.
func (a *Authenticator) Authenticate(authURL string) (*CodeRedirectURL, error) {
	// fetch fresh keys
	// encrypt the signed challenge response for the idp
	idpEncKey, err := fetchEncryptionKey(context.Background(), a.Metadata.EncryptionKeyURI, a.httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetching challenge encryption key: %w", err)
	}
	idpSigKey, err := fetchSigningKey(context.Background(), a.Metadata.SigningKeyURI, a.httpClient, a.trust)
	if err != nil {
		return nil, fmt.Errorf("fetching challenge signing key: %w", err)
	}

	// derive a redirect-suppressing client from the injected one (the challenge flow inspects the
	// 302 Location itself), without mutating the caller's client
	noFollow := *a.httpClient
	noFollow.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	httpClient := &noFollow

	resp, err := httpClient.Get(authURL)
	if err != nil {
		return nil, fmt.Errorf("unable to get auth URL: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusFound:
		location, err := resp.Location()
		if err != nil {
			return nil, fmt.Errorf("IDP responded with unexpected redirect: %w", err)
		}
		if refusal := refusalOf(location); refusal != nil {
			return nil, refusal
		}
		return nil, errors.New("IDP responded with a redirect instead of a challenge")
	default:
		return nil, parseErrorResponse(resp.StatusCode, resp.Body)
	}

	challenge := new(Challenge)
	err = json.NewDecoder(io.LimitReader(resp.Body, maxIDPResponseBytes)).Decode(challenge)
	if err != nil {
		return nil, fmt.Errorf("decoding challenge: %w", err)
	}

	token, err := josebp.ParseToken([]byte(challenge.Challenge), josebp.WithKey(idpSigKey))
	if err != nil {
		return nil, fmt.Errorf("parsing challenge NJWT: %w", err)
	}

	// What gets the card holder's signature is judged first, as ti-idpd does: BP256R1 alone, while josebp would take any
	// algorithm of the key's size, and within its lifetime. An exp is required, and the response's JWE repeats it.
	if alg := token.Headers["alg"]; alg != josebp.AlgorithmNameBP256R1 {
		return nil, fmt.Errorf("challenge signed with alg %v, expected %s", alg, josebp.AlgorithmNameBP256R1)
	}
	challengePayload := new(ChallengePayload)
	err = json.Unmarshal(token.PayloadJSON, challengePayload)
	if err != nil {
		return nil, fmt.Errorf("parsing challenge payload: %w", err)
	}
	if challengePayload.Exp == 0 {
		return nil, errors.New("challenge without exp")
	}
	if err := openid.ValidateLifetime(token.PayloadJSON, time.Now(), challengeSkew); err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}

	signedChallenge, err := a.signerFunc(*challenge)
	if err != nil {
		return nil, fmt.Errorf("signing challenge: %w", err)
	}

	challengeResponseClaims := Njwt{
		Njwt: signedChallenge,
	}

	challengeResponseClaimsJSON, err := json.Marshal(challengeResponseClaims)
	if err != nil {
		return nil, fmt.Errorf("marshalling challenge response claims: %w", err)
	}

	challengeResponseEncrypted, err := josebp.NewJWEBuilder().
		Header("cty", "NJWT").
		Header("exp", challengePayload.Exp).
		Plaintext([]byte(challengeResponseClaimsJSON)).
		EncryptECDHES(idpEncKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting challenge response: %w", err)
	}

	// post the encrypted challenge response to the idp
	form := url.Values{
		"signed_challenge": {string(challengeResponseEncrypted)},
	}

	resp, err = httpClient.PostForm(a.Metadata.AuthorizationEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("unable to post challenge response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return nil, parseErrorResponse(resp.StatusCode, resp.Body)
	}

	codeRedirectURL, err := resp.Location()
	if err != nil {
		return nil, fmt.Errorf("getting code redirect URL: %w", err)
	}
	if refusal := refusalOf(codeRedirectURL); refusal != nil {
		return nil, refusal
	}
	code := codeRedirectURL.Query().Get("code")
	if code == "" {
		return nil, errors.New("code redirect without a code")
	}

	return &CodeRedirectURL{
		URL:   codeRedirectURL,
		Code:  code,
		State: codeRedirectURL.Query().Get("state"),
	}, nil
}

// refusalOf is the IDP's error in a redirect's query, nil if there is none. An error goes before a code that came with
// it, as in ti-idpd.
func refusalOf(location *url.URL) *Error {
	query := location.Query()
	if query.Get("error") == "" {
		return nil
	}
	// The timestamp is informational, and a refusal stays one without it.
	timestamp, _ := strconv.ParseInt(query.Get("gematik_timestamp"), 10, 64)
	return &Error{
		ErrorCode:        query.Get("error"),
		GematikErrorText: query.Get("gematik_error_text"),
		GematikTimestamp: timestamp,
		GematikCode:      query.Get("gematik_code"),
		GematikUUID:      query.Get("gematik_uuid"),
	}
}

// SignWith returns a signer that signs the challenge as a BP256R1 JWS with signFunc and carries the
// certificate from certFunc in x5c. certFunc runs on every signature.
func SignWith(signFunc brainpool.SignFunc, certFunc func() (*x509.Certificate, error)) ChallengeSignerFunc {
	return func(challenge Challenge) (string, error) {
		cert, err := certFunc()
		if err != nil {
			return "", fmt.Errorf("getting certificate: %w", err)
		}
		challengeResponse, err := josebp.NewJWTBuilder().
			Header("typ", "JWT").
			Header("cty", "NJWT").
			Header("alg", "BP256R1").
			Header("x5c", []string{base64.StdEncoding.EncodeToString(cert.Raw)}).
			Claim("njwt", challenge.Challenge).
			Sign(sha256.New(), signFunc)
		if err != nil {
			return "", fmt.Errorf("signing challenge: %w", err)
		}

		return string(challengeResponse), nil
	}
}

// SignWithSoftkeyPEM is SignWithSoftkey for a PEM-encoded Brainpool key and certificate. A parsing error
// is logged here and returned by the signer on use.
func SignWithSoftkeyPEM(prkPEM []byte, certPEM []byte) ChallengeSignerFunc {
	var parsingErr error
	var err error
	var prk *ecdsa.PrivateKey
	var cert *x509.Certificate

	if prk, err = brainpool.ParsePrivateKeyPEM(prkPEM); err != nil {
		slog.Error("Parsing private key PEM", "error", err)
		parsingErr = err
	}

	if cert, err = brainpool.ParseCertificatePEM(certPEM); err != nil {
		slog.Error("Parsing certificate PEM", "error", err)
		parsingErr = err
	}

	return func(challenge Challenge) (string, error) {
		if parsingErr != nil {
			return "", fmt.Errorf("parsing PEM: %w", parsingErr)
		}
		return SignWithSoftkey(prk, cert)(challenge)
	}
}

// SignWithSoftkey returns a signer for a Brainpool key held in memory.
func SignWithSoftkey(prk *ecdsa.PrivateKey, cert *x509.Certificate) ChallengeSignerFunc {
	return SignWith(
		brainpool.SignFuncPrivateKey(prk),
		func() (*x509.Certificate, error) {
			return cert, nil
		},
	)
}
