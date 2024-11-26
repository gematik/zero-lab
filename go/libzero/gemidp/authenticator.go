package gemidp

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gematik/zero-lab/go/brainpool"
)

type ChallengeSignerFunc func(challenge Challenge) (string, error)

func SignWith(signFunc brainpool.SignFunc, certFunc func() (*x509.Certificate, error)) ChallengeSignerFunc {
	return func(challenge Challenge) (string, error) {
		cert, err := certFunc()
		if err != nil {
			return "", fmt.Errorf("getting certificate: %w", err)
		}
		challengeResponse, err := brainpool.NewJWTBuilder().
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

func SignWithSoftkeyPEM(prkPEM []byte, certPEM []byte) ChallengeSignerFunc {
	var err error
	var prk *ecdsa.PrivateKey
	var cert *x509.Certificate

	if prk, err = brainpool.ParsePrivateKeyPEM(prkPEM); err != nil {
		slog.Error("Parsing private key PEM", "error", err)
	}

	if cert, err = brainpool.ParseCertificatePEM(certPEM); err != nil {
		slog.Error("Parsing certificate PEM", "error", err)
	}

	return func(challenge Challenge) (string, error) {
		if err != nil {
			return "", fmt.Errorf("parsing PEM: %w", err)
		}
		return SignWithSoftkey(prk, cert)(challenge)
	}
}

func SignWithSoftkey(prk *ecdsa.PrivateKey, cert *x509.Certificate) ChallengeSignerFunc {
	return SignWith(
		brainpool.SignFuncPrivateKey(prk),
		func() (*x509.Certificate, error) {
			return cert, nil
		},
	)
}

// Challenge sent from the gematik IDP-Dienst to the authenticator
type Challenge struct {
	Challenge   string      `json:"challenge"`
	UserConsent UserConsent `json:"user_consent"`
}

// User consent of the challenge sent from the gematik IDP-Dienst to the authenticator
type UserConsent struct {
	RequestedScopes map[string]string `json:"requested_scopes"`
	RequestedClaims map[string]string `json:"requested_claims"`
}

// Nested JWT claims used during the challenge response flow
type Njwt struct {
	Njwt string `json:"njwt"`
}

// Payload of the signed challenge token sent from the gematik IDP-Dienst to the authenticator
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

type Authenticator struct {
	Environment Environment
	Metadata    Metadata
	baseURL     string
	signerFunc  ChallengeSignerFunc
}

type AuthenticatorConfig struct {
	Environment Environment
	SignerFunc  ChallengeSignerFunc
}

// NewAuthenticator creates a new Authenticator
func NewAuthenticator(config AuthenticatorConfig) (*Authenticator, error) {
	baseURL := config.Environment.GetBaseURL()
	metadata, err := fetchMetadata(baseURL, http.DefaultClient)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		Environment: config.Environment,
		Metadata:    *metadata,
		baseURL:     baseURL,
		signerFunc:  config.SignerFunc,
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
	idpEncKey, err := fetchKey(a.Metadata.EncryptionKeyURI)
	if err != nil {
		return nil, fmt.Errorf("fetching challenge encryption key: %w", err)
	}
	idpSigKey, err := fetchKey(a.Metadata.SigningKeyURI)
	if err != nil {
		return nil, fmt.Errorf("fetching challenge signing key: %w", err)
	}
	slog.Warn("Using signing and encryption keys with unverified certificates")

	// create http client which prevents redirects
	httpClient := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := httpClient.Get(authURL)
	if err != nil {
		return nil, fmt.Errorf("unable to get auth URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp.StatusCode, resp.Body)
	}

	var challenge = new(Challenge)
	err = json.NewDecoder(resp.Body).Decode(challenge)
	if err != nil {
		return nil, fmt.Errorf("decoding challenge: %w", err)
	}

	slog.Debug("Challenge", "challenge", challenge)

	token, err := brainpool.ParseToken([]byte(challenge.Challenge), brainpool.WithKey(idpSigKey))
	if err != nil {
		return nil, fmt.Errorf("parsing challenge: %w", err)
	}

	var challengePayload = new(ChallengePayload)
	err = json.Unmarshal(token.PayloadJson, challengePayload)
	if err != nil {
		return nil, fmt.Errorf("parsing challenge payload: %w", err)
	}

	signedChallenge, err := a.signerFunc(*challenge)
	if err != nil {
		return nil, fmt.Errorf("signing challenge: %w", err)
	}

	challengeResponseClaims := Njwt{
		Njwt: signedChallenge,
	}

	challengeResponseClaimsJson, err := json.Marshal(challengeResponseClaims)
	if err != nil {
		return nil, fmt.Errorf("marshalling challenge response claims: %w", err)
	}

	slog.Info("Challenge response claims", "claims", string(challengeResponseClaimsJson))

	challengeResponseEncrypted, err := brainpool.NewJWEBuilder().
		Header("cty", "NJWT").
		Header("exp", challengePayload.Exp).
		Plaintext([]byte(challengeResponseClaimsJson)).
		EncryptECDHES(idpEncKey.Key.(*ecdsa.PublicKey))

	if err != nil {
		return nil, fmt.Errorf("encrypting challenge response: %w", err)
	}

	slog.Info("Encrypted challenge response", "encrypted", string(challengeResponseEncrypted))

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
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, body)
	}

	codeRedirectURL, err := resp.Location()
	if err != nil {
		return nil, fmt.Errorf("getting code redirect URL: %w", err)
	}

	return &CodeRedirectURL{
		URL:   codeRedirectURL,
		Code:  codeRedirectURL.Query().Get("code"),
		State: codeRedirectURL.Query().Get("state"),
	}, nil
}
