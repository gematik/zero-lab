package epa

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gemidp"
)

type Nonce struct {
	Nonce string `json:"nonce"`
}

func (c *Session) GetNonce() (string, error) {
	req, err := http.NewRequest("GET", "/epa/authz/v1/getNonce", nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-useragent", UserAgent)

	resp, err := c.VAUChannel.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", parseHttpError(resp)
	}

	nonce := new(Nonce)
	if err := json.NewDecoder(resp.Body).Decode(nonce); err != nil {
		return "", fmt.Errorf("unmarshaling response: %w", err)
	}

	return nonce.Nonce, nil
}

func (s *Session) SendAuthorizationRequestSC() (string, error) {
	req, err := http.NewRequest("GET", "/epa/authz/v1/send_authorization_request_sc", nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-useragent", UserAgent)

	resp, err := s.VAUChannel.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}

	if resp.StatusCode != http.StatusFound {
		return "", parseHttpError(resp)
	}

	return resp.Header.Get("Location"), nil
}

func (s *Session) SendAuthCodeSC(authCode SendAuthCodeSCtype) error {
	body, err := json.Marshal(authCode)
	if err != nil {
		return fmt.Errorf("marshaling body: %w", err)
	}
	slog.Debug("SendAuthCodeSC", "body", string(body))
	req, err := http.NewRequest("POST", "/epa/authz/v1/send_authcode_sc", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	req.Header.Set("x-useragent", UserAgent)

	resp, err := s.VAUChannel.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseHttpError(resp)
	}

	return nil
}

type SendAuthCodeSCtype struct {
	AuthorizationCode string `json:"authorizationCode"`
	ClientAttest      string `json:"clientAttest"`
}

func (s *Session) CreateClientAttest() (string, error) {
	nonce, err := s.GetNonce()
	if err != nil {
		return "", fmt.Errorf("GetNonce: %w", err)
	}

	cert, err := s.securityFunctions.ClientAssertionCertFunc()
	if err != nil {
		return "", fmt.Errorf("ClientAssertionCertFunc: %w", err)
	}

	tk, err := brainpool.NewJWTBuilder().
		Header("typ", "JWT").
		Header("alg", brainpool.AlgorithmNameES256).
		Header("x5c", []string{base64.StdEncoding.EncodeToString(cert.Raw)}).
		Claim("nonce", nonce).
		Claim("iat", time.Now().Unix()).
		Claim("exp", time.Now().Add(20*time.Minute).Unix()).
		Sign(sha256.New(), s.securityFunctions.ClientAssertionSignFunc)

	if err != nil {
		return "", fmt.Errorf("Sign: %w", err)
	}

	return string(tk), nil
}

func (s *Session) Authorize(authenticator *gemidp.Authenticator) error {
	clientAttest, err := s.CreateClientAttest()
	if err != nil {
		return fmt.Errorf("creating client attest: %w", err)
	}

	authz_uri, err := s.SendAuthorizationRequestSC()
	if err != nil {
		return fmt.Errorf("sending authorization request: %w", err)
	}

	slog.Debug("Authorize", "authz_uri", authz_uri)

	codeRedirectURL, err := authenticator.Authenticate(authz_uri)
	if err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}

	slog.Debug("Authorize", "codeRedirectURL", codeRedirectURL)

	err = s.SendAuthCodeSC(SendAuthCodeSCtype{
		AuthorizationCode: codeRedirectURL.Code,
		ClientAttest:      clientAttest,
	})

	if err != nil {
		return fmt.Errorf("sending auth code: %w", err)
	}

	return nil
}
