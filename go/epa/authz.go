package epa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
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
	slog.Debug("SendAuthCodeSC", "host_url", s.BaseURL)
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

// identity is the session's signing identity, or an error naming what is missing.
func (s *Session) identity() (Identity, error) {
	if s.securityFunctions == nil || s.securityFunctions.Identity == nil {
		return nil, fmt.Errorf("no SMC-B authn identity configured")
	}
	return s.securityFunctions.Identity, nil
}

// CreateClientAttest signs the VAU's nonce with the SMC-B: `alg ES256`, `x5c` the AUT
// certificate, 20 minutes of validity.
func (s *Session) CreateClientAttest() (string, error) {
	nonce, err := s.GetNonce()
	if err != nil {
		return "", fmt.Errorf("GetNonce: %w", err)
	}
	identity, err := s.identity()
	if err != nil {
		return "", err
	}
	now := time.Now()
	jws, err := identity.SignJWT(context.Background(),
		map[string]any{"typ": "JWT"},
		map[string]any{
			"nonce": nonce,
			"iat":   now.Unix(),
			"exp":   now.Add(20 * time.Minute).Unix(),
		})
	if err != nil {
		return "", fmt.Errorf("signing client attest: %w", err)
	}
	return jws, nil
}

// Authorize runs the authorization: client attest, the Aktensystem's authorization
// request, the IDP-Dienst through authenticator, and the code back to the Aktensystem.
func (s *Session) Authorize(authenticator Authenticator) error {
	clientAttest, err := s.CreateClientAttest()
	if err != nil {
		return fmt.Errorf("creating client attest: %w", err)
	}

	authz_uri, err := s.SendAuthorizationRequestSC()
	if err != nil {
		return fmt.Errorf("sending authorization request: %w", err)
	}

	slog.Debug("Authorize", "authz_uri", authz_uri)

	codeRedirectURL, err := authenticator.Authenticate(context.Background(), authz_uri)
	if err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}

	slog.Debug("Authorize", "code_redirect_url", codeRedirectURL.URL)

	err = s.SendAuthCodeSC(SendAuthCodeSCtype{
		AuthorizationCode: codeRedirectURL.Code,
		ClientAttest:      clientAttest,
	})

	if err != nil {
		return fmt.Errorf("sending auth code: %w", err)
	}

	return nil
}
