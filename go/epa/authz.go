package epa

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (c *Client) GetNonce() (string, error) {
	req, err := http.NewRequest("GET", "/epa/authz/v1/getNonce", nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-useragent", UserAgent)

	resp, err := c.channel.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Unexpected response status %v", resp.StatusCode)
	}

	nonce := new(Nonce)
	if err := json.NewDecoder(resp.Body).Decode(nonce); err != nil {
		return "", fmt.Errorf("unmarshaling response: %w", err)
	}

	return nonce.Nonce, nil
}

func (c *Client) SendAuthorizationRequestSC() (string, error) {
	req, err := http.NewRequest("GET", "/epa/authz/v1/send_authorization_request_sc", nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-useragent", UserAgent)

	resp, err := c.channel.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}

	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("Unexpected response status %v", resp.StatusCode)
	}

	return resp.Header.Get("Location"), nil
}
