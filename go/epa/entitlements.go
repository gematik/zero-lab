package epa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type EntitlementRequestType struct {
	JWT string `json:"jwt"`
}

func (s *Session) SetEntitlementPs(insurantId string, entitlement EntitlementRequestType) error {

	body, err := json.Marshal(entitlement)
	if err != nil {
		return fmt.Errorf("marshaling body: %w", err)
	}

	req, err := http.NewRequest("POST", s.baseURL+"/epa/basic/api/v1/ps/entitlements", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-insurantid", insurantId)
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	resp, err := s.channel.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return parseHttpError(resp)
	}

	return nil
}
