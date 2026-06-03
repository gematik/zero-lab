package epa

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

func (c *Client) GetRecordStatus(insurantId string) (bool, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/information/api/v1/ehr", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("x-insurantid", insurantId)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusNoContent {
		return true, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else {
		return false, parseHttpError(resp)
	}
}

func (c *Client) GetConsentDecisionInformation(insurantId string) (*GetConsentDecisionInformationType, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/information/api/v1/ehr/consentdecisions", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("x-insurantid", insurantId)

	slog.Info("Requesting consent decision information", "method", req.Method, "url", req.URL, "headers", req.Header)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseHttpError(resp)
	}

	body := new(GetConsentDecisionInformationType)
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	return body, nil
}

type ConsentDecisionType string

const (
	ConsentDecisionPermit ConsentDecisionType = "permit"
	ConsentDecisionDeny   ConsentDecisionType = "deny"
)

type ConsentDecisionsResponseType struct {
	FunctionId string `json:"functionId"`
	Decision   string `json:"decision"`
}

type GetConsentDecisionInformationType struct {
	Data []ConsentDecisionsResponseType `json:"data"`
}
