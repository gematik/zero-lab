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

package epa

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// GetRecordStatus reports whether this Aktensystem holds the insurant's record. It needs
// no VAU channel.
func (c *Client) GetRecordStatus(insurantID string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/information/api/v1/ehr", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("x-insurantid", insurantID)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}

	switch resp.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, parseHTTPError(resp)
	}
}

// GetConsentDecisionInformation returns the insurant's consent decisions at this
// Aktensystem. It needs no VAU channel.
func (c *Client) GetConsentDecisionInformation(insurantID string) (*GetConsentDecisionInformationType, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/information/api/v1/ehr/consentdecisions", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("x-insurantid", insurantID)

	slog.Info("Requesting consent decision information", "method", req.Method, "url", req.URL, "headers", req.Header)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseHTTPError(resp)
	}

	body := new(GetConsentDecisionInformationType)
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	return body, nil
}

// ConsentDecisionType is the insurant's decision on a function of the record.
type ConsentDecisionType string

// Decisions an Aktensystem reports.
const (
	ConsentDecisionPermit ConsentDecisionType = "permit"
	ConsentDecisionDeny   ConsentDecisionType = "deny"
)

// ConsentDecisionsResponseType is the decision on one function of the record.
type ConsentDecisionsResponseType struct {
	FunctionID string `json:"functionId"`
	Decision   string `json:"decision"`
}

// GetConsentDecisionInformationType is the answer of the consentdecisions endpoint.
type GetConsentDecisionInformationType struct {
	Data []ConsentDecisionsResponseType `json:"data"`
}
