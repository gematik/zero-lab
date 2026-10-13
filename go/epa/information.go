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
