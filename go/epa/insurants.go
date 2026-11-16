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
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"time"
)

var kvnrRegexp = regexp.MustCompile(`^[A-Z]\d{9}$`)

// InsurantProviderStatus is what one provider knows about an insurant; a provider that
// could not be asked fills only Error.
type InsurantProviderStatus struct {
	Number           ProviderNumber                 `json:"number"`
	RecordFound      bool                           `json:"recordFound"`
	ConsentDecisions []ConsentDecisionsResponseType `json:"consentDecisions,omitempty"`
	Error            string                         `json:"error,omitempty"`
}

// InsurantRecordInfo says which provider, if any, holds the insurant's record.
type InsurantRecordInfo struct {
	Found    bool           `json:"found"`
	Provider ProviderNumber `json:"provider,omitzero"`
}

// InsurantEntitlementInfo is the proxy's cached entitlement for an insurant; the times are RFC 3339.
type InsurantEntitlementInfo struct {
	Entitled   bool           `json:"entitled"`
	Provider   ProviderNumber `json:"provider,omitzero"`
	EntitledAt string         `json:"entitledAt,omitempty"`
	ValidTo    string         `json:"validTo,omitempty"`
}

// InsurantInfo is the answer of GET /insurants/{insurantID}.
type InsurantInfo struct {
	InsurantID  string                   `json:"insurantId"`
	Record      InsurantRecordInfo       `json:"record"`
	Providers   []InsurantProviderStatus `json:"providers"`
	Entitlement InsurantEntitlementInfo  `json:"entitlement"`
}

// responseJSON writes the proxy's answers as they always were: a nil slice or map as null rather than [] and {}, a
// map's members sorted by name, and invalid UTF-8 replaced by U+FFFD, since an answer can carry an Aktensystem's
// error text and must not fail to encode for it.
var responseJSON = json.JoinOptions(json.Deterministic(true), json.FormatNilSliceAsNull(true), json.FormatNilMapAsNull(true),
	jsontext.AllowInvalidUTF8(true))

// writeJSON encodes body before it sends status, so a body that cannot be encoded becomes a 500 instead of status with
// half a body. The newline ends the answer as it always has.
func writeJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.Marshal(body, responseJSON)
	if err != nil {
		slog.Error("Failed to encode response", "error", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(append(data, '\n')); err != nil {
		slog.Error("Failed to write response", "error", err)
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// HandleInsurantInfo reports where the record of an insurant lives and which
// consent decisions apply there. Read-only: unlike the /vau/ forwarding path
// it never creates an entitlement.
func (p *Proxy) HandleInsurantInfo(w http.ResponseWriter, r *http.Request) {
	insurantID := r.PathValue("insurantID")
	if !kvnrRegexp.MatchString(insurantID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_kvnr", "KVNR must be an uppercase letter followed by 9 digits")
		return
	}

	type result struct {
		status InsurantProviderStatus
	}
	results := make(chan result, len(AllProviders))

	for _, provider := range AllProviders {
		go func(provider ProviderNumber) {
			status := InsurantProviderStatus{Number: provider}
			defer func() { results <- result{status: status} }()

			session, err := p.sessionManager.GetSession(provider)
			if err != nil {
				status.Error = err.Error()
				return
			}
			found, err := session.GetRecordStatus(insurantID)
			if err != nil {
				status.Error = err.Error()
				return
			}
			status.RecordFound = found
			if !found {
				return
			}
			consent, err := session.GetConsentDecisionInformation(insurantID)
			if err != nil {
				status.Error = fmt.Sprintf("consent decisions: %v", err)
				return
			}
			status.ConsentDecisions = consent.Data
		}(provider)
	}

	info := InsurantInfo{
		InsurantID: insurantID,
		Providers:  make([]InsurantProviderStatus, 0, len(AllProviders)),
	}
	errorCount := 0
	for range AllProviders {
		r := <-results
		info.Providers = append(info.Providers, r.status)
		if r.status.Error != "" && !r.status.RecordFound {
			errorCount++
		}
		if r.status.RecordFound && !info.Record.Found {
			info.Record = InsurantRecordInfo{Found: true, Provider: r.status.Number}
		}
	}
	slices.SortFunc(info.Providers, func(a, b InsurantProviderStatus) int {
		return int(a.Number) - int(b.Number)
	})

	if errorCount == len(AllProviders) {
		multiErr := &MultiProviderError{Errors: make([]ProvidersError, 0, len(AllProviders))}
		for _, s := range info.Providers {
			multiErr.Errors = append(multiErr.Errors, ProvidersError{
				Code:           "provider_error",
				Description:    s.Error,
				ProviderNumber: s.Number,
			})
		}
		writeJSON(w, http.StatusBadGateway, multiErr)
		return
	}

	p.recordsLock.RLock()
	rm, entitled := p.records[insurantID]
	p.recordsLock.RUnlock()
	if entitled {
		info.Entitlement = InsurantEntitlementInfo{
			Entitled: !rm.EntitledAt.IsZero(),
			Provider: rm.Provider,
		}
		if !rm.EntitledAt.IsZero() {
			info.Entitlement.EntitledAt = rm.EntitledAt.Format(time.RFC3339)
		}
		if !rm.ValidTo.IsZero() {
			info.Entitlement.ValidTo = rm.ValidTo.Format(time.RFC3339)
		}
	}

	writeJSON(w, http.StatusOK, &info)
}

// maxEntitleBodyBytes bounds the optional body of an entitle request, which names one provider.
const maxEntitleBodyBytes = 256

// errEntitleBody is an entitle request's body refused.
var errEntitleBody = errors.New("entitle body refused")

// errEntitleBodyTooLarge is an entitle request's body refused for its size.
var errEntitleBodyTooLarge = fmt.Errorf("%w: larger than %d bytes", errEntitleBody, maxEntitleBodyBytes)

// entitleProvider reads the optional body {"provider": n} of an entitle request; an empty body names none. The format
// is the proxy's own, so a member it does not know is refused, as are a member named twice and invalid UTF-8.
func entitleProvider(body io.Reader) (ProviderNumber, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxEntitleBodyBytes+1))
	if err != nil {
		return 0, fmt.Errorf("%w: unreadable", errEntitleBody)
	}
	if len(data) > maxEntitleBodyBytes {
		return 0, errEntitleBodyTooLarge
	}
	if len(bytes.Trim(data, " \t\r\n")) == 0 {
		return 0, nil
	}
	var request struct {
		Provider ProviderNumber `json:"provider"`
	}
	if err := json.Unmarshal(data, &request, json.RejectUnknownMembers(true)); err != nil {
		return 0, fmt.Errorf("%w: %w", errEntitleBody, &decodeError{what: "JSON", err: err})
	}
	return request.Provider, nil
}

// HandleEntitleInsurant explicitly entitles this proxy's SMC-B identity for
// the insurant's record. The provider is auto-resolved unless the optional
// JSON body {"provider": n} forces one.
func (p *Proxy) HandleEntitleInsurant(w http.ResponseWriter, r *http.Request) {
	insurantID := r.PathValue("insurantID")
	if !kvnrRegexp.MatchString(insurantID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_kvnr", "KVNR must be an uppercase letter followed by 9 digits")
		return
	}

	provider, err := entitleProvider(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", `the body is empty or {"provider": n}`)
		return
	}

	var session *Session
	switch {
	case provider != 0:
		if !slices.Contains(AllProviders, provider) {
			writeJSONError(w, http.StatusBadRequest, "invalid_provider", fmt.Sprintf("unknown provider %d", provider))
			return
		}
		session, err = p.sessionManager.GetSession(provider)
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, "provider_error", err.Error())
			return
		}
	default:
		var multiErr *MultiProviderError
		session, multiErr = p.findRecordProvider(insurantID)
		if multiErr != nil {
			writeJSON(w, http.StatusBadGateway, multiErr)
			return
		}
	}

	validTo, err := p.entitle(session, insurantID)
	if err != nil {
		slog.Error("Failed to entitle", "provider", session.ProviderNumber, "error", err)
		writeJSONError(w, http.StatusBadGateway, "entitlement_failed", err.Error())
		return
	}

	rm := PatientRecordMetadata{
		InsurantID: insurantID,
		Provider:   session.ProviderNumber,
		EntitledAt: p.now(),
		ValidTo:    validTo,
	}
	p.recordsLock.Lock()
	p.records[insurantID] = rm
	p.recordsLock.Unlock()

	response := map[string]any{
		"insurantId": insurantID,
		"provider":   rm.Provider,
		"entitledAt": rm.EntitledAt.Format(time.RFC3339),
	}
	if !rm.ValidTo.IsZero() {
		response["validTo"] = rm.ValidTo.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusCreated, response)
}
