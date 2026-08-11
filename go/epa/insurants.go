package epa

import (
	"encoding/json"
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

type InsurantProviderStatus struct {
	Number           ProviderNumber                 `json:"number"`
	RecordFound      bool                           `json:"recordFound"`
	ConsentDecisions []ConsentDecisionsResponseType `json:"consentDecisions,omitempty"`
	Error            string                         `json:"error,omitempty"`
}

type InsurantRecordInfo struct {
	Found    bool           `json:"found"`
	Provider ProviderNumber `json:"provider,omitempty"`
}

type InsurantEntitlementInfo struct {
	Entitled   bool           `json:"entitled"`
	Provider   ProviderNumber `json:"provider,omitempty"`
	EntitledAt string         `json:"entitledAt,omitempty"`
	ValidTo    string         `json:"validTo,omitempty"`
}

type InsurantInfo struct {
	InsurantID  string                   `json:"insurantId"`
	Record      InsurantRecordInfo       `json:"record"`
	Providers   []InsurantProviderStatus `json:"providers"`
	Entitlement InsurantEntitlementInfo  `json:"entitlement"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("Failed to encode response", "error", err)
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

// HandleEntitleInsurant explicitly entitles this proxy's SMC-B identity for
// the insurant's record. The provider is auto-resolved unless the optional
// JSON body {"provider": n} forces one.
func (p *Proxy) HandleEntitleInsurant(w http.ResponseWriter, r *http.Request) {
	insurantID := r.PathValue("insurantID")
	if !kvnrRegexp.MatchString(insurantID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_kvnr", "KVNR must be an uppercase letter followed by 9 digits")
		return
	}

	var body struct {
		Provider ProviderNumber `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	var session *Session
	switch {
	case body.Provider != 0:
		if !slices.Contains(AllProviders, body.Provider) {
			writeJSONError(w, http.StatusBadRequest, "invalid_provider", fmt.Sprintf("unknown provider %d", body.Provider))
			return
		}
		var err error
		session, err = p.sessionManager.GetSession(body.Provider)
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
		slog.Error("Failed to entitle", "provider", session.ProviderNumber, "insurantID", insurantID, "error", err)
		writeJSONError(w, http.StatusBadGateway, "entitlement_failed", err.Error())
		return
	}

	rm := PatientRecordMetadata{
		InsurantID: insurantID,
		Provider:   session.ProviderNumber,
		EntitledAt: time.Now(),
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
