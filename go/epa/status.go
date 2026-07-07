package epa

import (
	"net/http"
	"slices"
	"time"

	"github.com/gematik/zero-lab/go/epa/vau"
)

type ProviderVAUStatus struct {
	Number          ProviderNumber `json:"number"`
	BaseURL         string         `json:"baseURL,omitempty"`
	SessionOpenedAt string         `json:"sessionOpenedAt,omitempty"`
	// VAU carries the spec-named keys from GET /VAU-Status:
	// VAU-Type, VAU-Version, User-Authentication, KeyID, Connection-Start.
	VAU   *vau.Status `json:"vau,omitempty"`
	Error string      `json:"error,omitempty"`
}

type ProxyStatus struct {
	Name            string              `json:"name"`
	Env             Env                 `json:"env"`
	Subject         string              `json:"subject,omitempty"`
	TelematikID     string              `json:"telematikId,omitempty"`
	IdentityError   string              `json:"identityError,omitempty"`
	InsurantsCached int                 `json:"insurantsCached"`
	Providers       []ProviderVAUStatus `json:"providers"`
}

// HandleProxyStatus aggregates GET /VAU-Status of all providers with the
// local session state. Provider failures are reported as data, not as an
// HTTP error — a status endpoint must answer even when providers are down.
func (p *Proxy) HandleProxyStatus(w http.ResponseWriter, r *http.Request) {
	results := make(chan ProviderVAUStatus, len(AllProviders))

	for _, provider := range AllProviders {
		go func(provider ProviderNumber) {
			status := ProviderVAUStatus{Number: provider}
			defer func() { results <- status }()

			session, err := p.sessionManager.GetSession(provider)
			if err != nil {
				status.Error = err.Error()
				return
			}
			status.BaseURL = session.BaseURL
			status.SessionOpenedAt = session.OpenedAt.Format(time.RFC3339)

			vauStatus, err := session.GetStatus()
			if err != nil {
				status.Error = err.Error()
				return
			}
			status.VAU = vauStatus
		}(provider)
	}

	proxyStatus := ProxyStatus{
		Name:      p.config.Name,
		Env:       p.Env,
		Providers: make([]ProviderVAUStatus, 0, len(AllProviders)),
	}
	for range AllProviders {
		proxyStatus.Providers = append(proxyStatus.Providers, <-results)
	}
	slices.SortFunc(proxyStatus.Providers, func(a, b ProviderVAUStatus) int {
		return int(a.Number) - int(b.Number)
	})

	if info, err := p.GetProxyInfo(); err != nil {
		proxyStatus.IdentityError = err.Error()
	} else {
		proxyStatus.Subject = info.Subject
		if info.AdmissionStatement != nil {
			proxyStatus.TelematikID = info.AdmissionStatement.RegistrationNumber
		}
	}

	p.recordsLock.RLock()
	proxyStatus.InsurantsCached = len(p.records)
	p.recordsLock.RUnlock()

	writeJSON(w, http.StatusOK, &proxyStatus)
}
