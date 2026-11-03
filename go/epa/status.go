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
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/epa/vau"
)

// ProviderVAUStatus is one provider's session and VAU state; a provider that failed fills Error.
type ProviderVAUStatus struct {
	Number          ProviderNumber `json:"number"`
	BaseURL         string         `json:"baseURL,omitempty"`
	SessionOpenedAt string         `json:"sessionOpenedAt,omitempty"`
	// VAU carries the spec-named keys from GET /VAU-Status:
	// VAU-Type, VAU-Version, User-Authentication, KeyID, Connection-Start.
	VAU   *vau.Status `json:"vau,omitempty"`
	Error string      `json:"error,omitempty"`
}

// ProxyStatus is the answer of GET /status.
type ProxyStatus struct {
	Name            string              `json:"name"`
	Env             Env                 `json:"env"`
	Subject         string              `json:"subject,omitempty"`
	TelematikID     string              `json:"telematikId,omitempty"`
	IdentityError   string              `json:"identityError,omitempty"`
	InsurantsCached int                 `json:"insurantsCached"`
	Providers       []ProviderVAUStatus `json:"providers"`
}

// HandleProxyStatus aggregates GET /VAU-Status of all providers with the local session state,
// through the guard, so that polling pages do not reach the providers at their own rate.
// Provider failures are reported as data, not as an HTTP error: a status endpoint must answer
// even when providers are down.
func (p *Proxy) HandleProxyStatus(w http.ResponseWriter, r *http.Request) {
	providers, err := p.statusGuard.Status(r.Context())
	if err != nil {
		return
	}

	proxyStatus := ProxyStatus{
		Name:      p.config.Name,
		Env:       p.Env,
		Providers: providers,
	}

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

// checkProviderStatus asks one provider for its VAU status; without a session it opens one.
func (p *Proxy) checkProviderStatus(provider ProviderNumber) ProviderVAUStatus {
	status := ProviderVAUStatus{Number: provider}

	session, err := p.sessionManager.GetSession(provider)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.BaseURL = session.BaseURL
	status.SessionOpenedAt = session.OpenedAt.Format(time.RFC3339)

	vauStatus, err := session.GetStatus()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.VAU = vauStatus
	return status
}
