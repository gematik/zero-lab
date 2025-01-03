package epa

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/gempki"
)

var ErrRecordNotFound = errors.New("record not found")

type Proxy struct {
	Env            Env
	config         *ProxyConfig
	Authenticator  *gemidp.Authenticator
	mux            *http.ServeMux
	sessionManager *sessionManager
	records        map[string]PatientRecordMetadata
	recordsLock    sync.RWMutex
}

type ProxyConfig struct {
	Env               Env
	SecurityFunctions SecurityFunctions
	Timeout           time.Duration
}

type PatientRecordMetadata struct {
	InsurantID string
	Provider   ProviderNumber
}

func IDPEnvironment(env Env) gemidp.Environment {
	switch env {
	case EnvDev:
		return gemidp.EnvironmentReference
	case EnvRef:
		return gemidp.EnvironmentReference
	case EnvTest:
		return gemidp.EnvironmentTest
	case EnvProd:
		return gemidp.EnvironmentProduction
	default:
		return gemidp.EnvironmentReference
	}
}

func NewProxy(config *ProxyConfig) (*Proxy, error) {
	p := &Proxy{
		Env:         config.Env,
		config:      config,
		mux:         http.NewServeMux(),
		records:     make(map[string]PatientRecordMetadata),
		recordsLock: sync.RWMutex{},
	}

	var tslURL string
	switch config.Env {
	case EnvDev:
		tslURL = gempki.URLTrustServiceListRef
	case EnvTest:
		tslURL = gempki.URLTrustServiceListTest
	case EnvRef:
		tslURL = gempki.URLTrustServiceListRef
	case EnvProd:
		tslURL = gempki.URLTrustServiceListProd
	default:
		return nil, errors.New("unknown environment")
	}

	tsl, err := gempki.LoadTSL(tslURL)
	if err != nil {
		return nil, err
	}

	certPool := gempki.RootsRef.BuildCertPool(tsl)

	idpEnv := IDPEnvironment(p.Env)

	p.Authenticator, err = gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Environment: idpEnv,
		SignerFunc:  gemidp.SignWith(config.SecurityFunctions.AuthnSignFunc, config.SecurityFunctions.AuthnCertFunc),
	})

	p.sessionManager = &sessionManager{
		env:               p.Env,
		timeout:           config.Timeout,
		securityFunctions: config.SecurityFunctions,
		authenticator:     p.Authenticator,
		certPool:          certPool,
		sessions:          make(map[ProviderNumber]*Session),
	}

	for _, providerNumber := range AllProviders {
		_, err := p.sessionManager.GetSession(providerNumber)
		go p.sessionManager.WatchSession(providerNumber)
		if err != nil {
			slog.Error("Failed to open session", "provider", providerNumber, "error", err)
		}
	}

	// add direct VAU handler
	p.mux.Handle("/api/providers", http.HandlerFunc(p.GetProviders))
	p.mux.Handle("/api/providers/{providerNumber}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUProvider))

	// add insurants handler
	p.mux.Handle("/api/insurants", http.HandlerFunc(p.GetInsurants))
	p.mux.Handle("/api/insurants/{insurantID}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUInsurant))

	return p, nil
}

func (p *Proxy) HandleForwardToVAUProvider(w http.ResponseWriter, r *http.Request) {
	num, err := strconv.Atoi(r.PathValue("providerNumber"))
	if err != nil {
		http.Error(w, "invalid provider number", http.StatusBadRequest)
		return
	}

	p.forwardToVAU(w, r, ProviderNumber(num), "")
}

func (p *Proxy) forwardToVAU(w http.ResponseWriter, r *http.Request, providerNumber ProviderNumber, insurantID string) {
	path := r.PathValue("path")
	path = "/" + path
	session, err := p.sessionManager.GetSession(providerNumber)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get session: %v", err), http.StatusBadGateway)
		return
	}

	r2, err := http.NewRequest(r.Method, path, r.Body)
	if err != nil {
		slog.Error("Failed to create request", "error", err)
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}

	r2.Header.Set("x-useragent", UserAgent)
	if insurantID != "" {
		r2.Header.Set("x-insurantid", insurantID)
	}

	resp, err := session.VAUChannel.Do(r2)
	if err != nil {
		slog.Error("Failed to forward request", "error", err)
		http.Error(w, fmt.Sprintf("failed to forward request: %v", err), http.StatusInternalServerError)
		return
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	slog.Info("Got forwarded request response", "method", r2.Method, "url", r2.URL.String(), "status", resp.StatusCode)

	w.WriteHeader(resp.StatusCode)

	// read from response body and write to response writer
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

func (p *Proxy) Close() {
	p.sessionManager.Close()
}

func (p *Proxy) findAndCacheRecord(insurantID string) (*PatientRecordMetadata, error) {
	p.recordsLock.RLock()
	rm, ok := p.records[insurantID]
	p.recordsLock.RUnlock()
	if !ok {
		p.recordsLock.Lock()
		defer p.recordsLock.Unlock()
		// try to find the record by asking every session if it has the record
		// run in parallel
		type result struct {
			provider ProviderNumber
			record   PatientRecordMetadata
			session  *Session
			error    error
		}

		results := make(chan result, len(AllProviders))

		for _, provider := range AllProviders {
			go func(provider ProviderNumber) {
				slog.Info(fmt.Sprintf("Checking record status for insurantID %s with provider %d", insurantID, provider))
				session, err := p.sessionManager.GetSession(provider)
				if err != nil {
					results <- result{provider: provider, error: err}
					return
				}
				found, err := session.GetRecordStatus(insurantID)
				if err != nil {
					results <- result{provider: provider, error: err}
					return
				}
				if found {
					results <- result{
						provider: provider,
						record: PatientRecordMetadata{
							InsurantID: insurantID,
							Provider:   provider,
						},
						session: session,
					}
					return
				} else {
					results <- result{
						provider: provider,
					}
				}
			}(provider)
		}

		for range AllProviders {
			r := <-results
			if r.error != nil {
				slog.Error("Failed to get record status", "provider", r.provider, "error", r.error)
				continue
			}
			if r.record.InsurantID == "" {
				slog.Info("Record not found", "provider", r.provider, "insurantID", insurantID)
				continue
			}
			slog.Info("Record status", "provider", r.provider, "insurantID", insurantID, "found", r.record.InsurantID != "")
			// entitle
			err := r.session.Entitle(insurantID)
			if err != nil {
				slog.Error("Failed to entitle", "provider", r.provider, "insurantID", insurantID, "error", err)
			}

			p.records[insurantID] = r.record
			rm = r.record
			break
		}

		if rm.InsurantID == "" {
			return nil, ErrRecordNotFound
		}

	}

	return &rm, nil
}

func (p *Proxy) HandleForwardToVAUInsurant(w http.ResponseWriter, r *http.Request) {
	insurantID := r.PathValue("insurantID")
	rm, err := p.findAndCacheRecord(insurantID)
	if err != nil {
		slog.Error("Failed to find record", "insurantID", insurantID, "error", err)
		if errors.Is(err, ErrRecordNotFound) {
			http.Error(w, "record not found", http.StatusNotFound)
			return
		} else {
			http.Error(w, fmt.Sprintf("failed to find record: %v", err), http.StatusBadGateway)
			return
		}
	}

	p.forwardToVAU(w, r, rm.Provider, rm.InsurantID)

}

func (p *Proxy) GetProviders(w http.ResponseWriter, r *http.Request) {
	type Provider struct {
		Number          ProviderNumber `json:"number"`
		BaseURL         string         `json:"baseURL"`
		SessionOpenedAt string         `json:"sessionOpenedAt"`
	}
	w.Header().Set("Content-Type", "application/json")
	providers := make([]Provider, 0, len(AllProviders))
	for _, providerNumber := range AllProviders {
		session, err := p.sessionManager.GetSession(providerNumber)
		if err != nil {
			slog.Error("Failed to get session", "provider", providerNumber, "error", err)
			continue
		}
		providers = append(providers, Provider{
			Number:          providerNumber,
			BaseURL:         session.BaseURL,
			SessionOpenedAt: session.OpenedAt.Format(time.RFC3339),
		})
	}
	err := json.NewEncoder(w).Encode(providers)
	if err != nil {
		slog.Error("Failed to encode providers", "error", err)
	}
}

func (p *Proxy) GetInsurants(w http.ResponseWriter, r *http.Request) {
	p.recordsLock.RLock()
	defer p.recordsLock.RUnlock()
	type InsurantModel struct {
		InsurantID     string `json:"insurantID"`
		ProviderNumber int    `json:"providerNumber"`
	}
	w.Header().Set("Content-Type", "application/json")
	insurants := make([]InsurantModel, 0, len(p.records))
	for _, record := range p.records {
		insurants = append(insurants, InsurantModel{
			InsurantID:     record.InsurantID,
			ProviderNumber: int(record.Provider),
		})
	}

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(insurants)
	if err != nil {
		slog.Error("Failed to encode insurants", "error", err)
	}
}

type sessionManager struct {
	lock              sync.RWMutex
	timeout           time.Duration
	env               Env
	certPool          *x509.CertPool
	securityFunctions SecurityFunctions
	authenticator     *gemidp.Authenticator
	sessions          map[ProviderNumber]*Session
}

func (sm *sessionManager) GetSession(provider ProviderNumber) (*Session, error) {
	session, ok := sm.sessions[provider]
	if !ok {
		return sm.openSession(provider)
	}
	return session, nil
}

func (sm *sessionManager) openSession(provider ProviderNumber) (*Session, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	session, err := OpenSession(sm.env, provider, sm.securityFunctions, WithCertPool(sm.certPool), WithTimeout(sm.timeout))
	if err != nil {
		return nil, fmt.Errorf("open session at provider %d: %w", provider, err)
	}

	err = session.Authorize(sm.authenticator)
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("authorize session at provider %d: %w", provider, err)
	}

	sm.sessions[provider] = session
	return session, nil
}

func (sm *sessionManager) WatchSession(pn ProviderNumber) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			slog.Debug("Checking session health", "provider", pn)
			session, err := sm.GetSession(pn)
			if err != nil {
				slog.Error("Failed to get session", "provider", pn, "error", err)
				continue
			}
			if err := session.HealthCheck(); err != nil {
				slog.Error("Session is unhealthy", "provider", session.ProviderNumber, "error", err)
				sm.lock.Lock()
				session.Close()
				delete(sm.sessions, session.ProviderNumber)
				sm.lock.Unlock()
				_, err := sm.openSession(session.ProviderNumber)
				if err != nil {
					slog.Error("Failed to re-open session", "provider", session.ProviderNumber, "error", err)
				}
			}

		}
	}
}

func (sm *sessionManager) Close() {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	for pn, session := range sm.sessions {
		session.Close()
		delete(sm.sessions, pn)
	}

}
