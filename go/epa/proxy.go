package epa

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/gempki"
)

type ProvidersError struct {
	Code           string         `json:"error"`
	Description    string         `json:"error_description"`
	ProviderNumber ProviderNumber `json:"provider"`
}

func (e *ProvidersError) Error() string {
	return fmt.Sprintf("provider %d: %s: %s", e.ProviderNumber, e.Code, e.Description)
}

type MultiProviderError struct {
	Errors []ProvidersError `json:"errors"`
}

func (e *MultiProviderError) Error() string {
	var errStrings []string
	for _, err := range e.Errors {
		errStrings = append(errStrings, err.Error())
	}
	return fmt.Sprintf("multiple provider errors: %s", strings.Join(errStrings, "; "))
}

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
	BaseDir string        `yaml:"-"`
	Name    string        `yaml:"name" validate:"required"`
	Env     Env           `yaml:"env" validate:"required,oneof=dev test ref prod"`
	Timeout time.Duration `yaml:"timeout" validate:"required,gt=0"`

	AuthnCertPath string `yaml:"authn_cert_path" validate:"required"`
	AuthnKeyPath  string `yaml:"authn_key_path" validate:"required"`

	VsdmHmacKeyHex string `yaml:"vsdm_hmac_key_hex" validate:"required"`
	VsdmHmacKeyId  string `yaml:"vsdm_hmac_key_id" validate:"required"`

	SecurityFunctions *SecurityFunctions `yaml:"-"`
}

func (pc *ProxyConfig) Init() error {
	provideHCV := func(insurantId string) ([]byte, error) {
		return CalculateHCV("19981123", "Berliner Straße")
	}

	vsdmHMACKey := pc.VsdmHmacKeyHex
	vsdmHMACKeyID := pc.VsdmHmacKeyId
	slog.Debug("Using VSDM HMAC Key", "key", "***", "kid", vsdmHMACKeyID)
	proofOfAuditEvidenceFunc, err := CalculatePNv2(
		vsdmHMACKey,
		vsdmHMACKeyID,
		provideHCV,
	)
	if err != nil {
		return fmt.Errorf("failed to create ProofOfAuditEvidenceFunc: %w", err)
	}

	// read the private key and certificate for SMC-B
	authnCertPath := resolvePath(pc.BaseDir, pc.AuthnCertPath)
	authnPrivateKeyPath := resolvePath(pc.BaseDir, pc.AuthnKeyPath)
	slog.Debug("Reading SMC-B private key and certificate", "private_key_path", authnPrivateKeyPath, "cert_path", authnCertPath)

	authnCertData, err := os.ReadFile(authnCertPath)
	if err != nil {
		return fmt.Errorf("failed to read SMC-B certificate: %w", err)
	}
	authnCert, err := brainpool.ParseCertificatePEM(authnCertData)
	if err != nil {
		return fmt.Errorf("failed to parse SMC-B certificate: %w", err)
	}
	slog.Info("Successfully read SMC-B certificate", "subject", authnCert.Subject.CommonName)
	authnPrivateKeyData, err := os.ReadFile(authnPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read SMC-B private key: %w", err)
	}
	authnPrivateKey, err := brainpool.ParsePrivateKeyPEM(authnPrivateKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse SMC-B private key: %w", err)
	}

	pc.SecurityFunctions = &SecurityFunctions{
		AuthnSignFunc:           brainpool.SignFuncPrivateKey(authnPrivateKey),
		AuthnCertFunc:           func() (*x509.Certificate, error) { return authnCert, nil },
		ClientAssertionSignFunc: brainpool.SignFuncPrivateKey(authnPrivateKey),
		ClientAssertionCertFunc: func() (*x509.Certificate, error) { return authnCert, nil },
		ProvidePN:               proofOfAuditEvidenceFunc,
		ProvideHCV:              provideHCV,
	}

	return nil
}

type PatientRecordMetadata struct {
	InsurantID string
	Provider   ProviderNumber
}

func resolvePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
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
	var err error

	p := &Proxy{
		Env:         config.Env,
		config:      config,
		mux:         http.NewServeMux(),
		records:     make(map[string]PatientRecordMetadata),
		recordsLock: sync.RWMutex{},
	}

	idpEnv := IDPEnvironment(p.Env)

	p.Authenticator, err = gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Idp:        gemidp.GetIdpByEnvironment(idpEnv),
		SignerFunc: gemidp.SignWith(config.SecurityFunctions.AuthnSignFunc, config.SecurityFunctions.AuthnCertFunc),
	})
	if err != nil {
		return nil, fmt.Errorf("creating authenticator: %w", err)
	}

	p.sessionManager = &sessionManager{
		env:               p.Env,
		timeout:           config.Timeout,
		securityFunctions: config.SecurityFunctions,
		authenticator:     p.Authenticator,
		certPool:          nil,
		sessions:          make(map[ProviderNumber]*Session),
	}

	for _, providerNumber := range AllProviders {
		go p.sessionManager.WatchSession(providerNumber)
	}

	// add direct VAU handler
	p.mux.Handle("/providers", http.HandlerFunc(p.GetProviders))
	p.mux.Handle("/providers/{providerNumber}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUProvider))

	// add insurants handler
	p.mux.Handle("/insurants", http.HandlerFunc(p.GetInsurants))
	p.mux.Handle("/insurants/{insurantID}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUInsurant))

	// shows proxy info
	p.mux.Handle("/info", http.HandlerFunc(p.HandleProxyInfo))

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

	r2.URL.RawQuery = r.URL.RawQuery

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

	slog.Info("Got forwarded request response", "method", r2.Method, "url", session.BaseURL, "path", r2.URL.String(), "status", resp.StatusCode)

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

		multiProviderError := &MultiProviderError{
			Errors: make([]ProvidersError, 0, len(AllProviders)),
		}

		for range AllProviders {
			r := <-results
			if r.error != nil {
				multiProviderError.Errors = append(multiProviderError.Errors, ProvidersError{
					Code:           "provider_error",
					Description:    r.error.Error(),
					ProviderNumber: r.provider,
				})
				slog.Error("Failed to get record status", "provider", r.provider, "error", r.error)
				continue
			}
			if r.record.InsurantID == "" {
				slog.Info("Record not found", "provider", r.provider, "insurantID", insurantID)
				multiProviderError.Errors = append(multiProviderError.Errors, ProvidersError{
					Code:           "record_not_found",
					Description:    fmt.Sprintf("record not found for insurantID '%s'", insurantID),
					ProviderNumber: r.provider,
				})
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
			return nil, multiProviderError
		}

	}

	return &rm, nil
}

func (p *Proxy) HandleForwardToVAUInsurant(w http.ResponseWriter, r *http.Request) {
	insurantID := r.PathValue("insurantID")
	rm, err := p.findAndCacheRecord(insurantID)
	if err != nil {
		slog.Error("Failed to find record", "insurantID", insurantID, "error", err)
		if mperr, ok := err.(*MultiProviderError); ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			errBytes, err := json.Marshal(mperr)
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to marshal error: %v", err), http.StatusInternalServerError)
				return
			}
			w.Write(errBytes)
			return
		} else {
			http.Error(w, fmt.Sprintf("failed to find record: %v", err), http.StatusBadGateway)
			return
		}
	}

	p.forwardToVAU(w, r, rm.Provider, rm.InsurantID)

}

type ProxyInfo struct {
	Name               string                     `json:"name"`
	Env                Env                        `json:"env"`
	Subject            string                     `json:"subject"`
	AdmissionStatement *gempki.AdmissionStatement `json:"admission_statement"`
}

func (p *Proxy) GetProxyInfo() (*ProxyInfo, error) {
	cert, err := p.config.SecurityFunctions.AuthnCertFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to get authn cert: %w", err)
	}
	admissionStatement, err := gempki.ParseAdmissionStatement(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse admission statement: %w", err)
	}
	return &ProxyInfo{
		Name:               p.config.Name,
		Env:                p.Env,
		Subject:            cert.Subject.CommonName,
		AdmissionStatement: admissionStatement,
	}, nil
}

func (p *Proxy) HandleProxyInfo(w http.ResponseWriter, r *http.Request) {
	info, err := p.GetProxyInfo()
	if err != nil {
		slog.Error("Failed to get proxy info", "error", err)
		http.Error(w, fmt.Sprintf("failed to get proxy info: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(info)
	if err != nil {
		slog.Error("Failed to encode proxy info", "error", err)
		return
	}
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
