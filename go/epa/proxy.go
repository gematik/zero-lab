package epa

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/google/uuid"

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

	// SMC-B identity: either a PKCS#12 (authn_p12_path) or a PEM cert+key pair
	// (authn_cert_path + authn_key_path). PKCS#12 takes precedence when set.
	AuthnP12Path     string `yaml:"authn_p12_path"`
	AuthnP12Password string `yaml:"authn_p12_password"`
	AuthnCertPath    string `yaml:"authn_cert_path"`
	AuthnKeyPath     string `yaml:"authn_key_path"`

	VsdmHmacKeyHex string `yaml:"vsdm_hmac_key_hex" validate:"required"`
	VsdmHmacKeyId  string `yaml:"vsdm_hmac_key_id" validate:"required"`

	SecurityFunctions *SecurityFunctions `yaml:"-"`

	// CertPool is the TLS root pool used when connecting to ePA aggregators.
	// When nil, the session manager falls back to InsecureSkipVerify — fine for
	// demos, wrong for anything real. Callers should populate this from the
	// gematik TI roots (e.g. via gempki.EmbeddedLoader{Env}.Load(ctx)).
	CertPool *x509.CertPool `yaml:"-"`
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

	// Load the SMC-B identity: PKCS#12 takes precedence, else PEM cert+key.
	var authnSignFunc brainpool.SignFunc
	var authnCert *x509.Certificate
	switch {
	case pc.AuthnP12Path != "":
		p12Path := resolvePath(pc.BaseDir, pc.AuthnP12Path)
		slog.Debug("Reading SMC-B identity from PKCS#12", "p12_path", p12Path)
		key, cert, err := LoadIdentityP12(p12Path, pc.AuthnP12Password)
		if err != nil {
			return fmt.Errorf("failed to load SMC-B identity from PKCS#12: %w", err)
		}
		authnSignFunc = brainpool.SignFuncPrivateKey(key)
		authnCert = cert
	case pc.AuthnCertPath != "" && pc.AuthnKeyPath != "":
		authnCertPath := resolvePath(pc.BaseDir, pc.AuthnCertPath)
		authnPrivateKeyPath := resolvePath(pc.BaseDir, pc.AuthnKeyPath)
		slog.Debug("Reading SMC-B private key and certificate", "private_key_path", authnPrivateKeyPath, "cert_path", authnCertPath)

		authnCertData, err := os.ReadFile(authnCertPath)
		if err != nil {
			return fmt.Errorf("failed to read SMC-B certificate: %w", err)
		}
		if authnCert, err = brainpool.ParseCertificatePEM(authnCertData); err != nil {
			return fmt.Errorf("failed to parse SMC-B certificate: %w", err)
		}
		authnPrivateKeyData, err := os.ReadFile(authnPrivateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read SMC-B private key: %w", err)
		}
		authnPrivateKey, err := brainpool.ParsePrivateKeyPEM(authnPrivateKeyData)
		if err != nil {
			return fmt.Errorf("failed to parse SMC-B private key: %w", err)
		}
		authnSignFunc = brainpool.SignFuncPrivateKey(authnPrivateKey)
	default:
		return fmt.Errorf("identity config required: set authn_p12_path, or both authn_cert_path and authn_key_path")
	}
	slog.Info("Successfully loaded SMC-B certificate", "subject", authnCert.Subject.CommonName)

	certFunc := func() (*x509.Certificate, error) { return authnCert, nil }
	pc.SecurityFunctions = &SecurityFunctions{
		AuthnSignFunc:           authnSignFunc,
		AuthnCertFunc:           certFunc,
		ClientAssertionSignFunc: authnSignFunc,
		ClientAssertionCertFunc: certFunc,
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

// NewProxyWithSecurityFunctions builds a Proxy from a pre-assembled
// SecurityFunctions, skipping ProxyConfig.Init() (which reads cert+key files
// from disk and assembles a VSDM-HMAC ProvidePN). Use this from callers that
// already produced SecurityFunctions through some other identity backend
// (e.g. a Konnektor-backed signer or a PKCS#12 loaded in another process).
//
// ProvidePN / ProvideHCV may be left nil on sf when the caller is only
// interested in /information endpoints and the VAU handshake; VAU-bound calls
// that need entitlement will fail at the first call with a clear nil-deref
// error from the consuming code.
func NewProxyWithSecurityFunctions(env Env, sf *SecurityFunctions, name string, timeout time.Duration, certPool *x509.CertPool) (*Proxy, error) {
	if sf == nil {
		return nil, fmt.Errorf("SecurityFunctions is required")
	}
	return NewProxy(&ProxyConfig{
		Env:               env,
		Name:              name,
		Timeout:           timeout,
		SecurityFunctions: sf,
		CertPool:          certPool,
	})
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
		certPool:          config.CertPool,
		sessions:          make(map[ProviderNumber]*Session),
	}

	for _, providerNumber := range AllProviders {
		go p.sessionManager.WatchSession(providerNumber)
	}

	p.mux.Handle("/providers", http.HandlerFunc(p.GetProviders))
	// add direct VAU handler
	p.mux.Handle("/providers/{providerNumber}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUProvider))
	// add direct provider handler
	p.mux.Handle("/providers/{providerNumber}/{path...}", http.HandlerFunc(p.HandleForwardToProvider))

	// add insurants handlers
	p.mux.Handle("/insurants", http.HandlerFunc(p.GetInsurants))
	p.mux.Handle("/insurants/{insurantID}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUInsurant))

	// shows proxy info
	p.mux.Handle("/info", http.HandlerFunc(p.HandleProxyInfo))

	return p, nil
}

func (p *Proxy) HandleForwardToProvider(w http.ResponseWriter, r *http.Request) {
	num, err := strconv.Atoi(r.PathValue("providerNumber"))
	if err != nil {
		http.Error(w, "invalid provider number", http.StatusBadRequest)
		return
	}

	session, err := p.sessionManager.GetSession(ProviderNumber(num))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get session: %v", err), http.StatusBadGateway)
		return
	}

	r2, err := http.NewRequest(r.Method, session.BaseURL+"/"+r.PathValue("path"), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
		return
	}
	r2.URL.RawQuery = r.URL.RawQuery

	copyAndPrepareHeaders(r.Header, r2.Header)

	slog.Info("Forwarding request to provider", "method", r2.Method, "url", r2.URL.String(), "headers", r2.Header)

	resp, err := session.HttpClient.Do(r2)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to forward request: %v", err), http.StatusInternalServerError)
		return
	}

	maps.Copy(w.Header(), resp.Header)
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

func (p *Proxy) HandleForwardToVAUProvider(w http.ResponseWriter, r *http.Request) {
	num, err := strconv.Atoi(r.PathValue("providerNumber"))
	if err != nil {
		http.Error(w, "invalid provider number", http.StatusBadRequest)
		return
	}

	p.forwardToVAU(w, r, ProviderNumber(num), "")
}

var proxyBlockedHeaderNames = []string{
	"authorization",
	"via",
	"x-forwarded-host",
	"x-forwarded-for",
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
	r2.Host = session.VAUChannel.ChannelURL.Host

	copyAndPrepareHeaders(r.Header, r2.Header)

	if insurantID != "" {
		r2.Header.Set("x-insurantid", insurantID)
	}

	if r2.Header.Get("x-request-id") == "" {
		// set request id to uuid4
		r2.Header.Set("x-request-id", uuid.New().String())
	}

	slog.Info("Forwarding request to VAU", "method", r2.Method, "path", r2.URL.String(), "headers", r2.Header, "session_url", session.BaseURL)

	resp, err := session.VAUChannel.Do(r2)
	if err != nil {
		slog.Error("Failed to forward request", "error", err)
		http.Error(w, fmt.Sprintf("failed to forward request: %v", err), http.StatusInternalServerError)
		return
	}

	maps.Copy(w.Header(), resp.Header)

	slog.Info("Got forwarded request response", "method", r2.Method, "path", r2.URL.String(), "status", resp.StatusCode, "session_url", session.BaseURL)

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

// copyAndPrepareHeaders copies headers from src to dst, while
// 1. removing or modifying headers that should not be forwarded to the provider.
// 2. adding necessary headers if they are not specified explicitly by the client
func copyAndPrepareHeaders(src, dst http.Header) {
	for n, v := range src {
		lowerN := strings.ToLower(n)
		if slices.Contains(proxyBlockedHeaderNames, lowerN) {
			continue
		}
		dst[n] = v
	}

	if dst.Get("x-useragent") == "" {
		dst.Set("x-useragent", UserAgent)
	}

	if dst.Get("x-request-id") == "" {
		// set request id to uuid4
		dst.Set("x-request-id", uuid.New().String())
	}
}
