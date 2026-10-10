package epa

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/epa/ti"
	"github.com/gematik/zero-lab/go/epa/vau"
	"github.com/google/uuid"
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
	Authenticator  Authenticator
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

	// SMC-B identity, loaded and used by the `ti` tool: a PKCS#12 (authn_p12_path, its
	// password in the file authn_p12_password_path names, default 00), a PEM cert+key
	// pair (authn_cert_path + authn_key_path), or a card at the Konnektor (authn_card,
	// with authn_connector naming the .kon configuration, else the selected one).
	// authn_p12_password passes the password itself and is kept for old configurations;
	// prefer the file, which stays out of the process list.
	AuthnP12Path         string `yaml:"authn_p12_path"`
	AuthnP12PasswordPath string `yaml:"authn_p12_password_path"`
	AuthnP12Password     string `yaml:"authn_p12_password"`
	AuthnCertPath        string `yaml:"authn_cert_path"`
	AuthnKeyPath         string `yaml:"authn_key_path"`
	AuthnCard            string `yaml:"authn_card"`
	AuthnConnector       string `yaml:"authn_connector"`

	// VAUCertVerify is what to do with the verdict on the VAU's certificates and host
	// keys: warn (default) logs it, enforce fails the handshake on a bad one, off skips
	// the check.
	VAUCertVerify string `yaml:"vau_cert_verify" validate:"omitempty,oneof=off warn enforce"`

	VsdmHmacKeyHex string `yaml:"vsdm_hmac_key_hex" validate:"required"`
	VsdmHmacKeyId  string `yaml:"vsdm_hmac_key_id" validate:"required"`

	SecurityFunctions *SecurityFunctions `yaml:"-"`
	// Authenticator answers the IDP-Dienst's challenges; Init sets it up over the
	// identity, callers of NewProxyWithSecurityFunctions bring their own.
	Authenticator Authenticator `yaml:"-"`
	// TI is the tool; nil means EPA_TI_BIN or `ti` on the PATH.
	TI *ti.Binary `yaml:"-"`

	// CertPool is the TLS root pool used when connecting to ePA aggregators.
	// When nil, the session manager falls back to InsecureSkipVerify — fine for
	// demos, wrong for anything real. Callers should populate this from the
	// gematik TI roots (`ti pki roots bundle`).
	CertPool *x509.CertPool `yaml:"-"`

	vauVerifier vau.CertVerifier
}

// identitySource is the `ti` identity the configuration names.
func (pc *ProxyConfig) identitySource() ti.IdentitySource {
	source := ti.IdentitySource{
		P12Password: pc.AuthnP12Password,
		Card:        pc.AuthnCard,
		Connector:   pc.AuthnConnector,
	}
	if pc.AuthnP12Path != "" {
		source.P12Path = resolvePath(pc.BaseDir, pc.AuthnP12Path)
	}
	if pc.AuthnP12PasswordPath != "" {
		source.P12PasswordPath = resolvePath(pc.BaseDir, pc.AuthnP12PasswordPath)
	}
	if pc.AuthnCertPath != "" {
		source.CertPath = resolvePath(pc.BaseDir, pc.AuthnCertPath)
	}
	if pc.AuthnKeyPath != "" {
		source.KeyPath = resolvePath(pc.BaseDir, pc.AuthnKeyPath)
	}
	return source
}

// VAUVerification is the client option carrying the configured VAU certificate check,
// for callers that build clients themselves (the probe).
func (pc *ProxyConfig) VAUVerification() ClientOption {
	return WithVAUVerification(pc.vauVerifier, pc.vauVerifyMode())
}

// vauVerifyMode is the configured mode, warn by default.
func (pc *ProxyConfig) vauVerifyMode() vau.VerifyMode {
	switch pc.VAUCertVerify {
	case "off":
		return vau.VerifyOff
	case "enforce":
		return vau.VerifyEnforce
	default:
		return vau.VerifyWarn
	}
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

	// The SMC-B identity lives with the ti tool; this process only learns the
	// certificate.
	runner := pc.TI
	if runner == nil {
		runner, err = ti.NewBinary()
		if err != nil {
			return err
		}
	}
	ctx := context.Background()
	version, err := runner.Version(ctx)
	if err != nil {
		return fmt.Errorf("ti at %s: %w", runner.Path, err)
	}
	slog.Debug("Using ti", "path", runner.Path, "version", version.Version)

	source := pc.identitySource()
	slog.Debug("Loading SMC-B identity", "source", source.String())
	identity, err := ti.NewIdentity(ctx, runner, source)
	if err != nil {
		return fmt.Errorf("failed to load SMC-B identity: %w", err)
	}
	slog.Info("Successfully loaded SMC-B certificate", "subject", identity.CommonName(), "telematik_id", identity.TelematikID(), "curve", identity.Curve())

	pc.SecurityFunctions = SecurityFunctionsFromIdentity(identity, provideHCV, proofOfAuditEvidenceFunc)
	pc.Authenticator = &ti.Authenticator{Runner: runner, Source: source, Env: IDPEnvironment(pc.Env)}
	if pc.vauVerifyMode() != vau.VerifyOff {
		pc.vauVerifier = &ti.Verifier{Runner: runner}
	}

	return nil
}

type PatientRecordMetadata struct {
	InsurantID string
	Provider   ProviderNumber
	EntitledAt time.Time
	ValidTo    time.Time
}

func resolvePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// IDPEnvironment is the TI environment whose IDP-Dienst serves the ePA environment,
// as `ti idpd authenticate --env` takes it: dev shares the reference IDP.
func IDPEnvironment(env Env) string {
	switch env {
	case EnvTest:
		return "test"
	case EnvProd:
		return "prod"
	default:
		return "ref"
	}
}

// NewProxyWithSecurityFunctions builds a Proxy from a pre-assembled
// SecurityFunctions and Authenticator, skipping ProxyConfig.Init() (which loads
// the identity through the ti tool and assembles a VSDM-HMAC ProvidePN). Use
// this from callers that bring their own identity backend.
//
// ProvidePN / ProvideHCV may be left nil on sf when the caller is only
// interested in /information endpoints and the VAU handshake; VAU-bound calls
// that need entitlement will fail at the first call with a clear error from
// the consuming code. When sf.ProvidePoPP is set, the proxy entitles via the
// PoPP token path and ignores ProvidePN/ProvideHCV. The VAU's certificates are
// not verified on this path.
func NewProxyWithSecurityFunctions(env Env, sf *SecurityFunctions, authenticator Authenticator, name string, timeout time.Duration, certPool *x509.CertPool) (*Proxy, error) {
	if sf == nil {
		return nil, fmt.Errorf("SecurityFunctions is required")
	}
	if authenticator == nil {
		return nil, fmt.Errorf("Authenticator is required")
	}
	return NewProxy(&ProxyConfig{
		Env:               env,
		Name:              name,
		Timeout:           timeout,
		SecurityFunctions: sf,
		Authenticator:     authenticator,
		CertPool:          certPool,
		VAUCertVerify:     "off",
	})
}

func NewProxy(config *ProxyConfig) (*Proxy, error) {
	if config.SecurityFunctions == nil || config.Authenticator == nil {
		return nil, fmt.Errorf("proxy %q: identity not loaded (ProxyConfig.Init)", config.Name)
	}
	p := &Proxy{
		Env:           config.Env,
		config:        config,
		Authenticator: config.Authenticator,
		mux:           http.NewServeMux(),
		records:       make(map[string]PatientRecordMetadata),
		recordsLock:   sync.RWMutex{},
	}

	p.sessionManager = &sessionManager{
		env:               p.Env,
		timeout:           config.Timeout,
		securityFunctions: config.SecurityFunctions,
		authenticator:     p.Authenticator,
		certPool:          config.CertPool,
		vauVerifier:       config.vauVerifier,
		vauVerify:         config.vauVerifyMode(),
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
	p.mux.Handle("GET /insurants/{insurantID}", http.HandlerFunc(p.HandleInsurantInfo))
	p.mux.Handle("POST /insurants/{insurantID}/entitlement", http.HandlerFunc(p.HandleEntitleInsurant))
	p.mux.Handle("/insurants/{insurantID}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUInsurant))

	// shows proxy info
	p.mux.Handle("/info", http.HandlerFunc(p.HandleProxyInfo))

	// aggregated VAU/session status of all providers
	p.mux.Handle("GET /status", http.HandlerFunc(p.HandleProxyStatus))

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

// entitle registers an entitlement for the insurant on the given session,
// choosing the proof source from the configured SecurityFunctions: a PoPP
// token when ProvidePoPP is set, otherwise the VSDM Prüfziffer. Returns the
// entitlement's validTo, zero on the VSDM path whose response has no body.
func (p *Proxy) entitle(session *Session, insurantID string) (time.Time, error) {
	sf := p.config.SecurityFunctions
	if sf == nil {
		return time.Time{}, fmt.Errorf("no security functions configured")
	}

	if sf.ProvidePoPP != nil {
		poppToken, err := sf.ProvidePoPP(insurantID)
		if err != nil {
			return time.Time{}, fmt.Errorf("getting PoPP token: %w", err)
		}
		return session.SetEntitlementPoPP(insurantID, poppToken)
	}

	if sf.ProvidePN == nil || sf.ProvideHCV == nil {
		return time.Time{}, fmt.Errorf("no entitlement proof configured: set ProvidePoPP or ProvidePN+ProvideHCV")
	}

	auditEvidence, err := sf.ProvidePN(insurantID)
	if err != nil {
		return time.Time{}, fmt.Errorf("getting proof of audit evidence: %w", err)
	}

	hcv, err := sf.ProvideHCV(insurantID)
	if err != nil {
		return time.Time{}, fmt.Errorf("getting HCV: %w", err)
	}

	if err := session.SetEntitlementPN(insurantID, auditEvidence, hcv); err != nil {
		return time.Time{}, err
	}

	return time.Time{}, nil
}

// findRecordProvider asks all providers in parallel which one holds the
// record for the given insurant. It performs no entitlement and touches no
// cache; callers must not rely on any lock being held.
func (p *Proxy) findRecordProvider(insurantID string) (*Session, *MultiProviderError) {
	type result struct {
		provider ProviderNumber
		found    bool
		session  *Session
		err      error
	}

	results := make(chan result, len(AllProviders))

	for _, provider := range AllProviders {
		go func(provider ProviderNumber) {
			slog.Info("Checking record status", "insurantID", insurantID, "provider", provider)
			session, err := p.sessionManager.GetSession(provider)
			if err != nil {
				results <- result{provider: provider, err: err}
				return
			}
			found, err := session.GetRecordStatus(insurantID)
			results <- result{provider: provider, found: found, session: session, err: err}
		}(provider)
	}

	multiProviderError := &MultiProviderError{
		Errors: make([]ProvidersError, 0, len(AllProviders)),
	}

	var foundSession *Session
	for range AllProviders {
		r := <-results
		if r.err != nil {
			multiProviderError.Errors = append(multiProviderError.Errors, ProvidersError{
				Code:           "provider_error",
				Description:    r.err.Error(),
				ProviderNumber: r.provider,
			})
			slog.Error("Failed to get record status", "provider", r.provider, "error", r.err)
			continue
		}
		if !r.found {
			slog.Info("Record not found", "provider", r.provider, "insurantID", insurantID)
			multiProviderError.Errors = append(multiProviderError.Errors, ProvidersError{
				Code:           "record_not_found",
				Description:    fmt.Sprintf("record not found for insurantID '%s'", insurantID),
				ProviderNumber: r.provider,
			})
			continue
		}
		slog.Info("Record found", "provider", r.provider, "insurantID", insurantID)
		if foundSession == nil {
			foundSession = r.session
		}
	}

	if foundSession == nil {
		return nil, multiProviderError
	}
	return foundSession, nil
}

func (p *Proxy) findAndCacheRecord(insurantID string) (*PatientRecordMetadata, error) {
	p.recordsLock.RLock()
	rm, ok := p.records[insurantID]
	p.recordsLock.RUnlock()
	if ok {
		return &rm, nil
	}

	session, multiErr := p.findRecordProvider(insurantID)
	if multiErr != nil {
		return nil, multiErr
	}

	rm = PatientRecordMetadata{
		InsurantID: insurantID,
		Provider:   session.ProviderNumber,
	}
	if validTo, err := p.entitle(session, insurantID); err != nil {
		slog.Error("Failed to entitle", "provider", session.ProviderNumber, "insurantID", insurantID, "error", err)
	} else {
		rm.EntitledAt = time.Now()
		rm.ValidTo = validTo
	}

	p.recordsLock.Lock()
	p.records[insurantID] = rm
	p.recordsLock.Unlock()

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
	Name               string     `json:"name"`
	Env                Env        `json:"env"`
	Subject            string     `json:"subject"`
	AdmissionStatement *Admission `json:"admission_statement"`
}

func (p *Proxy) GetProxyInfo() (*ProxyInfo, error) {
	identity := p.config.SecurityFunctions.Identity
	if identity == nil {
		return nil, fmt.Errorf("no SMC-B authn identity configured")
	}
	admission := identity.Admission()
	if admission == nil {
		return nil, fmt.Errorf("the SMC-B certificate has no admission statement")
	}
	return &ProxyInfo{
		Name:               p.config.Name,
		Env:                p.Env,
		Subject:            CommonName(identity.Subject()),
		AdmissionStatement: admission,
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
