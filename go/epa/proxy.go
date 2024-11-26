package epa

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"

	"github.com/gematik/zero-lab/go/gempki"
)

var ErrRecordNotFound = errors.New("record not found")

type Proxy struct {
	mux         *http.ServeMux
	sessions    map[ProviderNumber]*Session
	records     map[string]PatientRecordMetadata
	recordsLock sync.RWMutex
}

type ProxyConfig struct {
	Env               Env
	SecurityFunctions SecurityFunctions
}

type PatientRecordMetadata struct {
	InsurantID string
	Provider   ProviderNumber
}

func NewProxy(config *ProxyConfig) (*Proxy, error) {
	p := &Proxy{
		mux:         http.NewServeMux(),
		sessions:    make(map[ProviderNumber]*Session),
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

	for _, providerNumber := range []ProviderNumber{
		ProviderNumber1,
		ProviderNumber2,
	} {
		session, err := OpenSession(
			config.Env,
			providerNumber,
			config.SecurityFunctions,
			WithCertPool(certPool),
		)
		if err != nil {
			slog.Error("Failed to open session", "provider", providerNumber, "error", err)
			continue
		}

		err = session.Authorize()
		if err != nil {
			slog.Error("Failed to authorize session", "provider", providerNumber, "error", err)
			continue
		}

		p.sessions[providerNumber] = session
	}

	// add direct VAU handler
	p.mux.Handle("/providers/{providerNumber}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUProvider))

	// add insurants handler
	p.mux.Handle("/insurants/{insurantID}/vau/{path...}", http.HandlerFunc(p.HandleForwardToVAUInsurant))

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
	r.URL.Path = "/" + path
	session, ok := p.sessions[providerNumber]
	if !ok {
		http.Error(w, "provider not found", http.StatusNotFound)
		return
	}

	resp, err := session.VAUChannel.Do(r)
	if err != nil {
		http.Error(w, "failed to forward request", http.StatusInternalServerError)
		return
	}

	r.Header.Set("x-useragent", UserAgent)
	if insurantID != "" {
		r.Header.Set("x-insurantid", insurantID)
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	slog.Info("Forwarded request", "method", r.Method, "url", r.URL, "status", resp.StatusCode)

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
	for _, session := range p.sessions {
		session.Close()
	}
}

func (p *Proxy) findAndCacheRecord(insurantID string) (*PatientRecordMetadata, error) {
	p.recordsLock.RLock()
	rm, ok := p.records[insurantID]
	p.recordsLock.RUnlock()
	if !ok {
		// try to find the record by asking every session if it has the record
		// run in parallel
		type result struct {
			provider ProviderNumber
			record   PatientRecordMetadata
			error    error
		}

		results := make(chan result, len(p.sessions))

		for provider, session := range p.sessions {
			go func(provider ProviderNumber, session *Session) {
				slog.Info("Checking record status", "provider", provider, "insurantID", insurantID)
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
					}
					return
				} else {
					results <- result{
						provider: provider,
					}
				}
			}(provider, session)
		}

		for i := 0; i < len(p.sessions); i++ {
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
			p.recordsLock.Lock()
			p.records[insurantID] = r.record
			p.recordsLock.Unlock()
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
			http.Error(w, "failed to find record", http.StatusInternalServerError)
			return
		}
	}

	p.forwardToVAU(w, r, rm.Provider, rm.InsurantID)

}
