package pep

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/libzero/oauth2server"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type PEP struct {
	Config             Config
	httpClient         http.Client
	authzIssuer        string
	authzMetadata      *oauth2server.Metadata
	authzMetadataMutex sync.RWMutex
	jwksCache          *jwk.Cache
	proxies            []*ResourceReverseProxy
}

type ResourceReverseProxy struct {
	config ResourceConfig
	proxy  *httputil.ReverseProxy
}

func (proxy *ResourceReverseProxy) Forward(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("X-ZTA-PEP-Version", "0.0.1")
	proxy.proxy.ServeHTTP(w, r)
}

func New(config Config) (*PEP, error) {
	p := &PEP{
		Config:      config,
		httpClient:  http.Client{},
		authzIssuer: config.AuthzIssuer,
	}

	for _, r := range config.Resources {
		url, err := url.Parse(r.Destination)
		if err != nil {
			return nil, fmt.Errorf("parse destination URL for pattern '%s': %w", r.Pattern, err)
		}
		p.proxies = append(p.proxies, &ResourceReverseProxy{
			config: r,
			proxy:  httputil.NewSingleHostReverseProxy(url),
		})
		slog.Info("created reverse proxy", "pattern", r.Pattern, "destination", r.Destination)
	}

	go p.periodicMetadataReload(context.Background(), 5*time.Minute)

	return p, nil
}

func (p *PEP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, proxy := range p.proxies {
		if proxy.config.Pattern.MatchString(r.URL.Path) {
			proxy.Forward(w, r)
			return
		}
	}
	p.RespondWithError(w, r, ErrorNotFound)
}

func (p *PEP) RespondWithError(w http.ResponseWriter, r *http.Request, err ErrorType) {
	w.WriteHeader(err.HttpStatus)
	json.NewEncoder(w).Encode(err)
}

func (p *PEP) ListenAndServe(ctx context.Context) error {

	server := &http.Server{
		Addr:         p.Config.Address,
		Handler:      p,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// stop server when context is done
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	return server.ListenAndServe()
}
