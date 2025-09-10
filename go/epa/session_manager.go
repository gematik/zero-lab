package epa

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/gemidp"
)

type sessionManager struct {
	lock              sync.RWMutex
	timeout           time.Duration
	env               Env
	certPool          *x509.CertPool
	securityFunctions *SecurityFunctions
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
	var err error
	var session *Session
	if sm.certPool == nil {
		session, err = OpenSession(sm.env, provider, sm.securityFunctions, WithTimeout(sm.timeout), WithInsecureSkipVerify())
	} else {
		session, err = OpenSession(sm.env, provider, sm.securityFunctions, WithTimeout(sm.timeout), WithCertPool(sm.certPool))
	}
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

	for range ticker.C {
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

func (sm *sessionManager) Close() {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	for pn, session := range sm.sessions {
		session.Close()
		delete(sm.sessions, pn)
	}

}
