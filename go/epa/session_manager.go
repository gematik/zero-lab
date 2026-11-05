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
	"crypto/x509"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/epa/vau"
)

type sessionManager struct {
	lock              sync.RWMutex
	timeout           time.Duration
	env               Env
	certPool          *x509.CertPool
	securityFunctions *SecurityFunctions
	authenticator     Authenticator
	vauVerifier       vau.CertVerifier
	vauVerify         vau.VerifyMode
	sessions          map[ProviderNumber]*Session
	// opening holds a lock per provider, so a login waits only for another login at the same provider.
	opening map[ProviderNumber]*sync.Mutex
	// login opens and authorizes a session; nil means [sessionManager.loginAt].
	login func(ProviderNumber) (*Session, error)
}

func (sm *sessionManager) GetSession(provider ProviderNumber) (*Session, error) {
	sm.lock.RLock()
	session, ok := sm.sessions[provider]
	sm.lock.RUnlock()
	if !ok {
		return sm.openSession(provider)
	}
	return session, nil
}

func (sm *sessionManager) openSession(provider ProviderNumber) (*Session, error) {
	gate := sm.gate(provider)
	gate.Lock()
	defer gate.Unlock()

	// a concurrent caller may have opened the session while we waited
	sm.lock.RLock()
	session, ok := sm.sessions[provider]
	sm.lock.RUnlock()
	if ok {
		return session, nil
	}

	login := sm.login
	if login == nil {
		login = sm.loginAt
	}
	session, err := login(provider)
	if err != nil {
		return nil, err
	}

	sm.lock.Lock()
	sm.sessions[provider] = session
	sm.lock.Unlock()
	return session, nil
}

// gate is the lock that lets one login at a time run at provider.
func (sm *sessionManager) gate(provider ProviderNumber) *sync.Mutex {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	if sm.opening == nil {
		sm.opening = make(map[ProviderNumber]*sync.Mutex)
	}
	gate, ok := sm.opening[provider]
	if !ok {
		gate = new(sync.Mutex)
		sm.opening[provider] = gate
	}
	return gate
}

// loginAt opens a VAU session at provider and authorizes it.
func (sm *sessionManager) loginAt(provider ProviderNumber) (*Session, error) {
	options := []ClientOption{WithTimeout(sm.timeout), WithVAUVerification(sm.vauVerifier, sm.vauVerify)}
	if sm.certPool == nil {
		options = append(options, WithInsecureSkipVerify())
	} else {
		options = append(options, WithCertPool(sm.certPool))
	}
	client, err := NewClient(sm.env, provider, sm.securityFunctions, options...)
	if err != nil {
		return nil, fmt.Errorf("new client at provider %d: %w", provider, err)
	}

	session, err := client.OpenSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("open session at provider %d: %w", provider, err)
	}

	if err := session.Authorize(sm.authenticator); err != nil {
		client.Close()
		return nil, fmt.Errorf("authorize session at provider %d: %w", provider, err)
	}
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
	for session := range maps.Values(sm.sessions) {
		session.Close()
	}
	clear(sm.sessions)
}
