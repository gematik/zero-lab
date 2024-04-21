package zas

import (
	"errors"
	"sync"

	"github.com/gematik/zero-lab/pkg/oidc"
)

type mockSessionStore struct {
	sessions                map[string]*AuthzSession
	standaloneAuthnSessions map[string]*oidc.AuthnSession
	lock                    sync.RWMutex
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions:                make(map[string]*AuthzSession),
		standaloneAuthnSessions: make(map[string]*oidc.AuthnSession),
	}
}

func (s *mockSessionStore) GetAuthzSession(state string) (*AuthzSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	session, ok := s.sessions[state]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func (s *mockSessionStore) SaveAutzhSession(session *AuthzSession) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[session.State] = session
	return nil
}

func (s *mockSessionStore) DeleteAuthzSession(state string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.sessions, state)
	return nil
}

func (s *mockSessionStore) GetAutzhSessionByRequestURI(requestUri string) (*AuthzSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.RequestUri == requestUri {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetAuthzSessionByAuthnState(opState string) (*AuthzSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.AuthnSession != nil && session.AuthnSession.State == opState {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetAuthzSessionByCode(code string) (*AuthzSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.Code == code {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetAuthnSessionByState(state string) (*oidc.AuthnSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	session, ok := s.standaloneAuthnSessions[state]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func (s *mockSessionStore) SaveAuthnSession(session *oidc.AuthnSession) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.standaloneAuthnSessions[session.State] = session
	return nil
}

func (s *mockSessionStore) DeleteAuthnSession(state string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.standaloneAuthnSessions, state)
	return nil
}

func (s *mockSessionStore) GetAuthnSessionByID(id string) (*oidc.AuthnSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.standaloneAuthnSessions {
		if session.ID == id {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}
