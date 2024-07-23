package oauth2server

import (
	"errors"
	"sync"

	"github.com/gematik/zero-lab/go/libzero/oidc"
)

type mockSessionStore struct {
	sessions                map[string]*AuthzServerSession
	standaloneAuthnSessions map[string]*oidc.AuthnClientSession
	lock                    sync.RWMutex
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions:                make(map[string]*AuthzServerSession),
		standaloneAuthnSessions: make(map[string]*oidc.AuthnClientSession),
	}
}

func (s *mockSessionStore) GetAuthzServerSession(state string) (*AuthzServerSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	session, ok := s.sessions[state]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func (s *mockSessionStore) SaveAutzhServerSession(session *AuthzServerSession) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[session.State] = session
	return nil
}

func (s *mockSessionStore) DeleteAuthzServerSession(state string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.sessions, state)
	return nil
}

func (s *mockSessionStore) GetAutzhServerSessionByRequestURI(requestUri string) (*AuthzServerSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.RequestUri == requestUri {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetAuthzServerSessionByAuthnState(opState string) (*AuthzServerSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.AuthnClientSession != nil && session.AuthnClientSession.State == opState {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetAuthzServerSessionByCode(code string) (*AuthzServerSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.Code == code {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetAuthnClientSessionByState(state string) (*oidc.AuthnClientSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	session, ok := s.standaloneAuthnSessions[state]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func (s *mockSessionStore) SaveAuthnClientSession(session *oidc.AuthnClientSession) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.standaloneAuthnSessions[session.State] = session
	return nil
}

func (s *mockSessionStore) DeleteAuthnClientSession(state string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.standaloneAuthnSessions, state)
	return nil
}

func (s *mockSessionStore) GetAuthnClientSessionByID(id string) (*oidc.AuthnClientSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.standaloneAuthnSessions {
		if session.ID == id {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}
