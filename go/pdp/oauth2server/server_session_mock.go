package oauth2server

import (
	"errors"
	"sync"
)

type mockSessionStore struct {
	sessions []*AuthzServerSession
	lock     sync.RWMutex
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make([]*AuthzServerSession, 0, 16),
	}
}

func (s *mockSessionStore) GetAuthzServerSessionByID(id string) (*AuthzServerSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.ID == id {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetAuthzServerSessionByState(state string) (*AuthzServerSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.State == state {
			return session, nil
		}
	}

	return nil, errors.New("session not found")
}

func (s *mockSessionStore) SaveAutzhServerSession(session *AuthzServerSession) error {
	if _, err := s.GetAuthzServerSessionByID(session.ID); err == nil {
		return nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions = append(s.sessions, session)

	return nil
}

func (s *mockSessionStore) DeleteAuthzServerSessionByID(id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for i, session := range s.sessions {
		if session.ID == id {
			s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
			return nil
		}
	}
	return errors.New("session not found")
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
