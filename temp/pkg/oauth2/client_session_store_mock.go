package oauth2

import (
	"errors"
	"sync"
)

func NewMockAuthzClientSessionStore() AuthzClientSessionStore {
	return &mockAuthzClientSessionStore{
		sessions: make(map[string]*AuthzClientSession),
	}
}

var ErrSessionNotFound = errors.New("session not found")

type mockAuthzClientSessionStore struct {
	sessions map[string]*AuthzClientSession
	lock     sync.RWMutex
}

func (s *mockAuthzClientSessionStore) GetAuthzClientSessionByID(id string) (*AuthzClientSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return session, nil
}

func (s *mockAuthzClientSessionStore) GetAuthzClientSessionByState(state string) (*AuthzClientSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	for _, session := range s.sessions {
		if session.State == state {
			return session, nil
		}
	}
	return nil, ErrSessionNotFound
}

func (s *mockAuthzClientSessionStore) SaveAuthzClientSession(session *AuthzClientSession) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *mockAuthzClientSessionStore) DeleteAuthzClientSession(state string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for id, session := range s.sessions {
		if session.State == state {
			delete(s.sessions, id)
			return nil
		}
	}
	return ErrSessionNotFound
}
