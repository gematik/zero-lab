package tpmattest

import (
	"fmt"
	"sync"
)

type mockActivationSessionStore struct {
	sessions map[string]ActivationSession
	lock     sync.RWMutex
}

func (s *mockActivationSessionStore) SaveTPMActivationSession(session ActivationSession) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.sessions[session.ID] = session
	return nil
}

func (s *mockActivationSessionStore) LoadTPMActivationSession(id string) (*ActivationSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	session, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	return &session, nil
}
