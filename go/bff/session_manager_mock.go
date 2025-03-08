package bff

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/segmentio/ksuid"
)

type sessionManagerMock struct {
	mux      *sync.RWMutex
	sessions map[string]*Session
}

func NewSessionManagerMock() SessionManager {
	return &sessionManagerMock{
		mux:      &sync.RWMutex{},
		sessions: make(map[string]*Session),
	}
}

func (m *sessionManagerMock) CreateSession(state string, codeVerifier string, codeChallengeMethod string) (*Session, error) {
	m.mux.Lock()
	defer m.mux.Unlock()
	session := &Session{
		ID:                  ksuid.New().String(),
		State:               state,
		CreatedAt:           time.Now(),
		CodeVerifier:        codeVerifier,
		CodeChallengeMethod: codeChallengeMethod,
	}
	m.sessions[state] = session
	slog.Info("session created", "id", session.ID, "state", session.State)
	return session, nil
}

func (m *sessionManagerMock) UpdateSession(session *Session) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.sessions[session.State] = session
	slog.Info("session updated", "id", session.ID, "state", session.State)
	return nil
}

func (m *sessionManagerMock) GetSessionByState(state string) (*Session, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	if session, ok := m.sessions[state]; ok {
		return session, nil
	}
	return nil, fmt.Errorf("session with state '%s' not found", state)
}

func (m *sessionManagerMock) GetSessionByID(id string) (*Session, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()
	for _, session := range m.sessions {
		if session.ID == id {
			return session, nil
		}
	}
	return nil, fmt.Errorf("session with id '%s' not found", id)
}

func (m *sessionManagerMock) DeleteSessionByID(id string) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	for state, session := range m.sessions {
		if session.ID == id {
			delete(m.sessions, state)
			slog.Info("session deleted", "id", session.ID, "state", session.State)
			return nil
		}
	}
	return fmt.Errorf("session with id '%s' not found", id)
}
