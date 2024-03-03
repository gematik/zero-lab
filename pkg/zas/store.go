package zas

import "errors"

type SessionStore interface {
	GetSession(state string) (*AuthorizationSession, error)
	GetSessionByOPState(opState string) (*AuthorizationSession, error)
	GetSessionByRequestUri(requestUri string) (*AuthorizationSession, error)
	GetSessionByCode(code string) (*AuthorizationSession, error)
	SaveSession(session *AuthorizationSession) error
	DeleteSession(state string) error
}

type mockSessionStore struct {
	sessions map[string]*AuthorizationSession
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*AuthorizationSession),
	}
}

func (s *mockSessionStore) GetSession(state string) (*AuthorizationSession, error) {
	session, ok := s.sessions[state]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func (s *mockSessionStore) SaveSession(session *AuthorizationSession) error {
	s.sessions[session.State] = session
	return nil
}

func (s *mockSessionStore) DeleteSession(state string) error {
	delete(s.sessions, state)
	return nil
}

func (s *mockSessionStore) GetSessionByRequestUri(requestUri string) (*AuthorizationSession, error) {
	for _, session := range s.sessions {
		if session.RequestUri == requestUri {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetSessionByOPState(opState string) (*AuthorizationSession, error) {
	for _, session := range s.sessions {
		if session.OPSession != nil && session.OPSession.State == opState {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *mockSessionStore) GetSessionByCode(code string) (*AuthorizationSession, error) {
	for _, session := range s.sessions {
		if session.Code == code {
			return session, nil
		}
	}
	return nil, errors.New("session not found")
}
