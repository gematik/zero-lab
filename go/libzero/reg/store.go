package reg

import (
	"fmt"
	"log/slog"

	"github.com/segmentio/ksuid"
)

type RegistrationStore interface {
	UpsertRegistration(*RegistrationEntity) error
	UpsertAuthSession(*AuthSessionEntity) error
	PopAuthSession(state string) (*AuthSessionEntity, error)
	UpsertAccount(*AccountEntity) error
	GetRegistration(id string) (*RegistrationEntity, error)
	FindRegistrationByThumbprint(thumbprint string) (*RegistrationEntity, error)
	UpsertClient(*ClientEntity) error
	GetClient(id string) (*ClientEntity, error)
}

type MockRegistrationStore struct {
	registrations map[string]*RegistrationEntity
	authSessions  map[string]*AuthSessionEntity
	accounts      map[string]*AccountEntity
	clients       map[string]*ClientEntity
}

func NewMockRegistrationStore() *MockRegistrationStore {
	return &MockRegistrationStore{
		registrations: make(map[string]*RegistrationEntity),
		authSessions:  make(map[string]*AuthSessionEntity),
		accounts:      make(map[string]*AccountEntity),
		clients:       make(map[string]*ClientEntity),
	}
}

func (s *MockRegistrationStore) UpsertRegistration(r *RegistrationEntity) error {
	s.registrations[r.ID] = r
	return nil
}

func (s *MockRegistrationStore) UpsertAuthSession(a *AuthSessionEntity) error {
	s.authSessions[a.State] = a
	return nil
}

func (s *MockRegistrationStore) PopAuthSession(state string) (*AuthSessionEntity, error) {
	a, ok := s.authSessions[state]
	if !ok {
		return nil, fmt.Errorf("no such session")
	}
	delete(s.authSessions, state)
	return a, nil
}

func (s *MockRegistrationStore) UpsertAccount(account *AccountEntity) error {
	if _, ok := s.accounts[account.ID]; ok {
		s.accounts[account.ID] = account
		return nil
	}

	// try to find using issuer and subject
	for _, a := range s.accounts {
		if a.Issuer == account.Issuer && a.Subject == account.Subject {
			slog.Info("found existing account", "id", a.ID, "subject", a.Subject, "issuer", a.Issuer)
			s.accounts[a.ID] = account
			return nil
		}
	}

	// very new account
	account.ID = ksuid.New().String()
	s.accounts[account.ID] = account
	slog.Info("created new account", "id", account.ID, "subject", account.Subject, "issuer", account.Issuer)
	return nil
}

func (s *MockRegistrationStore) GetRegistration(id string) (*RegistrationEntity, error) {
	r, ok := s.registrations[id]
	if !ok {
		return nil, fmt.Errorf("no such registration")
	}
	return r, nil
}

func (s *MockRegistrationStore) UpsertClient(client *ClientEntity) error {
	s.clients[client.ID] = client
	return nil
}

func (s *MockRegistrationStore) GetClient(id string) (*ClientEntity, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, fmt.Errorf("no such client")
	}
	return c, nil
}

func (s *MockRegistrationStore) FindRegistrationByThumbprint(thumbprint string) (*RegistrationEntity, error) {
	for _, r := range s.registrations {
		if r.JwkThumbprint == thumbprint {
			return r, nil
		}
	}
	return nil, nil
}
