package tpmattest

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/gematik/zero-lab/pkg/util"
	"github.com/google/go-attestation/attest"
	"github.com/segmentio/ksuid"
)

type ActivationSession struct {
	ID                   string
	Secret               []byte
	AttestationChallenge AttestationChallenge
}

type mockAttestationStore struct {
	sessions map[string]ActivationSession
	lock     sync.RWMutex
}

func (s *mockAttestationStore) SaveSession(session ActivationSession) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.sessions[session.ID] = session
	return nil
}

func (s *mockAttestationStore) LoadSession(id string) (*ActivationSession, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	session, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	return &session, nil
}

type Server struct {
	store mockAttestationStore
}

func NewServer() *Server {
	return &Server{
		store: mockAttestationStore{
			sessions: make(map[string]ActivationSession),
		},
	}
}

func (a *Server) NewActivationSession(ar *AttestationRequest) (*ActivationSession, error) {
	ek, err := ar.ConvertEK()
	if err != nil {
		return nil, fmt.Errorf("parsing EK certificate: %w", err)
	}

	slog.Info("Received attestation request", "ek", util.CertificateToText(ek.Certificate))

	params := attest.ActivationParameters{
		TPMVersion: ar.TPMVersion(),
		EK:         ek.Public,
		AK:         ar.ConvertParameters(),
	}

	secret, encryptedCredential, err := params.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating activation challenge: %w", err)
	}
	session := ActivationSession{
		ID:     ksuid.New().String(),
		Secret: secret,
		AttestationChallenge: AttestationChallenge{
			Credential: encryptedCredential.Credential,
			Secret:     encryptedCredential.Secret,
			Status:     ChallengeStatusPending,
		},
	}

	slog.Info("Created new activation session", "id", session.ID)

	a.store.SaveSession(session)

	return &session, nil
}
