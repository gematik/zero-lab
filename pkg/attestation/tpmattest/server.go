package tpmattest

import (
	"bytes"
	"crypto"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/go-attestation/attest"
	"github.com/segmentio/ksuid"
)

type AttestationSession struct {
	ID                   string
	Secret               []byte
	EndorsementKey       EndorsementKey
	AttestationKey       crypto.PublicKey
	AttestationChallenge AttestationChallenge
}

type mockAttestationStore struct {
	sessions map[string]AttestationSession
	lock     sync.RWMutex
}

func (s *mockAttestationStore) SaveSession(session AttestationSession) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.sessions[session.ID] = session
	return nil
}

func (s *mockAttestationStore) LoadSession(id string) (*AttestationSession, error) {
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
			sessions: make(map[string]AttestationSession),
		},
	}
}

func (a *Server) NewActivationSession(ar *AttestationRequest) (*AttestationSession, error) {
	ek, err := ar.ConvertEK()
	if err != nil {
		return nil, fmt.Errorf("parsing EK certificate: %w", err)
	}

	slog.Info("Received attestation request", "ek", ek)

	params := attest.ActivationParameters{
		TPMVersion: ar.TPMVersion(),
		EK:         ek.Public,
		AK:         ar.ConvertParameters(),
	}

	secret, encryptedCredential, err := params.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating activation challenge: %w", err)
	}
	id := ksuid.New().String()
	session := AttestationSession{
		ID:             id,
		Secret:         secret,
		EndorsementKey: ar.EndorsementKey,
		AttestationKey: params.AK.Public,
		AttestationChallenge: AttestationChallenge{
			ID:         id,
			Credential: encryptedCredential.Credential,
			Secret:     encryptedCredential.Secret,
			Status:     ChallengeStatusPending,
		},
	}

	slog.Info("Created new activation session", "id", session.ID)

	a.store.SaveSession(session)

	return &session, nil
}

func (a *Server) VerifyChallengeResponse(session *AttestationSession, cr AttestationChallengeResponse) error {
	if bytes.Equal(session.Secret, cr.DecryptedSecret) {
		session.AttestationChallenge.Status = ChallengeStatusValid
	} else {
		session.AttestationChallenge.Status = ChallengeStatusInvalid
	}
	a.store.SaveSession(*session)
	slog.Info("Challenge response verified", "status", session.AttestationChallenge.Status)
	return nil
}
