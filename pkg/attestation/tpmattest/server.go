package tpmattest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"

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
	// choose the correct EK based from the request
	// prefer the ECC over RSA
	// if there are multiple ECC keys, prefer the one with the highest curve
	var attestationEK *attest.EK
	for _, e := range ar.EndorsementKeys {
		ek, err := e.convert()
		if err != nil {
			return nil, fmt.Errorf("parsing EK certificate: %w", err)
		}

		slog.Info("Processing EK", "serial", ek.Certificate.SerialNumber.String(), "public_key_algorithm", ek.Certificate.PublicKeyAlgorithm)
		if attestationEK == nil {
			attestationEK = ek
			continue
		}

		if ek.Certificate.PublicKeyAlgorithm == x509.ECDSA {
			bitSize := ek.Certificate.PublicKey.(*ecdsa.PublicKey).Curve.Params().BitSize
			if attestationEK.Certificate.PublicKeyAlgorithm != x509.ECDSA {
				attestationEK = ek
				slog.Info("Found ECC EK", "serial", ek.Certificate.SerialNumber.String(), "bit_size", bitSize)
			} else if attestationEK.Certificate.PublicKeyAlgorithm == x509.ECDSA &&
				bitSize > attestationEK.Certificate.PublicKey.(*ecdsa.PublicKey).Curve.Params().BitSize {
				attestationEK = ek
				slog.Info("Found higher bit ECC EK", "serial", ek.Certificate.SerialNumber.String(), "bit_size", bitSize)
			}
		}
	}

	if attestationEK == nil {
		return nil, fmt.Errorf("no EK found")
	}

	params := attest.ActivationParameters{
		TPMVersion: ar.TPMVersion(),
		EK:         attestationEK.Public,
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

	slog.Info("Created new activation session", "id", session.ID, "ek_serial", session.AttestationChallenge.EKSerialNumber)

	a.store.SaveSession(session)

	return &session, nil
}
