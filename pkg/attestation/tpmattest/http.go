package tpmattest

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gematik/zero-lab/pkg/attestation/tpmattest/tpmtypes"
	"github.com/labstack/echo/v4"
	"github.com/segmentio/ksuid"
)

type ActivationSession struct {
	ID        string `json:"id"`
	Challenge string `json:"challenge"`
}
type mockAttestationStore struct {
	sessions map[string]ActivationSession
	lock     sync.RWMutex
}

func (s *mockAttestationStore) NewSession() ActivationSession {
	s.lock.Lock()
	defer s.lock.Unlock()

	session := ActivationSession{
		ID:        ksuid.New().String(),
		Challenge: ksuid.New().String(),
	}

	s.sessions[session.ID] = session
	return session
}

func (s *mockAttestationStore) SaveSession(session ActivationSession) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.sessions[session.ID] = session
}

type TPMAttestor struct {
	store mockAttestationStore
}

func NewTPMAttestor() *TPMAttestor {
	return &TPMAttestor{
		store: mockAttestationStore{
			sessions: make(map[string]ActivationSession),
		},
	}
}

func (a *TPMAttestor) MountRoutes(group *echo.Group) {
	subgroup := group.Group("/activations")
	subgroup.POST("", a.NewActivationSession)
}

func (a *TPMAttestor) NewActivationSession(c echo.Context) error {
	var ar = new(tpmtypes.ActivationRequest)
	if err := c.Bind(ar); err != nil {
		return err
	}

	if err := c.Validate(ar); err != nil {
		return err
	}

	slog.Info("Activation request", "params", ar)

	session := a.store.NewSession()

	baseURL := fmt.Sprintf("%s://%s", c.Scheme(), c.Request().Host)

	c.Response().Header().Set("Location", fmt.Sprintf("%s/activations/%s", baseURL, session.ID))

	return c.JSON(http.StatusCreated, session)
}
