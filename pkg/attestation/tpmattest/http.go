package tpmattest

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (a *Server) MountRoutes(group *echo.Group) {
	subgroup := group.Group("/attestations")
	subgroup.POST("", a.PostAttestations)
	subgroup.POST("/:id", a.PostChallengeResponse)
}

func (a *Server) PostAttestations(c echo.Context) error {
	var ar = new(AttestationRequest)
	if err := c.Bind(ar); err != nil {
		return err
	}

	if err := c.Validate(ar); err != nil {
		return err
	}

	slog.Info("Activation request", "activation_reuzest", ar)

	session, err := a.NewActivationSession(ar)
	if err != nil {
		slog.Error("creating activation session", "error", err)
		return err
	}

	baseURL := fmt.Sprintf("%s://%s", c.Scheme(), c.Request().Host)

	c.Response().Header().Set("Location", fmt.Sprintf("%s/activations/%s", baseURL, session.ID))

	return c.JSON(http.StatusCreated, session.AttestationChallenge)
}

func (a *Server) PostChallengeResponse(c echo.Context) error {
	id := c.Param("id")

	session, err := a.store.LoadSession(id)
	if err != nil {
		return c.String(http.StatusNotFound, "Session not found")
	}

	var cr AttestationChallengeResponse
	if err := c.Bind(&cr); err != nil {
		return err
	}

	err = a.VerifyChallengeResponse(session, cr)
	if err != nil {
		return c.String(http.StatusUnauthorized, "Challenge response verification failed")
	}

	slog.Info("Challenge response", "params", cr)

	return c.JSON(http.StatusOK, session.AttestationChallenge)
}
