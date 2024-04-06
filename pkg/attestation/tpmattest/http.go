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
}

func (a *Server) PostAttestations(c echo.Context) error {
	var ar = new(AttestationRequest)
	if err := c.Bind(ar); err != nil {
		return err
	}

	if err := c.Validate(ar); err != nil {
		return err
	}

	slog.Info("Activation request", "params", ar)

	session, err := a.NewActivationSession(ar)
	if err != nil {
		slog.Error("Failed to create activation session", "error", err)
		return err
	}

	baseURL := fmt.Sprintf("%s://%s", c.Scheme(), c.Request().Host)

	c.Response().Header().Set("Location", fmt.Sprintf("%s/activations/%s", baseURL, session.ID))

	return c.JSON(http.StatusCreated, session.AttestationChallenge)
}
