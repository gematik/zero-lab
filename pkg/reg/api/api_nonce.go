package api

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (r *RegistrationAPI) newNonce(c echo.Context) error {
	nonce, err := r.regService.NonceService.Get()
	if err != nil {
		slog.Error("Unable to get nonce", "error", err)
		return echo.NewHTTPError(500, "Unable to get nonce")
	}
	c.Response().Header().Set("Replay-Nonce", nonce)
	c.Response().WriteHeader(http.StatusCreated)
	return nil
}
