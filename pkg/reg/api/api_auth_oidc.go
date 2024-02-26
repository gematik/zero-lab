package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
)

func (r *RegistrationAPI) authCallbackOidc(c echo.Context) error {
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	client, err := r.regService.AuthCallbackOidc(state, code)
	if err != nil {
		slog.Error("auth callback error", "err", err)
		return echo.NewHTTPError(http.StatusForbidden, err)
	}

	redirect_url, err := url.Parse("x-zero-auth:")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	if client == nil {
		q := url.Values{}
		q.Add("error", "registration_pending")
		redirect_url.RawQuery = q.Encode()
		return echo.NewHTTPError(http.StatusForbidden, "no client")
	}

	clientURL := fmt.Sprintf("%s://%s%s", c.Scheme(), c.Request().Host, "/reg/clients/"+client.ID)

	q := url.Values{}
	q.Add("client_url", clientURL)
	redirect_url.RawQuery = q.Encode()

	return c.Redirect(http.StatusFound, redirect_url.String())
}
