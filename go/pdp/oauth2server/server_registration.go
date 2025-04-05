package oauth2server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// Implements https://datatracker.ietf.org/doc/html/rfc7591
func (s *Server) RegistrationEndpoint(c echo.Context) error {
	if c.Request().Header.Get("Content-Type") != "application/json" {
		return &Error{
			HttpStatus:  http.StatusUnsupportedMediaType,
			Code:        "unsupported_media_type",
			Description: "content type must be application/json",
		}
	}

	return &Error{
		HttpStatus:  http.StatusNotImplemented,
		Code:        "not_implemented",
		Description: "registration endpoint is not implemented",
	}
}
