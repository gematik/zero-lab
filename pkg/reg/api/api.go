package api

import (
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/pkg/reg"
	"github.com/labstack/echo/v4"
)

type RegistrationAPI struct {
	regService *reg.RegistrationService
}

func NewRegistrationAPI(regService *reg.RegistrationService) (*RegistrationAPI, error) {
	return &RegistrationAPI{
		regService: regService,
	}, nil
}

func (r *RegistrationAPI) MountRoutes(group *echo.Group) {
	group.HEAD("/nonce", r.newNonce)
	group.POST("/registrations", r.newRegistration, r.parseSignedRequest)
	group.POST("/registrations/:id", r.getRegistration, r.parseSignedRequest)
	group.GET("/auth/oidc/callback", r.authCallbackOidc)
	//group.GET("/auth/oidf/device", r.authDeviceCode(), r.regService.)
	//group.GET("/clients/:id")
	//group.POST("/clients/:id/issue-cert")
}

// middleware to parse the JWS signed messages
func (r *RegistrationAPI) parseSignedRequest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var err error
		var attestation *reg.AttestationEntity
		if c.Request().Header.Get("Content-Type") != echo.MIMEApplicationForm {
			return echo.NewHTTPError(http.StatusBadRequest, "unsupported content type")
		}
		messageStr := c.FormValue("message")
		var dataStr string
		var formatStr string
		var data []byte
		binderr := echo.FormFieldBinder(c).
			MustString("message", &messageStr).
			MustString("attestation_format", &formatStr).
			String("attestation_data", &dataStr).
			BindError()
		if binderr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, binderr)
		}
		format, err := reg.ParseAttestationFormat(formatStr)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}
		data, err = base64.RawURLEncoding.DecodeString(dataStr)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}
		attestation, err = r.regService.ValidateMessageAttestation([]byte(messageStr), format, data, nil)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}

		slog.Info("attestation is valid", "format", attestation.Format)

		message, err := ParseSignedMessage([]byte(messageStr), r.regService.NonceService.Redeem)
		if err != nil {
			slog.Error("parse error", "err", err)
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}

		message.Attestation = attestation

		if err != nil {
			slog.Error("parse error", "err", err)
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}

		c.Set("message", message)
		return next(c)
	}
}
