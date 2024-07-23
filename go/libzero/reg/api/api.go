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

type signedRequest struct {
	message           *verifiedMessage
	messageRaw        []byte
	attestationFormat reg.AttestationFormat
	attestationData   []byte
}

func (r *RegistrationAPI) parseSignedRequest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var err error
		if c.Request().Header.Get("Content-Type") != echo.MIMEApplicationForm {
			return echo.NewHTTPError(http.StatusBadRequest, "unsupported content type")
		}
		var messageStr string
		var dataStr string
		var formatStr string
		binderr := echo.FormFieldBinder(c).
			MustString("message", &messageStr).
			MustString("attestation_format", &formatStr).
			String("attestation_data", &dataStr).
			BindError()
		if binderr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, binderr)
		}
		messageRaw := []byte(messageStr)
		attestationFormat, err := reg.ParseAttestationFormat(formatStr)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}
		attestationData, err := base64.RawURLEncoding.DecodeString(dataStr)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}
		message, err := parseSignedMessage(messageRaw, r.regService.NonceService.Redeem)
		if err != nil {
			slog.Error("parse error", "err", err)
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}

		if err != nil {
			slog.Error("parse error", "err", err)
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}

		signedRequest := &signedRequest{
			message:           message,
			messageRaw:        []byte(messageStr),
			attestationFormat: attestationFormat,
			attestationData:   attestationData,
		}

		c.Set("signedRequest", signedRequest)
		return next(c)
	}
}
