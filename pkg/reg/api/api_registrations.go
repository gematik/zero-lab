package api

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/pkg/reg"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/labstack/echo/v4"
)

func (r *RegistrationAPI) newRegistration(c echo.Context) error {
	message := c.Get("message").(*VerifiedMessage)

	fullUrl := fmt.Sprintf("%s://%s%s", c.Scheme(), c.Request().Host, c.Request().RequestURI)

	input, err := anyToStruct[RegistrationRequest](message.Payload)
	if err != nil {
		slog.Error("decode error", "err", err, "input", string(message.Payload))
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	clientJwk := &util.Jwk{Key: message.Jwk}

	registration := &reg.RegistrationEntity{
		Name:        input.Name,
		Jwk:         clientJwk,
		Attestation: message.Attestation,
		Csr:         input.Csr,
	}

	registration, err = r.regService.CreateRegistration(registration)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	c.Response().Header().Set("Location", fullUrl+"/"+registration.ID)
	return c.JSON(http.StatusCreated, toRegistrationOutput(registration))
}

func (r *RegistrationAPI) getRegistration(c echo.Context) error {
	id := c.Param("id")
	message := c.Get("message").(*VerifiedMessage)

	tumbprintB, err := message.Jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	thumbprint := base64.RawURLEncoding.EncodeToString(tumbprintB)

	registration, err := r.regService.GetRegistration(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err)
	}

	if registration.JwkThumbprint != thumbprint {
		slog.Error("thumbprint mismatch", "actual", registration.JwkThumbprint, "expected", thumbprint)
		return echo.NewHTTPError(http.StatusNotFound, "Not found")
	}

	return c.JSON(http.StatusOK, toRegistrationOutput(registration))
}

func toRegistrationOutput(registration *reg.RegistrationEntity) *RegistrationResponse {
	challenges := make([]*RegistrationChallenge, len(registration.Challenges))
	for i, challenge := range registration.Challenges {
		challengesOutput := RegistrationChallenge(*challenge)
		challenges[i] = &challengesOutput
	}
	registrationOutput := RegistrationResponse{
		ID:                registration.ID,
		Status:            registration.Status,
		Challenges:        challenges,
		ClientID:          registration.ClientID,
		ClientCertificate: registration.ClientCertificate,
	}
	return &registrationOutput
}
