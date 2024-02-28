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
	signedRequest := c.Get("signedRequest").(*signedRequest)

	attestation, err := r.regService.ValidateMessageAttestation(signedRequest.messageRaw, signedRequest.attestationFormat, signedRequest.attestationData, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err)
	}

	fullUrl := fmt.Sprintf("%s://%s%s", c.Scheme(), c.Request().Host, c.Request().RequestURI)

	regReq, err := util.AnyToStruct[RegistrationRequest](signedRequest.message.Payload)
	if err != nil {
		slog.Error("decode error", "err", err, "input", string(signedRequest.message.Payload))
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	clientJwk := &util.Jwk{Key: signedRequest.message.Jwk}

	platform, err := reg.ParseClientPlatform(regReq.Platform)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	registration := &reg.RegistrationEntity{
		Iss: regReq.Iss,
		Client: &reg.ClientEntity{
			Name:        regReq.Name,
			Jwk:         clientJwk,
			Attestation: attestation,
			Platform:    platform,
			Posture:     regReq.Posture,
			Csr:         regReq.Csr,
		},
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
	signedRequest := c.Get("signedRequest").(*signedRequest)

	tumbprintB, err := signedRequest.message.Jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	thumbprint := base64.RawURLEncoding.EncodeToString(tumbprintB)

	registration, err := r.regService.GetRegistration(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err)
	}

	attestation, err := r.regService.ValidateMessageAttestation(signedRequest.messageRaw, signedRequest.attestationFormat, signedRequest.attestationData, registration.Client.Attestation)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err)
	}

	registration.Client.Attestation = attestation

	r.regService.UpdateRegistration(registration)

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
		ClientID:          registration.Client.ID,
		ClientCertificate: registration.Client.Certificate,
	}
	return &registrationOutput
}
