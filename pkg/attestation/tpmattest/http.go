package tpmattest

import (
	"log/slog"

	"github.com/gematik/zero-lab/pkg/attestation/tpmattest/tpmtypes"
	"github.com/labstack/echo/v4"
)

func PostActivationRequest(c echo.Context) error {
	var params tpmtypes.ActivationParameters
	if err := c.Bind(&params); err != nil {
		return err
	}

	slog.Info("Activation request", "params", params)

	return c.JSON(200, "Activation request received")
}
