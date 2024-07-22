package tpmattest

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

func MountActivationRoutes(group *echo.Group, as *ActivationService) {
	subgroup := group.Group("/activations")
	subgroup.POST("", postActivations(as))
	subgroup.POST("/:id", postActivationChallengeResponse(as))
}

func postActivations(as *ActivationService) echo.HandlerFunc {
	return func(c echo.Context) error {

		var ar = new(ActivationRequest)
		if err := c.Bind(ar); err != nil {
			return err
		}

		if err := c.Validate(ar); err != nil {
			return err
		}

		slog.Info("Activation request", "activation_request", ar)

		challenge, err := as.NewChallenge(ar)
		if err != nil {
			slog.Error("creating activation session", "error", err)
			return err
		}

		baseURL := fmt.Sprintf("%s://%s", c.Scheme(), c.Request().Host)

		c.Response().Header().Set("Location", fmt.Sprintf("%s/activations/%s", baseURL, challenge.ID))

		return c.JSON(http.StatusCreated, challenge)
	}
}

func postActivationChallengeResponse(as *ActivationService) echo.HandlerFunc {
	return func(c echo.Context) error {
		id := c.Param("id")

		var cr ActivationChallengeResponse
		if err := c.Bind(&cr); err != nil {
			return err
		}

		slog.Info("Received challenge response", "session", id)

		response, err := as.VerifyChallenge(id, cr)
		if err != nil {
			slog.Error("verifying challenge response", "error", err)
			return c.String(http.StatusUnauthorized, "Challenge response verification failed")
		}

		return c.JSON(http.StatusOK, response)
	}
}
