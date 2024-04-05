package tpmattest

import (
	"log/slog"

	"github.com/gematik/zero-lab/pkg/attestation/tpmattest/tpmtypes"
)

func Activate(params *tpmtypes.ActivationParameters) {

	tmpParams, err := params.ActivationParameters()
	secret, encryptedCredentials, err := tmpParams.Generate()
	if err != nil {
		// handle error
	}

	slog.Info("Activation", "secret", secret, "encryptedCredentials", encryptedCredentials)
}
