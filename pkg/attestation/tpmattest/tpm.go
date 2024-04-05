package tpmattest

import (
	"github.com/gematik/zero-lab/pkg/attestation/tpmattest/tpmtypes"
)

func Activate(ar *tpmtypes.ActivationRequest) {
	/*
		tmpParams, err := ar.ActivationParameters()
		secret, encryptedCredentials, err := tmpParams.Generate()
		if err != nil {
			// handle error
		}

		slog.Info("Activation", "secret", secret, "encryptedCredentials", encryptedCredentials)
	*/
}
