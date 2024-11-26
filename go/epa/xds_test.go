package epa_test

import (
	"crypto/x509"
	"log/slog"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/libzero/prettylog"
)

func TestXDS(t *testing.T) {

	for _, testRecord := range testRecords {
		t.Run(testRecord.insurantId, func(t *testing.T) {
			providerNumber := testRecord.providerNumber
			//insurantId := testRecord.insurantId

			testKey, _ := brainpool.ParsePrivateKeyPEM(testKeyBytes)
			testCert, _ := brainpool.ParseCertificatePEM(testCertBytes)

			logger := slog.New(prettylog.NewHandler(slog.LevelDebug))
			slog.SetDefault(logger)

			session, err := epa.OpenSession(
				epa.EnvDev,
				providerNumber,
				epa.SecurityFunctions{
					AuthnSignFunc:            brainpool.SignFuncPrivateKey(testKey),
					AuthnCertFunc:            func() (*x509.Certificate, error) { return testCert, nil },
					ClientAssertionSignFunc:  brainpool.SignFuncPrivateKey(testKey),
					ClientAssertionCertFunc:  func() (*x509.Certificate, error) { return testCert, nil },
					ProofOfAuditEvidenceFunc: EnvProofOfAuditEvidenceFunc,
				},
				epa.WithInsecureSkipVerify(),
			)
			if err != nil {
				t.Fatalf("Connect returned an error: %v", err)
			}

			err = session.Authorize()
			if err != nil {
				t.Fatalf("Authorize returned an error: %v", err)
			}

		})
	}
}
