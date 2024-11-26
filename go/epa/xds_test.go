package epa_test

import (
	"log/slog"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/libzero/gemidp"
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
				epa.WithInsecureSkipVerify(),
				epa.WithTokenSignFunc(brainpool.SignFuncPrivateKey(testKey)),
			)
			if err != nil {
				t.Fatalf("Connect returned an error: %v", err)
			}

			// TODO
			session.AttestCertificate = testCert
			session.ProofOfAuditEvidenceFunc = epa.TestProofOfAuditEvidenceFunc

			clientAttest, err := session.CreateClientAttest()
			if err != nil {
				t.Fatalf("CreateClientAttest returned an error: %v", err)
			}

			authz_uri, err := session.SendAuthorizationRequestSC()
			if err != nil {
				t.Fatalf("SendAuthorizationRequestSC returned an error: %v", err)
			}

			t.Logf("Authorization URI: %v", authz_uri)

			authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
				Environment: gemidp.EnvironmentReference,
				SignerFunc:  gemidp.SignWithSoftkey(testKey, testCert),
			})

			codeRedirectURL, err := authenticator.Authenticate(authz_uri)
			if err != nil {
				t.Fatalf("Authenticate returned an error: %v", err)
			}
			t.Logf("CodeRedirectURL: %v", codeRedirectURL)

			err = session.SendAuthCodeSC(epa.SendAuthCodeSCtype{
				AuthorizationCode: codeRedirectURL.Code,
				ClientAttest:      clientAttest,
			})
			if err != nil {
				t.Fatalf("SendAuthCodeSC returned an error: %v", err)
			}

			slog.Info("Session established", "session", session)

		})
	}
}
