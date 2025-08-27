package cmd

import (
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	proxyCmd.Flags().StringP("addr", "a", ":8082", "Address to listen on")
	viper.BindPFlag("addr", proxyCmd.Flags().Lookup("addr"))

	rootCmd.AddCommand(proxyCmd)
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run ePA Client as Proxy",
	Run: func(cmd *cobra.Command, args []string) {
		env, err := epa.EnvFromString(viper.GetString("env"))
		cobra.CheckErr(err)

		proxy, err := createProxy(env)
		cobra.CheckErr(err)

		e := echo.New()
		e.Use(middleware.Recover())

		e.Any("/*", echo.WrapHandler(proxy))

		addr := viper.GetString("addr")
		slog.Info(fmt.Sprintf("starting Proxy at %s", addr))

		log.Fatal(e.Start(addr))

	},
}

func createSecurityFunctions() epa.SecurityFunctions {

	provideHCV := func(insurantId string) ([]byte, error) {
		return epa.CalculateHCV("19981123", "Berliner Straße")
	}

	vsdmHMACKey := viper.GetString("vsdm-hmac-key")
	vsdmHMACKeyID := viper.GetString("vsdm-hmac-kid")
	slog.Debug("Using VSDM HMAC Key", "key", "***", "kid", vsdmHMACKeyID)
	proofOfAuditEvidenceFunc, err := epa.CalculatePNv2(
		vsdmHMACKey,
		vsdmHMACKeyID,
		provideHCV,
	)
	if err != nil {
		log.Fatalf("Failed to create ProofOfAuditEvidenceFunc: %v", err)
	}

	// read the private key and certificate for SMC-B
	authnCertPath := viper.GetString("authn-cert-path")
	authnPrivateKeyPath := viper.GetString("authn-private-key-path")
	slog.Debug("Reading SMC-B private key and certificate", "private_key_path", authnPrivateKeyPath, "cert_path", authnCertPath)

	// read certificate pem bytes
	certData, err := os.ReadFile(authnCertPath)
	if err != nil {
		log.Fatalf("Failed to read SMC-B certificate: %v", err)
	}

	// parse certificate
	cert, err := brainpool.ParseCertificatePEM(certData)
	if err != nil {
		log.Fatalf("Failed to parse SMC-B certificate: %v", err)
	}

	slog.Info("Successfully read SMC-B certificate", "subject", cert.Subject.CommonName, "alg", cert.PublicKeyAlgorithm.String())

	// read private key pem bytes
	prkData, err := os.ReadFile(authnPrivateKeyPath)
	if err != nil {
		log.Fatalf("Failed to read SMC-B private key: %v", err)
	}
	// parse private key
	prk, err := brainpool.ParsePrivateKeyPEM(prkData)
	if err != nil {
		log.Fatalf("Failed to parse SMC-B private key: %v", err)
	}

	return epa.SecurityFunctions{
		AuthnSignFunc:           brainpool.SignFuncPrivateKey(prk),
		AuthnCertFunc:           func() (*x509.Certificate, error) { return cert, nil },
		ClientAssertionSignFunc: brainpool.SignFuncPrivateKey(prk),
		ClientAssertionCertFunc: func() (*x509.Certificate, error) { return cert, nil },
		ProvidePN:               proofOfAuditEvidenceFunc,
		ProvideHCV:              provideHCV,
	}

}

func createProxy(env epa.Env) (*epa.Proxy, error) {

	timeout := viper.GetDuration("timeout")

	return epa.NewProxy(&epa.ProxyConfig{
		Env:               env,
		SecurityFunctions: createSecurityFunctions(),
		Timeout:           timeout,
	})

}
