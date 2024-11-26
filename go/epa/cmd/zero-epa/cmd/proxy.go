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

	proxyCmd.Flags().StringP("vsdm-hmac-key", "", "", "VSDM HMAC Key")
	viper.BindPFlag("vsdm-hmac-key", proxyCmd.Flags().Lookup("vsdm-hmac-key"))
	viper.BindEnv("vsdm-hmac-key", "VSDM_HMAC_KEY")

	proxyCmd.Flags().StringP("vsdm-hmac-kid", "", "", "VSDM HMAC Key ID")
	viper.BindPFlag("vsdm-hmac-kid", proxyCmd.Flags().Lookup("vsdm-hmac-kid"))
	viper.BindEnv("vsdm-hmac-kid", "VSDM_HMAC_KID")

	proxyCmd.Flags().StringP("authn-private-key-path", "", "", "Path to SMC-B private key")
	viper.BindPFlag("authn-private-key-path", proxyCmd.Flags().Lookup("authn-private-key-path"))
	viper.BindEnv("authn-private-key-path", "AUTHN_PRIVATE_KEY_PATH")

	proxyCmd.Flags().StringP("authn-cert-path", "", "", "Path to SMC-B certificate")
	viper.BindPFlag("authn-cert-path", proxyCmd.Flags().Lookup("authn-cert-path"))
	viper.BindEnv("authn-cert-path", "AUTHN_CERT_PATH")

	rootCmd.AddCommand(proxyCmd)
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run ePA Client as Proxy",
	Run: func(cmd *cobra.Command, args []string) {

		vsdmHMACKey := viper.GetString("vsdm-hmac-key")
		vsdmHMACKeyID := viper.GetString("vsdm-hmac-kid")
		slog.Info("Using VSDM HMAC Key", "key", vsdmHMACKey, "kid", vsdmHMACKeyID)
		proofOfAuditEvidenceFunc, err := epa.ProofOfAuditEvidenceHMAC(
			vsdmHMACKey,
			vsdmHMACKeyID,
		)
		if err != nil {
			log.Fatalf("Failed to create ProofOfAuditEvidenceFunc: %v", err)
		}

		// read the private key and certificate for SMC-B
		authnCertPath := viper.GetString("authn-cert-path")
		authnPrivateKeyPath := viper.GetString("authn-private-key-path")
		slog.Info("Reading SMC-B private key and certificate", "private_key_path", authnPrivateKeyPath, "cert_path", authnCertPath)

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

		proxy, err := epa.NewProxy(&epa.ProxyConfig{
			Env: epa.EnvDev,
			SecurityFunctions: epa.SecurityFunctions{
				AuthnSignFunc:            brainpool.SignFuncPrivateKey(prk),
				AuthnCertFunc:            func() (*x509.Certificate, error) { return cert, nil },
				ClientAssertionSignFunc:  brainpool.SignFuncPrivateKey(prk),
				ClientAssertionCertFunc:  func() (*x509.Certificate, error) { return cert, nil },
				ProofOfAuditEvidenceFunc: proofOfAuditEvidenceFunc,
			},
		})
		if err != nil {
			log.Fatalf("Failed to create Proxy: %v", err)
		}
		e := echo.New()
		e.Use(middleware.Recover())

		e.Any("/*", echo.WrapHandler(proxy))

		addr := viper.GetString("addr")
		slog.Info(fmt.Sprintf("starting Proxy at %s", addr))

		log.Fatal(e.Start(addr))

	},
}
