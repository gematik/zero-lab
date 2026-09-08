package connector

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

func newVerifyCertificateCmd() *cobra.Command {
	var (
		file             string
		crypt            string
		verificationTime string
	)

	cmd := &cobra.Command{
		Use:   "certificate [card-handle-or-telematik-id] [cert-ref]",
		Short: "Verify a certificate against the TI trust space",
		Long: "Verify a certificate against the TI trust space.\n" +
			"The connector validates the certification path and checks revocation status (OCSP).\n\n" +
			"Either name a card and a cert ref, or pass --file with a PEM or DER encoded certificate.\n" +
			"Cert refs: C.AUT, C.ENC, C.SIG, C.QES",
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := common.LoadConnectorConfig()
			if err != nil {
				return err
			}

			cryptType := certificateservice601.CryptType(crypt)
			if !cryptType.IsValid() {
				return fmt.Errorf("invalid crypt type %q, valid values: RSA, ECC", crypt)
			}

			var at time.Time
			if verificationTime != "" {
				at, err = time.Parse(time.RFC3339, verificationTime)
				if err != nil {
					return fmt.Errorf("invalid verification time %q, expected RFC3339: %w", verificationTime, err)
				}
			}

			if file != "" {
				if len(args) > 0 {
					return fmt.Errorf("--file cannot be combined with a card handle")
				}
				return runVerifyCertificateFile(cmd.Context(), config, file, at)
			}

			if len(args) != 2 {
				return fmt.Errorf("expected a card handle and a cert ref, or --file")
			}
			certRef := certificateservicecommon20.CertRefEnum(args[1])
			if !certRef.IsValid() {
				return fmt.Errorf("invalid cert ref: %s", args[1])
			}
			return runVerifyCardCertificate(cmd.Context(), config, args[0], certRef, cryptType, at)
		},
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Verify a certificate from a PEM or DER file instead of a card")
	cmd.Flags().StringVar(&crypt, "crypt", string(certificateservice601.CryptTypeEcc), "Cryptography type of the card certificate (RSA or ECC)")
	cmd.Flags().StringVar(&verificationTime, "time", "", "Verification time in RFC3339 format (default: connector's current time)")
	cmd.RegisterFlagCompletionFunc("crypt", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"RSA", "ECC"}, cobra.ShellCompDirectiveNoFileComp
	})
	common.AddConnectorConfigFlag(cmd)

	return cmd
}

func runVerifyCardCertificate(ctx context.Context, config *kon.Dotkon, identifier string, certRef certificateservicecommon20.CertRefEnum, crypt certificateservice601.CryptType, at time.Time) error {
	client, err := common.LoadClient(config)
	if err != nil {
		return err
	}

	cardHandle, _, err := common.ResolveCardHandle(ctx, client, identifier)
	if err != nil {
		return err
	}

	certs, err := client.ReadCardCertificates(ctx, cardHandle, crypt, certRef)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("certificate %s not found on card %s", certRef, cardHandle)
	}

	return verifyAndPrint(ctx, client, certs[0].X509, at)
}

func runVerifyCertificateFile(ctx context.Context, config *kon.Dotkon, path string, at time.Time) error {
	cert, err := loadCertificateFile(path)
	if err != nil {
		return err
	}

	client, err := common.LoadClient(config)
	if err != nil {
		return err
	}

	return verifyAndPrint(ctx, client, cert, at)
}

// loadCertificateFile reads a single certificate, PEM or bare DER.
func loadCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s: expected a CERTIFICATE PEM block, got %s", path, block.Type)
		}
		der = block.Bytes
	}

	cert, err := brainpool.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate %s: %w", path, err)
	}
	return cert, nil
}

func verifyAndPrint(ctx context.Context, client *kon.Client, cert *x509.Certificate, at time.Time) error {
	spin := startSpinner("Verifying certificate...")
	result, err := client.VerifyCertificate(ctx, cert, at)
	spin.Stop()
	if err != nil {
		return err
	}

	revocation := revocationStatus(result)

	if common.OutputFlag == "json" {
		return common.PrintJSON(struct {
			*kon.CertificateVerification
			Revocation string `json:"revocation"`
		}{result, revocation})
	}

	kv := common.NewKVWriter()
	kv.Section("Verification")
	kv.KV("Subject", cert.Subject.CommonName)
	kv.KV("Issuer", cert.Issuer.CommonName)
	kv.KV("Serial Number", common.ColonHex(cert.SerialNumber.Bytes()))
	kv.KV("Result", verificationResultLabel(result.Result))
	kv.KV("Revocation", revocation)
	if len(result.Roles) > 0 {
		kv.KV("Roles", strings.Join(result.Roles, ", "))
	}
	if result.Error != nil {
		kv.Section("Errors")
		for _, t := range result.Error.Trace {
			kv.KV(fmt.Sprintf("%d %s", t.Code, t.Severity), t.ErrorText)
		}
		kv.EndSection()
	}
	kv.EndSection()

	if err := kv.Print(); err != nil {
		return err
	}

	// A verdict other than VALID is a failed check, not a failed call: exit non-zero
	// so the command composes in scripts.
	if result.Result != certificateservice601.VerificationResultTypeValid {
		return fmt.Errorf("certificate verification result: %s", result.Result)
	}
	return nil
}

func verificationResultLabel(r certificateservice601.VerificationResultType) string {
	switch r {
	case certificateservice601.VerificationResultTypeValid:
		return "✅ VALID"
	case certificateservice601.VerificationResultTypeInvalid:
		return "❌ INVALID"
	case certificateservice601.VerificationResultTypeInconclusive:
		return "⚠️  INCONCLUSIVE"
	default:
		return string(r)
	}
}

// The connector performs the OCSP query inside VerifyCertificate, but the
// operation reports no dedicated revocation field — the outcome only reaches
// the client through the CheckCertificateDetail tokens the connector puts in
// the error trace. Map those back out so the status is stated rather than
// implied by an overall INVALID.
var revocationDetails = []struct {
	token certificateservicecommon20.CheckCertificateDetailEnum
	label string
}{
	{certificateservicecommon20.CheckCertificateDetailEnumCertRevoked, "REVOKED"},
	{certificateservicecommon20.CheckCertificateDetailEnumCertRevokedAfter, "REVOKED after the verification time"},
	{certificateservicecommon20.CheckCertificateDetailEnumCheckRevocationFailed, "check failed (responder unreachable or response unusable)"},
	{certificateservicecommon20.CheckCertificateDetailEnumNoRevocationCheck, "not performed by the connector"},
}

func revocationStatus(v *kon.CertificateVerification) string {
	if v.Error != nil {
		for _, t := range v.Error.Trace {
			text := strings.ToUpper(t.ErrorText)
			for _, d := range revocationDetails {
				if strings.Contains(text, string(d.token)) {
					return d.label
				}
			}
			// Connectors that omit the token still name it in the German text.
			if strings.Contains(text, "GESPERRT") {
				return "REVOKED"
			}
		}
	}
	if v.Result == certificateservice601.VerificationResultTypeValid {
		return "not revoked (checked by connector)"
	}
	return "unknown - see error trace"
}
