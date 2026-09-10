package pki

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

// newPKIVerifyAutoCmd is `ti pki verify` — same validation as `ti pki <env>
// verify`, with the environment worked out from the certificate.
func newPKIVerifyAutoCmd() *cobra.Command {
	var vf verifyFlags
	cmd := &cobra.Command{
		Use:   "verify FILE|-",
		Short: "Detect the environment, then build a chain and validate",
		Long: "Validate a certificate against the gematik TI roots of the environment it\n" +
			"belongs to, detected from the certificate itself.\n\n" +
			"Detection distinguishes production from the test environments only: dev and\n" +
			"ref are one trust domain, and ref and test publish the same roots. A non-prod\n" +
			"certificate is therefore validated against ref; pass `ti pki test verify` when\n" +
			"the certificate belongs to test.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, opts, err := vf.parse()
			if err != nil {
				return err
			}
			certs, err := loadCertChain(args[0])
			if err != nil {
				return err
			}
			det := gempki.DetectTrustDomain(certs)
			envName, err := envForTrustDomain(det, certs[0])
			if err != nil {
				return err
			}
			def, err := common.ResolveEnv(envName)
			if err != nil {
				return err
			}
			slog.Debug("ti: environment auto-detected",
				"subject", certs[0].Subject.CommonName,
				"env", envName,
				"trustDomain", string(det.Domain),
				"method", string(det.Method),
				"detail", det.Detail)
			opts.detectedEnvName = envName
			opts.detection = &det
			return runCertVerify(cmd.Context(), def, certs, f, opts)
		},
	}
	vf.register(cmd)
	return cmd
}

// envForTrustDomain maps a detected trust domain onto the environment whose
// roots and TSL to validate against. Non-prod resolves to ref, which is also
// dev; a test-environment certificate needs `ti pki test verify` and will fail
// the chain build here, visibly, rather than being quietly mis-validated.
func envForTrustDomain(det gempki.TrustDomainResult, leaf *x509.Certificate) (string, error) {
	switch det.Domain {
	case gempki.TrustDomainProd:
		return "prod", nil
	case gempki.TrustDomainNonProd:
		return "ref", nil
	default:
		return "", undetectableEnvError(det, leaf)
	}
}

// undetectableEnvError explains what was tried and how to get a verdict anyway.
// The trace comes from the detection itself, so it can never claim a step that
// did not run.
func undetectableEnvError(det gempki.TrustDomainResult, leaf *x509.Certificate) error {
	var b strings.Builder
	b.WriteString("cannot determine the TI environment for this certificate\n\n")
	fmt.Fprintf(&b, "  subject  %s\n", leaf.Subject)
	fmt.Fprintf(&b, "  issuer   %s\n\n", leaf.Issuer)
	b.WriteString("  tried:\n")
	for _, s := range det.Steps {
		fmt.Fprintf(&b, "    %-14s %s\n", s.Method, s.Outcome)
	}
	b.WriteString("\nName the environment explicitly:\n")
	b.WriteString("  ti pki ref verify FILE      (also covers dev)\n")
	b.WriteString("  ti pki test verify FILE\n")
	b.WriteString("  ti pki prod verify FILE\n\n")
	b.WriteString("Or append the issuing CA so the chain can be built offline:\n")
	b.WriteString("  ti pki ref tsl intermediates --format pem > subca.pem\n")
	b.WriteString("  cat cert.pem subca.pem | ti pki verify -")
	return fmt.Errorf("%s", b.String())
}
