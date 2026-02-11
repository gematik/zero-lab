package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
	"github.com/spf13/cobra"
)

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// subjectCN extracts the CommonName from a certificate subject.
// Falls back to searching Names for multi-valued RDN subjects
// where Go's pkix.Name doesn't populate CommonName.
func subjectCN(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(oidCommonName) {
			if s, ok := name.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func newDescribeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "describe",
		Short: "Describe a resource in detail",
	}

	cmd.AddCommand(newDescribeCertificateCmd())

	return cmd
}

func newDescribeCertificateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "certificate <card-handle> <cert-ref>",
		Short: "Show detailed certificate information",
		Long:  "Show detailed certificate information.\nCert refs: C.AUT, C.ENC, C.SIG, C.QES",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadDotkon()
			if err != nil {
				return err
			}
			certRef := certificateservicecommon20.CertRefEnum(args[1])
			if !certRef.IsValid() {
				return fmt.Errorf("invalid cert ref: %s", args[1])
			}
			return runDescribeCertificate(cmd.Context(), config, args[0], certRef)
		},
	}
}

func runDescribeCertificate(ctx context.Context, config *kon.Dotkon, cardHandle string, certRef certificateservicecommon20.CertRefEnum) error {
	client, err := loadClient(config)
	if err != nil {
		return err
	}

	certs, err := client.ReadCardCertificates(ctx, cardHandle, certRef)
	if err != nil {
		return err
	}

	if len(certs) == 0 {
		return fmt.Errorf("certificate %s not found on card %s", certRef, cardHandle)
	}

	c := certs[0]

	if outputFlag == "json" {
		return printJSON(c)
	}

	return printKeyValue(func(w io.Writer) {
		fmt.Fprintf(w, "Cert Ref\t%s\n", c.CertRef)
		fmt.Fprintf(w, "Subject\t%s\n", c.X509.Subject)
		fmt.Fprintf(w, "Subject CN\t%s\n", subjectCN(c.X509))
		fmt.Fprintf(w, "Issuer\t%s\n", c.X509.Issuer)
		fmt.Fprintf(w, "Issuer CN\t%s\n", c.X509.Issuer.CommonName)
		fmt.Fprintf(w, "Serial\t%s\n", c.X509.SerialNumber)
		fmt.Fprintf(w, "Not Before\t%s\n", c.X509.NotBefore.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(w, "Not After\t%s\n", c.X509.NotAfter.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(w, "Key Algorithm\t%s\n", c.X509.PublicKeyAlgorithm)
		if c.X509.PublicKey != nil {
			fmt.Fprintf(w, "Key Size\t%s\n", describePublicKey(c.X509.PublicKey))
		}
		fmt.Fprintf(w, "Signature Algorithm\t%s\n", c.X509.SignatureAlgorithm)
		if len(c.X509.DNSNames) > 0 {
			fmt.Fprintf(w, "DNS Names\t%s\n", strings.Join(c.X509.DNSNames, ", "))
		}
		if len(c.X509.EmailAddresses) > 0 {
			fmt.Fprintf(w, "Email\t%s\n", strings.Join(c.X509.EmailAddresses, ", "))
		}
		fmt.Fprintf(w, "Is CA\t%v\n", c.X509.IsCA)
		if c.X509.KeyUsage != 0 {
			fmt.Fprintf(w, "Key Usage\t%s\n", formatKeyUsage(c.X509.KeyUsage))
		}
		if len(c.X509.ExtKeyUsage) > 0 {
			fmt.Fprintf(w, "Ext Key Usage\t%s\n", formatExtKeyUsage(c.X509.ExtKeyUsage))
		}
		if len(c.X509.SubjectKeyId) > 0 {
			fmt.Fprintf(w, "Subject Key ID\t%s\n", hex.EncodeToString(c.X509.SubjectKeyId))
		}
		if len(c.X509.AuthorityKeyId) > 0 {
			fmt.Fprintf(w, "Authority Key ID\t%s\n", hex.EncodeToString(c.X509.AuthorityKeyId))
		}
	})
}

var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "DigitalSignature"},
	{x509.KeyUsageContentCommitment, "ContentCommitment"},
	{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
	{x509.KeyUsageDataEncipherment, "DataEncipherment"},
	{x509.KeyUsageKeyAgreement, "KeyAgreement"},
	{x509.KeyUsageCertSign, "CertSign"},
	{x509.KeyUsageCRLSign, "CRLSign"},
	{x509.KeyUsageEncipherOnly, "EncipherOnly"},
	{x509.KeyUsageDecipherOnly, "DecipherOnly"},
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var names []string
	for _, u := range keyUsageNames {
		if ku&u.bit != 0 {
			names = append(names, u.name)
		}
	}
	return strings.Join(names, ", ")
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "ServerAuth",
	x509.ExtKeyUsageClientAuth:                 "ClientAuth",
	x509.ExtKeyUsageCodeSigning:                "CodeSigning",
	x509.ExtKeyUsageEmailProtection:            "EmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                "IPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSECUser",
	x509.ExtKeyUsageTimeStamping:               "TimeStamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "MicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "NetscapeServerGatedCrypto",
}

func formatExtKeyUsage(usages []x509.ExtKeyUsage) string {
	names := make([]string, len(usages))
	for i, u := range usages {
		if name, ok := extKeyUsageNames[u]; ok {
			names[i] = name
		} else {
			names[i] = fmt.Sprintf("Unknown(%d)", u)
		}
	}
	return strings.Join(names, ", ")
}
