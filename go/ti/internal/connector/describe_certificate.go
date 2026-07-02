package connector

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

func newDescribeCertificateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate <card-handle> <cert-ref>",
		Short: "Show detailed certificate information",
		Long:  "Show detailed certificate information.\nCert refs: C.AUT, C.ENC, C.SIG, C.QES",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := common.LoadConnectorConfig()
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
	common.AddConnectorConfigFlag(cmd)
	return cmd
}

func runDescribeCertificate(ctx context.Context, config *kon.Dotkon, cardHandle string, certRef certificateservicecommon20.CertRefEnum) error {
	client, err := common.LoadClient(config)
	if err != nil {
		return err
	}

	certs, err := client.ReadCardCertificates(ctx, cardHandle, certificateservice601.CryptTypeEcc, certRef)
	if err != nil {
		return err
	}

	if len(certs) == 0 {
		return fmt.Errorf("certificate %s not found on card %s", certRef, cardHandle)
	}

	c := certs[0]

	if common.OutputFlag == "json" {
		return common.PrintJSON(c)
	}

	kv := common.NewKVWriter()
	writeCertificateDetail(kv, c)
	return kv.Print()
}

func writeCertificateDetail(kv *common.KVWriter, c *kon.CardCertificate) {
	cert := c.X509

	kv.Section("Certificate")
	kv.KV("Cert Ref", c.CertRef)
	kv.KV("Version", fmt.Sprintf("%d (0x%x)", cert.Version, cert.Version-1))
	kv.KV("Serial Number", fmt.Sprintf("%s (%d)", common.ColonHex(cert.SerialNumber.Bytes()), cert.SerialNumber))
	kv.KV("Signature Algorithm", cert.SignatureAlgorithm.String())

	kv.Section("Issuer")
	writeDistinguishedName(kv, cert.Issuer.Names)
	kv.EndSection()

	kv.Section("Validity")
	kv.KV("Not Before", cert.NotBefore.Format("Jan 02 15:04:05 2006 MST"))
	kv.KV("Not After", cert.NotAfter.Format("Jan 02 15:04:05 2006 MST"))
	kv.EndSection()

	kv.Section("Subject")
	writeDistinguishedName(kv, cert.Subject.Names)
	kv.EndSection()

	kv.Section("Subject Public Key Info")
	kv.KV("Algorithm", cert.PublicKeyAlgorithm.String())
	if cert.PublicKey != nil {
		kv.KV("Key Size", common.DescribePublicKey(cert.PublicKey))
	}
	kv.EndSection()

	// Extensions
	if cert.KeyUsage != 0 || len(cert.ExtKeyUsage) > 0 || cert.IsCA ||
		len(cert.SubjectKeyId) > 0 || len(cert.AuthorityKeyId) > 0 ||
		len(cert.DNSNames) > 0 || len(cert.EmailAddresses) > 0 ||
		len(cert.URIs) > 0 || len(cert.IPAddresses) > 0 ||
		len(cert.OCSPServer) > 0 || len(cert.IssuingCertificateURL) > 0 ||
		len(cert.CRLDistributionPoints) > 0 || len(cert.PolicyIdentifiers) > 0 {

		kv.Section("X509v3 Extensions")

		if cert.BasicConstraintsValid {
			ca := "FALSE"
			if cert.IsCA {
				ca = "TRUE"
				if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
					ca = fmt.Sprintf("TRUE, pathlen:%d", cert.MaxPathLen)
				}
			}
			kv.KV("Basic Constraints", fmt.Sprintf("CA:%s", ca))
		}

		if cert.KeyUsage != 0 {
			kv.KV("Key Usage", common.FormatKeyUsage(cert.KeyUsage))
		}

		if len(cert.ExtKeyUsage) > 0 {
			kv.KV("Extended Key Usage", common.FormatExtKeyUsage(cert.ExtKeyUsage))
		}

		if len(cert.SubjectKeyId) > 0 {
			kv.KV("Subject Key Identifier", common.ColonHex(cert.SubjectKeyId))
		}

		if len(cert.AuthorityKeyId) > 0 {
			kv.KV("Authority Key Identifier", common.ColonHex(cert.AuthorityKeyId))
		}

		// Subject Alternative Names
		hasSAN := len(cert.DNSNames) > 0 || len(cert.EmailAddresses) > 0 ||
			len(cert.IPAddresses) > 0 || len(cert.URIs) > 0
		if hasSAN {
			var sans []string
			for _, dns := range cert.DNSNames {
				sans = append(sans, "DNS:"+dns)
			}
			for _, email := range cert.EmailAddresses {
				sans = append(sans, "email:"+email)
			}
			for _, ip := range cert.IPAddresses {
				sans = append(sans, "IP:"+ip.String())
			}
			for _, uri := range cert.URIs {
				sans = append(sans, "URI:"+uri.String())
			}
			kv.KV("Subject Alternative Name", strings.Join(sans, ", "))
		}

		if len(cert.CRLDistributionPoints) > 0 {
			kv.KV("CRL Distribution Points", strings.Join(cert.CRLDistributionPoints, ", "))
		}

		if len(cert.OCSPServer) > 0 || len(cert.IssuingCertificateURL) > 0 {
			var aia []string
			for _, ocsp := range cert.OCSPServer {
				aia = append(aia, "OCSP: "+ocsp)
			}
			for _, ca := range cert.IssuingCertificateURL {
				aia = append(aia, "CA Issuers: "+ca)
			}
			kv.KV("Authority Info Access", strings.Join(aia, ", "))
		}

		if len(cert.PolicyIdentifiers) > 0 {
			var pols []string
			for _, oid := range cert.PolicyIdentifiers {
				pols = append(pols, oid.String())
			}
			kv.KV("Certificate Policies", strings.Join(pols, ", "))
		}

		kv.EndSection()
	}

	// Admission (TI-specific)
	if c.Admission != nil {
		kv.Section("Admission")
		if len(c.Admission.ProfessionItems) > 0 {
			kv.KV("Profession Items", strings.Join(c.Admission.ProfessionItems, ", "))
		}
		if len(c.Admission.ProfessionOids) > 0 {
			kv.KV("Profession OIDs", strings.Join(c.Admission.ProfessionOids, ", "))
		}
		if c.Admission.RegistrationNumber != "" {
			kv.KV("Registration Number", c.Admission.RegistrationNumber)
		}
		kv.EndSection()
	}

	// Fingerprints
	kv.Section("Fingerprints")
	sha1sum := sha1.Sum(cert.Raw)
	sha256sum := sha256.Sum256(cert.Raw)
	kv.KV("SHA-1", common.ColonHex(sha1sum[:]))
	kv.KV("SHA-256", common.ColonHex(sha256sum[:]))
	kv.EndSection()

	kv.EndSection() // Certificate
}

// writeDistinguishedName writes RDN attributes as indented key-value pairs.
func writeDistinguishedName(kv *common.KVWriter, names []pkix.AttributeTypeAndValue) {
	for _, name := range names {
		key := common.OIDName(name.Type)
		val := fmt.Sprintf("%v", name.Value)
		kv.KV(key, val)
	}
}
