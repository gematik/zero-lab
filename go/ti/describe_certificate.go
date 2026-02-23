package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservice601"
	"github.com/gematik/zero-lab/go/kon/api/gematik/conn/certificateservicecommon20"
	"github.com/spf13/cobra"
)

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

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

	certs, err := client.ReadCardCertificates(ctx, cardHandle, certificateservice601.CryptTypeEcc, certRef)
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

	kv := newKVWriter()
	writeCertificateDetail(kv, c)
	return kv.Print()
}

func writeCertificateDetail(kv *kvWriter, c *kon.CardCertificate) {
	cert := c.X509

	kv.Section("Certificate")
	kv.KV("Cert Ref", c.CertRef)
	kv.KV("Version", fmt.Sprintf("%d (0x%x)", cert.Version, cert.Version-1))
	kv.KV("Serial Number", fmt.Sprintf("%s (%d)", colonHex(cert.SerialNumber.Bytes()), cert.SerialNumber))
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
		kv.KV("Key Size", describePublicKey(cert.PublicKey))
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
			kv.KV("Key Usage", formatKeyUsage(cert.KeyUsage))
		}

		if len(cert.ExtKeyUsage) > 0 {
			kv.KV("Extended Key Usage", formatExtKeyUsage(cert.ExtKeyUsage))
		}

		if len(cert.SubjectKeyId) > 0 {
			kv.KV("Subject Key Identifier", colonHex(cert.SubjectKeyId))
		}

		if len(cert.AuthorityKeyId) > 0 {
			kv.KV("Authority Key Identifier", colonHex(cert.AuthorityKeyId))
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
	kv.KV("SHA-1", colonHex(sha1sum[:]))
	kv.KV("SHA-256", colonHex(sha256sum[:]))
	kv.EndSection()

	kv.EndSection() // Certificate
}

// writeDistinguishedName writes RDN attributes as indented key-value pairs.
func writeDistinguishedName(kv *kvWriter, names []pkix.AttributeTypeAndValue) {
	for _, name := range names {
		key := oidName(name.Type)
		val := fmt.Sprintf("%v", name.Value)
		kv.KV(key, val)
	}
}

var oidNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.17":                   "POSTALCODE",
	"2.5.4.9":                    "STREET",
	"2.5.4.42":                   "GN",
	"2.5.4.4":                    "SN",
	"2.5.4.12":                   "TITLE",
	"2.5.4.46":                   "DN Qualifier",
	"1.2.840.113549.1.9.1":       "EMAIL",
	"0.9.2342.19200300.100.1.25": "DC",
}

func oidName(oid asn1.ObjectIdentifier) string {
	if name, ok := oidNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
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
	x509.ExtKeyUsageServerAuth:                 "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:                 "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "E-mail Protection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSec End System",
	x509.ExtKeyUsageIPSECTunnel:                "IPSec Tunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSec User",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape Server Gated Crypto",
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
