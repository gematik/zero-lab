package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

// DescribePublicKey returns a short human label for a public key, e.g.
// "RSA-2048" or a named EC curve.
func DescribePublicKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return DescribeECCurve(k.Curve)
	default:
		return fmt.Sprintf("%T", pub)
	}
}

// DescribeECCurve returns the curve's name, or a bit-size fallback.
func DescribeECCurve(c elliptic.Curve) string {
	name := c.Params().Name
	if name != "" {
		return name
	}
	return fmt.Sprintf("%d bit EC", c.Params().BitSize)
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

// OIDName maps a known X.500 attribute OID to its short name, falling back to
// the dotted string form.
func OIDName(oid asn1.ObjectIdentifier) string {
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

// FormatKeyUsage renders a KeyUsage bitmask as a comma-separated label list.
func FormatKeyUsage(ku x509.KeyUsage) string {
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

// FormatExtKeyUsage renders extended key usages as a comma-separated label list.
func FormatExtKeyUsage(usages []x509.ExtKeyUsage) string {
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
