package pki

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

// ---- inspect ----------------------------------------------------------------

func newPKIInspectCmd() *cobra.Command {
	var formatRaw string
	var short bool
	cmd := &cobra.Command{
		Use:   "inspect FILE|-",
		Short: "Decode and print a certificate (offline; does not validate)",
		Long: "Decode a certificate read from a file or stdin (-) and print its contents.\n" +
			"PEM and DER are auto-detected.\n\n" +
			"This never builds a chain, never contacts the network and never consults a\n" +
			"trust store — it says nothing about whether the certificate is trusted.\n" +
			"Use `ti pki verify` for that.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsInspect)
			if err != nil {
				return err
			}
			certs, err := loadCertChain(args[0])
			if err != nil {
				return err
			}
			return runCertInspect(certs, f, short)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json, pem")
	cmd.Flags().BoolVar(&short, "short", false, "one-line summary per certificate")
	return cmd
}

func runCertInspect(certs []*x509.Certificate, f outputFormat, short bool) error {
	switch f {
	case formatPEM:
		for _, c := range certs {
			if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
				return err
			}
		}
		return nil
	case formatJSON:
		if short {
			out := make([]certSummary, len(certs))
			for i, c := range certs {
				out[i] = certSummary{
					Subject:  c.Subject.CommonName,
					NotAfter: c.NotAfter.Format(time.RFC3339),
					SHA256:   common.ColonHex(sha256Sum(c.Raw)),
				}
			}
			return common.PrintJSON(out)
		}
		out := make([]certInspect, len(certs))
		for i, c := range certs {
			out[i] = buildCertInspect(c)
		}
		return common.PrintJSON(out)
	}
	if short {
		for _, c := range certs {
			fmt.Printf("%s  not after %s  SHA-256 %s\n",
				c.Subject.CommonName,
				c.NotAfter.Format("2006-01-02"),
				shortHex(sha256.Sum256(c.Raw)),
			)
		}
		return nil
	}
	kv := common.NewKVWriter()
	for _, c := range certs {
		ci := buildCertInspect(c)
		writeCertInspect(kv, ci)
	}
	return kv.Print()
}

// certSummary is the --short shape: the same three facts the one-line text
// output prints, so text and JSON stay in step in both modes.
type certSummary struct {
	Subject  string `json:"subject"`
	NotAfter string `json:"notAfter"`
	SHA256   string `json:"sha256"`
}

// certInspect is the canonical inspection structure used by `ti pki inspect`.
// Text and JSON renderers both read from this so the two outputs stay in
// lock-step; adding a field is automatically visible in both.
type certInspect struct {
	Version            int                    `json:"version"`
	SerialNumberHex    string                 `json:"serialNumber"`
	SerialNumberDec    string                 `json:"serialNumberDecimal"`
	SignatureAlgorithm string                 `json:"signatureAlgorithm"`
	Issuer             distinguishedName      `json:"issuer"`
	Subject            distinguishedName      `json:"subject"`
	Validity           validityInfo           `json:"validity"`
	PublicKey          publicKeyInfo          `json:"publicKey"`
	Type               gempki.CertificateType `json:"type,omitempty"`
	TypeOID            string                 `json:"typeOID,omitempty"`
	SelectedProfile    string                 `json:"selectedProfile,omitempty"`
	CompatibleProfiles []string               `json:"compatibleProfiles,omitempty"`
	Extensions         *extensionsInfo        `json:"extensions,omitempty"`
	Admission          *admissionInfo         `json:"admission,omitempty"`
	Fingerprints       fingerprintsInfo       `json:"fingerprints"`
}

type distinguishedName struct {
	String string          `json:"string"`
	Attrs  []nameAttribute `json:"attributes"`
}

type nameAttribute struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type validityInfo struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type publicKeyInfo struct {
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
}

type extensionsInfo struct {
	BasicConstraints       *basicConstraintsInfo `json:"basicConstraints,omitempty"`
	KeyUsage               []string              `json:"keyUsage,omitempty"`
	ExtendedKeyUsage       []string              `json:"extendedKeyUsage,omitempty"`
	SubjectKeyIdentifier   string                `json:"subjectKeyIdentifier,omitempty"`
	AuthorityKeyIdentifier string                `json:"authorityKeyIdentifier,omitempty"`
	SubjectAltName         []string              `json:"subjectAltName,omitempty"`
	CRLDistributionPoints  []string              `json:"crlDistributionPoints,omitempty"`
	OCSPResponders         []string              `json:"ocspResponders,omitempty"`
	IssuingCertificateURLs []string              `json:"issuingCertificateURLs,omitempty"`
	AuthorityInfoAccess    []string              `json:"authorityInfoAccess,omitempty"`
	CertificatePolicies    []string              `json:"certificatePolicies,omitempty"`
}

type basicConstraintsInfo struct {
	IsCA    bool `json:"isCA"`
	PathLen *int `json:"pathLen,omitempty"`
}

type admissionInfo struct {
	ProfessionItems    []string `json:"professionItems,omitempty"`
	ProfessionOids     []string `json:"professionOids,omitempty"`
	RegistrationNumber string   `json:"registrationNumber,omitempty"`
}

type fingerprintsInfo struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// buildCertInspect maps an *x509.Certificate to the canonical structure.
func buildCertInspect(c *x509.Certificate) certInspect {
	sha1sum := sha1.Sum(c.Raw) //nolint:gosec // user-facing fingerprint
	sha256sum := sha256.Sum256(c.Raw)
	out := certInspect{
		Version:            c.Version,
		SerialNumberHex:    common.ColonHex(c.SerialNumber.Bytes()),
		SerialNumberDec:    c.SerialNumber.String(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		Issuer:             buildDN(c.Issuer.Names, c.Issuer.String()),
		Subject:            buildDN(c.Subject.Names, c.Subject.String()),
		Validity: validityInfo{
			NotBefore: c.NotBefore.Format(time.RFC3339),
			NotAfter:  c.NotAfter.Format(time.RFC3339),
		},
		PublicKey: publicKeyInfo{
			Algorithm: c.PublicKeyAlgorithm.String(),
			Key:       common.DescribePublicKey(c.PublicKey),
		},
		Fingerprints: fingerprintsInfo{
			SHA1:   common.ColonHex(sha1sum[:]),
			SHA256: common.ColonHex(sha256sum[:]),
		},
	}
	if t := gempki.DetectCertificateType(c); t != gempki.CertTypeUnknown {
		out.Type = t
		out.TypeOID = t.OID().String()
		// Selection, not just the type: we hold the certificate, so we can
		// say which profile `ti pki verify` would actually pick for it
		// rather than listing everything its type could match.
		if sel := gempki.SelectProfileForCert(c); sel.Profile != nil {
			out.SelectedProfile = sel.Profile.Name
		}
		for _, p := range gempki.ProfilesForType(t) {
			out.CompatibleProfiles = append(out.CompatibleProfiles, p.Name)
		}
	}
	if ext := buildExtensionsInfo(c); ext != nil {
		out.Extensions = ext
	}
	if adm, err := gempki.ParseAdmissionStatement(c); err == nil && adm != nil {
		out.Admission = &admissionInfo{
			ProfessionItems:    adm.ProfessionItems,
			ProfessionOids:     adm.ProfessionOids,
			RegistrationNumber: adm.RegistrationNumber,
		}
	}
	return out
}

func buildDN(attrs []pkix.AttributeTypeAndValue, full string) distinguishedName {
	out := distinguishedName{String: full}
	for _, a := range attrs {
		out.Attrs = append(out.Attrs, nameAttribute{
			Type:  common.OIDName(a.Type),
			Value: fmt.Sprintf("%v", a.Value),
		})
	}
	return out
}

func buildExtensionsInfo(c *x509.Certificate) *extensionsInfo {
	out := &extensionsInfo{}
	any := false
	if c.BasicConstraintsValid {
		bc := &basicConstraintsInfo{IsCA: c.IsCA}
		if c.MaxPathLenZero || c.MaxPathLen > 0 {
			pl := c.MaxPathLen
			if c.MaxPathLenZero {
				pl = 0
			}
			bc.PathLen = &pl
		}
		out.BasicConstraints = bc
		any = true
	}
	if c.KeyUsage != 0 {
		out.KeyUsage = keyUsageNamesList(c.KeyUsage)
		any = true
	}
	if len(c.ExtKeyUsage) > 0 {
		out.ExtendedKeyUsage = extKeyUsageNamesList(c.ExtKeyUsage)
		any = true
	}
	if len(c.SubjectKeyId) > 0 {
		out.SubjectKeyIdentifier = common.ColonHex(c.SubjectKeyId)
		any = true
	}
	if len(c.AuthorityKeyId) > 0 {
		out.AuthorityKeyIdentifier = common.ColonHex(c.AuthorityKeyId)
		any = true
	}
	var sans []string
	for _, dns := range c.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}
	for _, email := range c.EmailAddresses {
		sans = append(sans, "email:"+email)
	}
	for _, ip := range c.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, uri := range c.URIs {
		sans = append(sans, "URI:"+uri.String())
	}
	if len(sans) > 0 {
		out.SubjectAltName = sans
		any = true
	}
	if len(c.CRLDistributionPoints) > 0 {
		out.CRLDistributionPoints = c.CRLDistributionPoints
		any = true
	}
	if len(c.OCSPServer) > 0 {
		out.OCSPResponders = append([]string(nil), c.OCSPServer...)
		any = true
	}
	if len(c.IssuingCertificateURL) > 0 {
		out.IssuingCertificateURLs = append([]string(nil), c.IssuingCertificateURL...)
		any = true
	}
	if len(c.OCSPServer) > 0 || len(c.IssuingCertificateURL) > 0 {
		var aia []string
		for _, o := range c.OCSPServer {
			aia = append(aia, "OCSP: "+o)
		}
		for _, ca := range c.IssuingCertificateURL {
			aia = append(aia, "CA Issuers: "+ca)
		}
		out.AuthorityInfoAccess = aia
	}
	if len(c.PolicyIdentifiers) > 0 {
		out.CertificatePolicies = policyOIDStrings(c.PolicyIdentifiers)
		any = true
	}
	if !any {
		return nil
	}
	return out
}

// writeCertInspect renders a certInspect via common.KVWriter — the text companion
// of marshalling the struct to JSON.
func writeCertInspect(kv *common.KVWriter, ci certInspect) {
	if ci.Type != gempki.CertTypeUnknown {
		kv.Section("Certificate Type")
		kv.KV("Name", string(ci.Type))
		kv.KV("OID", ci.TypeOID)
		if ci.SelectedProfile != "" {
			kv.KV("Selected Profile", ci.SelectedProfile)
		}
		if len(ci.CompatibleProfiles) > 0 {
			kv.KV("Compatible Profiles", strings.Join(ci.CompatibleProfiles, ", "))
		}
		kv.EndSection()
	}
	kv.Section("Certificate")
	kv.KV("Version", fmt.Sprintf("%d (0x%x)", ci.Version, ci.Version-1))
	kv.KV("Serial Number", fmt.Sprintf("%s (%s)", ci.SerialNumberHex, ci.SerialNumberDec))
	kv.KV("Signature Algorithm", ci.SignatureAlgorithm)

	kv.Section("Issuer")
	for _, a := range ci.Issuer.Attrs {
		kv.KV(a.Type, a.Value)
	}
	kv.EndSection()

	kv.Section("Validity")
	kv.KV("Not Before", ci.Validity.NotBefore)
	kv.KV("Not After", ci.Validity.NotAfter)
	kv.EndSection()

	kv.Section("Subject")
	for _, a := range ci.Subject.Attrs {
		kv.KV(a.Type, a.Value)
	}
	kv.EndSection()

	kv.Section("Subject Public Key Info")
	kv.KV("Algorithm", ci.PublicKey.Algorithm)
	kv.KV("Key", ci.PublicKey.Key)
	kv.EndSection()

	if ci.Extensions != nil {
		kv.Section("X509v3 Extensions")
		if ci.Extensions.BasicConstraints != nil {
			bc := ci.Extensions.BasicConstraints
			s := fmt.Sprintf("CA:%t", bc.IsCA)
			if bc.PathLen != nil {
				s = fmt.Sprintf("CA:%t, pathlen:%d", bc.IsCA, *bc.PathLen)
			}
			kv.KV("Basic Constraints", s)
		}
		if len(ci.Extensions.KeyUsage) > 0 {
			kv.KV("Key Usage", strings.Join(ci.Extensions.KeyUsage, ", "))
		}
		if len(ci.Extensions.ExtendedKeyUsage) > 0 {
			kv.KV("Extended Key Usage", strings.Join(ci.Extensions.ExtendedKeyUsage, ", "))
		}
		if ci.Extensions.SubjectKeyIdentifier != "" {
			kv.KV("Subject Key Identifier", ci.Extensions.SubjectKeyIdentifier)
		}
		if ci.Extensions.AuthorityKeyIdentifier != "" {
			kv.KV("Authority Key Identifier", ci.Extensions.AuthorityKeyIdentifier)
		}
		if len(ci.Extensions.SubjectAltName) > 0 {
			kv.KV("Subject Alternative Name", strings.Join(ci.Extensions.SubjectAltName, ", "))
		}
		if len(ci.Extensions.CRLDistributionPoints) > 0 {
			kv.KV("CRL Distribution Points", strings.Join(ci.Extensions.CRLDistributionPoints, ", "))
		}
		if len(ci.Extensions.OCSPResponders) > 0 {
			kv.KV("OCSP Responder", strings.Join(ci.Extensions.OCSPResponders, ", "))
		}
		if len(ci.Extensions.IssuingCertificateURLs) > 0 {
			kv.KV("CA Issuers URL", strings.Join(ci.Extensions.IssuingCertificateURLs, ", "))
		}
		if len(ci.Extensions.AuthorityInfoAccess) > 0 {
			kv.KV("Authority Info Access", strings.Join(ci.Extensions.AuthorityInfoAccess, ", "))
		}
		if len(ci.Extensions.CertificatePolicies) > 0 {
			kv.KV("Certificate Policies", strings.Join(ci.Extensions.CertificatePolicies, ", "))
		}
		kv.EndSection()
	}

	if ci.Admission != nil {
		kv.Section("Admission")
		if len(ci.Admission.ProfessionItems) > 0 {
			kv.KV("Profession Items", strings.Join(ci.Admission.ProfessionItems, ", "))
		}
		if len(ci.Admission.ProfessionOids) > 0 {
			kv.KV("Profession OIDs", strings.Join(ci.Admission.ProfessionOids, ", "))
		}
		if ci.Admission.RegistrationNumber != "" {
			kv.KV("Registration Number", ci.Admission.RegistrationNumber)
		}
		kv.EndSection()
	}

	kv.Section("Fingerprints")
	kv.KV("SHA-1", ci.Fingerprints.SHA1)
	kv.KV("SHA-256", ci.Fingerprints.SHA256)
	kv.EndSection()

	kv.EndSection()
}

// shortHex returns a short prefix (first 8 bytes) of a sha256 sum as
// colon-hex, useful for one-line summaries.
func sha256Sum(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

func shortHex(sum [32]byte) string {
	return common.ColonHex(sum[:8])
}

func policyOIDStrings(pol []asn1.ObjectIdentifier) []string {
	out := make([]string, len(pol))
	for i, p := range pol {
		out[i] = p.String()
	}
	return out
}

// keyUsageNamesList returns the same names common.FormatKeyUsage produces, but
// as a slice (so the JSON output is structured, not a pre-joined string).
func keyUsageNamesList(ku x509.KeyUsage) []string {
	parts := strings.Split(common.FormatKeyUsage(ku), ", ")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// extKeyUsageNamesList is the structured equivalent of common.FormatExtKeyUsage.
func extKeyUsageNamesList(ekus []x509.ExtKeyUsage) []string {
	parts := strings.Split(common.FormatExtKeyUsage(ekus), ", ")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
