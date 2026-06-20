package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

// newPKICertCmd is the parent of all `ti pki <env> cert <verb>` commands.
func newPKICertCmd(def envDef) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Operate on individual X.509 certificates",
		Long: "Operations on a single cert read from a file or stdin (-).\n" +
			"PEM and DER are auto-detected.",
	}
	cmd.AddCommand(newPKICertInspectCmd(def))
	cmd.AddCommand(newPKICertVerifyCmd(def))
	cmd.AddCommand(newPKICertLintCmd(def))
	return cmd
}

// ---- shared input helpers ---------------------------------------------------

// readCertInputBytes reads either FILE or stdin ("-") and returns the raw bytes.
func readCertInputBytes(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// parseCertInput accepts PEM or DER bytes and returns all certificates found.
// Multiple PEM CERTIFICATE blocks are returned in order; single DER blobs are
// returned as a one-element slice.
func parseCertInput(raw []byte) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty certificate input")
	}
	// PEM heuristic: ASCII begins with "-----BEGIN".
	if isPEM(raw) {
		out, err := gempki.ParsePEMCertificates(raw)
		if err != nil {
			return nil, fmt.Errorf("parse PEM: %w", err)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no CERTIFICATE blocks found in PEM input")
		}
		return out, nil
	}
	cert, err := gempki.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse DER: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}

func isPEM(raw []byte) bool {
	const head = "-----BEGIN"
	if len(raw) < len(head) {
		return false
	}
	// Find the first non-whitespace byte; if it starts the PEM marker, it's PEM.
	for i := range raw {
		if raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\r' || raw[i] == '\n' {
			continue
		}
		return strings.HasPrefix(string(raw[i:]), head)
	}
	return false
}

// loadCertChain is the shared input loader for every cert subcommand.
func loadCertChain(path string) ([]*x509.Certificate, error) {
	raw, err := readCertInputBytes(path)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return parseCertInput(raw)
}

// ---- inspect ----------------------------------------------------------------

func newPKICertInspectCmd(def envDef) *cobra.Command {
	var formatRaw string
	var short bool
	cmd := &cobra.Command{
		Use:   "inspect FILE|-",
		Short: "Decode and print a certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsCertInspect)
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
	_ = def
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
		out := make([]certInspect, len(certs))
		for i, c := range certs {
			out[i] = buildCertInspect(c, short)
		}
		return printJSON(out)
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
	kv := newKVWriter()
	for _, c := range certs {
		ci := buildCertInspect(c, false)
		writeCertInspect(kv, ci)
	}
	return kv.Print()
}

// certInspect is the canonical inspection structure used by `cert inspect`.
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
	DefaultProfile     string                 `json:"defaultProfile,omitempty"`
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
// short=true is reserved for future use (the one-line text output handles
// "short" elsewhere); kept here for symmetry with the JSON path.
func buildCertInspect(c *x509.Certificate, short bool) certInspect {
	_ = short
	sha1sum := sha1.Sum(c.Raw) //nolint:gosec // user-facing fingerprint
	sha256sum := sha256.Sum256(c.Raw)
	out := certInspect{
		Version:            c.Version,
		SerialNumberHex:    colonHex(c.SerialNumber.Bytes()),
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
			Key:       describePublicKey(c.PublicKey),
		},
		Fingerprints: fingerprintsInfo{
			SHA1:   colonHex(sha1sum[:]),
			SHA256: colonHex(sha256sum[:]),
		},
	}
	if t := gempki.DetectCertificateType(c); t != gempki.CertTypeUnknown {
		out.Type = t
		out.TypeOID = t.OID().String()
		if dp := t.DefaultProfile(); dp != nil {
			out.DefaultProfile = dp.Name
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
			Type:  oidName(a.Type),
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
		out.SubjectKeyIdentifier = colonHex(c.SubjectKeyId)
		any = true
	}
	if len(c.AuthorityKeyId) > 0 {
		out.AuthorityKeyIdentifier = colonHex(c.AuthorityKeyId)
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

// writeCertInspect renders a certInspect via kvWriter — the text companion
// of marshalling the struct to JSON.
func writeCertInspect(kv *kvWriter, ci certInspect) {
	if ci.Type != gempki.CertTypeUnknown {
		kv.Section("Certificate Type")
		kv.KV("Name", string(ci.Type))
		kv.KV("OID", ci.TypeOID)
		if ci.DefaultProfile != "" {
			kv.KV("Default Profile", ci.DefaultProfile)
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
func shortHex(sum [32]byte) string {
	return colonHex(sum[:8])
}

func policyOIDStrings(pol []asn1.ObjectIdentifier) []string {
	out := make([]string, len(pol))
	for i, p := range pol {
		out[i] = p.String()
	}
	return out
}

// keyUsageNamesList returns the same names formatKeyUsage produces, but
// as a slice (so the JSON output is structured, not a pre-joined string).
func keyUsageNamesList(ku x509.KeyUsage) []string {
	parts := strings.Split(formatKeyUsage(ku), ", ")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// extKeyUsageNamesList is the structured equivalent of formatExtKeyUsage.
func extKeyUsageNamesList(ekus []x509.ExtKeyUsage) []string {
	parts := strings.Split(formatExtKeyUsage(ekus), ", ")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---- verify -----------------------------------------------------------------

func newPKICertVerifyCmd(def envDef) *cobra.Command {
	var formatRaw, rootsPath, intermediatesPath, profile, atRaw string
	var withOCSP, insecure bool
	cmd := &cobra.Command{
		Use:   "verify FILE|-",
		Short: "Build a chain and validate against gematik TI roots",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsCertVerify)
			if err != nil {
				return err
			}
			at, err := parseAtFlag(atRaw)
			if err != nil {
				return err
			}
			certs, err := loadCertChain(args[0])
			if err != nil {
				return err
			}
			if len(certs) == 0 {
				return fmt.Errorf("no certificate parsed from input")
			}
			return runCertVerify(cmd.Context(), def, certs, f, certVerifyOpts{
				RootsPath:         rootsPath,
				IntermediatesPath: intermediatesPath,
				Profile:           profile,
				WithOCSP:          withOCSP,
				Insecure:          insecure,
				At:                at,
			})
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	cmd.Flags().StringVar(&rootsPath, "roots", "", "PEM file of trust anchors (default: env embedded roots)")
	cmd.Flags().StringVar(&intermediatesPath, "intermediates", "", "PEM file of additional candidate intermediates")
	cmd.Flags().StringVar(&profile, "profile", "auto", "profile-driven EE checks. 'auto' (default) detects the cert type and picks the matching profile (C.HCI.AUT → smbauth, C.FD.SIG → idp). 'none' disables profile checks (chain-only). Explicit profiles: smbauth | epavau | idp. Use --profile explicitly when the cert type matches multiple profiles (e.g. C.FD.AUT → epavau or idp).")
	cmd.Flags().BoolVar(&withOCSP, "ocsp", false, "evaluate revocation via OCSP (AIA-driven). Profiles enable OCSP automatically per their gemSpec policy; this flag is for use without --profile.")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip chain build; print decoded cert only")
	cmd.Flags().StringVar(&atRaw, "at", "", "validate at a specific time (RFC3339; default: now)")
	return cmd
}

type certVerifyOpts struct {
	RootsPath         string
	IntermediatesPath string
	Profile           string
	WithOCSP          bool
	Insecure          bool
	At                *time.Time

	// httpClient + TSLResponders feed the OCSP path inside buildValidator
	// so a delegated responder (TI-style cross-CA OCSP, e.g. KOMP-CAxx
	// answering for SMCB-CAxx) can be authorized via the TSL listing.
	httpClient    *http.Client
	tslResponders []*x509.Certificate
	intermediates []*x509.Certificate
	roots         *gempki.TrustStore

	// Auto-detection bookkeeping (populated when Profile == "auto"):
	//   detectedType — what DetectCertificateType returned for the EE
	//   resolvedFrom — "auto", "explicit", or "none" (drives display)
	//   profileMissing — auto ran but no profile accepts the detected type
	//   profileAmbiguous — auto ran, multiple profiles accept the type,
	//                      none owns the default → user must pick
	//   profileCandidates — when ambiguous, the profile names that match
	detectedType      gempki.CertificateType
	resolvedFrom      string
	profileMissing    bool
	profileAmbiguous  bool
	profileCandidates []string
}

func runCertVerify(ctx context.Context, def envDef, certs []*x509.Certificate, f outputFormat, opts certVerifyOpts) error {
	if opts.Insecure {
		return runCertInspect(certs, f, false)
	}
	// Resolve --profile auto / none into a concrete profile name. Detection
	// runs against the EE (certs[0]); the result drives both the validator
	// choice and the "Detected Type" / "Profile" surface in the output.
	switch strings.ToLower(opts.Profile) {
	case "", "auto":
		t := gempki.DetectCertificateType(certs[0])
		opts.detectedType = t
		opts.resolvedFrom = "auto"
		candidates := gempki.ProfilesForType(t)
		switch {
		case len(candidates) == 0:
			opts.profileMissing = true
			opts.Profile = ""
			slog.Debug("gempki: profile auto-detection found no match",
				"subject", certs[0].Subject.CommonName,
				"type", string(t))
		case t.DefaultProfile() != nil:
			opts.Profile = t.DefaultProfile().Name
			slog.Debug("gempki: profile auto-selected",
				"subject", certs[0].Subject.CommonName,
				"type", string(t),
				"profile", opts.Profile)
		default:
			opts.profileAmbiguous = true
			opts.Profile = ""
			opts.profileCandidates = make([]string, len(candidates))
			for i, p := range candidates {
				opts.profileCandidates[i] = p.Name
			}
			slog.Debug("gempki: profile auto-detection found multiple matches",
				"subject", certs[0].Subject.CommonName,
				"type", string(t),
				"candidates", opts.profileCandidates)
		}
	case "none":
		opts.resolvedFrom = "none"
		opts.Profile = ""
	default:
		opts.resolvedFrom = "explicit"
		opts.detectedType = gempki.DetectCertificateType(certs[0])
	}
	httpClient := newHTTPClient()
	ts, err := resolveTrustStoreFor(ctx, def, opts.RootsPath, httpClient)
	if err != nil {
		return err
	}
	intermediates := append([]*x509.Certificate(nil), certs[1:]...)
	if opts.IntermediatesPath != "" {
		extra, err := loadCertChain(opts.IntermediatesPath)
		if err != nil {
			return fmt.Errorf("load intermediates: %w", err)
		}
		intermediates = append(intermediates, extra...)
	}
	// Always merge TSL intermediates — SMC-B/HBA chains rely on issuer CAs
	// that gematik publishes through the TSL, not the embedded roots. Also
	// pull TSL-listed OCSP responders so [buildValidator] can authorize a
	// delegated responder via the TSL-match path. A TSL fetch failure is
	// logged but not fatal; chain build proceeds with whatever we have.
	var tslResponders []*x509.Certificate
	tsl, terr := loadTSLCached(ctx, httpClient, def.TSLURL)
	if terr != nil {
		slog.Warn("TSL load failed; chain build will rely on roots + supplied intermediates only", "env", def.Env, "err", terr)
	} else {
		for _, c := range gempki.IntermediateCAsFromTSL(tsl) {
			if c.Cert != nil {
				intermediates = append(intermediates, c.Cert)
			}
		}
		for _, c := range gempki.OCSPRespondersFromTSL(tsl) {
			if c.Cert != nil {
				tslResponders = append(tslResponders, c.Cert)
			}
		}
	}
	opts.httpClient = httpClient
	opts.tslResponders = tslResponders
	opts.intermediates = intermediates
	opts.roots = ts

	v := buildValidator(def, ts, opts)
	result, err := v.Validate(ctx, append([]*x509.Certificate{certs[0]}, intermediates...))
	if err != nil {
		return err
	}

	if opts.profileMissing {
		w := *gempki.WarnProfileNotDetected
		w.Subject = certs[0].Subject.CommonName
		if opts.detectedType != gempki.CertTypeUnknown {
			w.Message = fmt.Sprintf(
				"no profile accepts type %s; ran chain-only validation (pass --profile explicitly or use --profile none to silence)",
				opts.detectedType,
			)
		}
		result.Warnings = append(result.Warnings, &w)
	}
	if opts.profileAmbiguous {
		w := *gempki.WarnProfileAmbiguous
		w.Subject = certs[0].Subject.CommonName
		w.Message = fmt.Sprintf(
			"type %s matches multiple profiles: %s; pass --profile explicitly",
			opts.detectedType, strings.Join(opts.profileCandidates, ", "),
		)
		result.Warnings = append(result.Warnings, &w)
	}
	if opts.resolvedFrom == "explicit" && opts.Profile != "" {
		if p, ok := gempki.ProfileRegistry[strings.ToLower(opts.Profile)]; ok &&
			opts.detectedType != gempki.CertTypeUnknown && !p.Accepts(opts.detectedType) {
			w := *gempki.WarnProfileTypeMismatch
			w.Subject = certs[0].Subject.CommonName
			w.Message = fmt.Sprintf(
				"profile %s does not accept type %s; running validation anyway",
				p.Name, opts.detectedType,
			)
			result.Warnings = append(result.Warnings, &w)
		}
	}

	if f == formatJSON {
		return printJSON(verifyResultJSON(result, opts))
	}
	return renderVerifyResultText(result, opts)
}

func resolveTrustStoreFor(ctx context.Context, def envDef, rootsPath string, httpClient *http.Client) (*gempki.TrustStore, error) {
	if rootsPath == "" {
		loader := gempki.NetworkLoader{Env: def.Env, HTTPClient: httpClient}
		return loader.Load(ctx)
	}
	pemBytes, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("read --roots: %w", err)
	}
	roots, err := gempki.ParsePEMCertificates(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse --roots: %w", err)
	}
	return gempki.NewTrustStore(roots)
}

func buildValidator(def envDef, ts *gempki.TrustStore, opts certVerifyOpts) *gempki.Validator {
	var v *gempki.Validator
	if p, ok := gempki.ProfileRegistry[strings.ToLower(opts.Profile)]; ok {
		v = p.Validator(ts, opts.detectedType)
	} else {
		v = gempki.NewValidator(gempki.WithTrustStore(ts))
	}
	if opts.At != nil {
		at := *opts.At
		v.TimeFunc = func() time.Time { return at }
	}
	// Revocation policy:
	//   - When a profile is set, the profile carries the mode (e.g.
	//     ProfileSmbAuth = SoftFail, ProfileIdp / ProfileEpaVau = HardFail).
	//     The profile dictates; we just wire the OCSPChecker so the mode has
	//     something to evaluate.
	//   - When no profile is set, `--ocsp` opts in to SoftFail revocation.
	//   - When neither is set, revocation is disabled (cheap decode + chain).
	profileSet := opts.Profile != ""
	if profileSet || opts.WithOCSP {
		client := opts.httpClient
		if client == nil {
			client = newHTTPClient()
		}
		gempki.WithRevocationChecker(&gempki.OCSPChecker{
			HTTPClient:     client,
			MaxResponseAge: 48 * time.Hour,
			TSLResponders:  opts.tslResponders,
			Intermediates:  opts.intermediates,
			Roots:          opts.roots,
		})(v)
		if !profileSet {
			gempki.WithRevocationMode(gempki.RevocationModeSoftFail)(v)
		}
	} else {
		gempki.WithRevocationMode(gempki.RevocationModeDisabled)(v)
	}
	_ = def
	return v
}

func renderVerifyResultText(result *gempki.ValidationResult, opts certVerifyOpts) error {
	kv := newKVWriter()
	// Lead with the most useful facts about the EE — type/profile (the
	// answers a user usually wants) and a compact identity block — so
	// reviewers see the "what cert and how was it judged" up front
	// without scrolling through the chain detail.
	if len(result.Chain) > 0 && result.Chain[0] != nil {
		ee := result.Chain[0]
		if opts.detectedType != gempki.CertTypeUnknown {
			kv.Section("Certificate Type")
			kv.KV("Name", string(opts.detectedType))
			kv.KV("OID", opts.detectedType.OID().String())
			if dp := opts.detectedType.DefaultProfile(); dp != nil {
				kv.KV("Default Profile", dp.Name)
			}
			if compat := gempki.ProfilesForType(opts.detectedType); len(compat) > 0 {
				names := make([]string, len(compat))
				for i, p := range compat {
					names[i] = p.Name
				}
				kv.KV("Compatible Profiles", strings.Join(names, ", "))
			}
			kv.EndSection()
		}
		kv.Section("Certificate")
		kv.KV("Subject", ee.Subject.CommonName)
		kv.KV("Issuer", ee.Issuer.CommonName)
		kv.KV("Serial Number", colonHex(ee.SerialNumber.Bytes()))
		kv.KV("Not Before", ee.NotBefore.Format(time.RFC3339))
		kv.KV("Not After", ee.NotAfter.Format(time.RFC3339))
		kv.KV("Public Key", fmt.Sprintf("%s %s", ee.PublicKeyAlgorithm, describePublicKey(ee.PublicKey)))
		kv.EndSection()
	}
	kv.Section("Validation")
	verdict := "VALID"
	if !result.Valid {
		verdict = "INVALID"
	}
	kv.KV("Result", verdict)
	kv.KV("Chain length", fmt.Sprintf("%d", len(result.Chain)))
	if opts.resolvedFrom == "auto" {
		typeStr := string(opts.detectedType)
		if typeStr == "" {
			typeStr = "(unknown)"
		}
		kv.KV("Detected Type", typeStr)
	}
	if opts.Profile != "" {
		kv.KV("Profile", opts.Profile)
	} else if opts.resolvedFrom == "none" {
		kv.KV("Profile", "(none — chain-only)")
	}
	if len(result.Errors) > 0 {
		kv.Section("Errors")
		for _, e := range result.Errors {
			kv.KV(string(e.Code), e.Error())
		}
		kv.EndSection()
	}
	if len(result.Warnings) > 0 {
		kv.Section("Warnings")
		for _, w := range result.Warnings {
			kv.KV(string(w.Code), w.String())
		}
		kv.EndSection()
	}
	if len(result.Chain) > 0 {
		kv.Section("Chain")
		for i, c := range result.Chain {
			pos := ""
			if i < len(result.Positions) {
				pos = string(result.Positions[i])
			}
			if c == nil {
				kv.KV(fmt.Sprintf("[%d] %s", i, pos), "(nil)")
				continue
			}
			label := fmt.Sprintf("[%d] %s", i, pos)
			kv.KV(strings.TrimSpace(label), c.Subject.CommonName)
		}
		kv.EndSection()
	}
	for i, cr := range result.CertResults {
		if cr.Revocation == nil {
			continue
		}
		label := "Revocation"
		if i < len(result.Positions) {
			label = fmt.Sprintf("Revocation [%d] %s", i, result.Positions[i])
		}
		kv.Section(label)
		writeRevocationDetail(kv, cr.Revocation)
		kv.EndSection()
	}
	kv.EndSection()
	return kv.Print()
}

func writeRevocationDetail(kv *kvWriter, rev *gempki.RevocationResult) {
	kv.KV("Status", string(rev.Status))
	kv.KV("Source", string(rev.Source))
	if rev.ResponderURL != "" {
		kv.KV("Responder URL", rev.ResponderURL)
	}
	if rev.ResponderName != "" {
		kv.KV("Responder", rev.ResponderName)
	}
	if !rev.ProducedAt.IsZero() {
		kv.KV("Produced At", rev.ProducedAt.Format(time.RFC3339))
	}
	if !rev.ThisUpdate.IsZero() {
		kv.KV("This Update", rev.ThisUpdate.Format(time.RFC3339))
	}
	if !rev.NextUpdate.IsZero() {
		kv.KV("Next Update", rev.NextUpdate.Format(time.RFC3339))
	}
	if !rev.CheckedAt.IsZero() {
		kv.KV("Checked At", rev.CheckedAt.Format(time.RFC3339))
	}
	if !rev.RevokedAt.IsZero() {
		kv.KV("Revoked At", rev.RevokedAt.Format(time.RFC3339))
	}
	if rev.Reason != "" {
		kv.KV("Reason", rev.Reason)
	}
}

func verifyResultJSON(r *gempki.ValidationResult, opts certVerifyOpts) map[string]any {
	errors := make([]map[string]any, len(r.Errors))
	for i, e := range r.Errors {
		errors[i] = map[string]any{
			"code":    string(e.Code),
			"subject": e.Subject,
			"message": e.Message,
		}
	}
	warnings := make([]map[string]any, len(r.Warnings))
	for i, w := range r.Warnings {
		warnings[i] = map[string]any{
			"code":    string(w.Code),
			"subject": w.Subject,
			"message": w.Message,
		}
	}
	chain := make([]map[string]any, len(r.Chain))
	for i, c := range r.Chain {
		entry := map[string]any{}
		if i < len(r.Positions) {
			entry["position"] = string(r.Positions[i])
		}
		if c != nil {
			entry["subject"] = c.Subject.String()
			entry["issuer"] = c.Issuer.String()
			entry["serialNumber"] = c.SerialNumber.String()
			entry["notBefore"] = c.NotBefore.Format(time.RFC3339)
			entry["notAfter"] = c.NotAfter.Format(time.RFC3339)
		}
		if i < len(r.CertResults) && r.CertResults[i].Revocation != nil {
			entry["revocation"] = revocationJSON(r.CertResults[i].Revocation)
		}
		chain[i] = entry
	}
	out := map[string]any{
		"valid":    r.Valid,
		"errors":   errors,
		"warnings": warnings,
		"chain":    chain,
	}
	if len(r.Chain) > 0 && r.Chain[0] != nil {
		ee := r.Chain[0]
		cert := map[string]any{
			"subject":      ee.Subject.CommonName,
			"issuer":       ee.Issuer.CommonName,
			"serialNumber": colonHex(ee.SerialNumber.Bytes()),
			"notBefore":    ee.NotBefore.Format(time.RFC3339),
			"notAfter":     ee.NotAfter.Format(time.RFC3339),
			"publicKey":    fmt.Sprintf("%s %s", ee.PublicKeyAlgorithm, describePublicKey(ee.PublicKey)),
		}
		if opts.detectedType != gempki.CertTypeUnknown {
			cert["type"] = string(opts.detectedType)
			cert["typeOID"] = opts.detectedType.OID().String()
			if dp := opts.detectedType.DefaultProfile(); dp != nil {
				cert["defaultProfile"] = dp.Name
			}
			if compat := gempki.ProfilesForType(opts.detectedType); len(compat) > 0 {
				names := make([]string, len(compat))
				for i, p := range compat {
					names[i] = p.Name
				}
				cert["compatibleProfiles"] = names
			}
		}
		out["certificate"] = cert
	}
	if opts.resolvedFrom == "auto" {
		out["detectedType"] = string(opts.detectedType)
	}
	if opts.Profile != "" {
		out["profile"] = opts.Profile
	} else if opts.resolvedFrom == "none" {
		out["profile"] = "none"
	}
	return out
}

func revocationJSON(rev *gempki.RevocationResult) map[string]any {
	out := map[string]any{
		"status": string(rev.Status),
		"source": string(rev.Source),
	}
	if rev.ResponderURL != "" {
		out["responderURL"] = rev.ResponderURL
	}
	if rev.ResponderName != "" {
		out["responder"] = rev.ResponderName
	}
	if !rev.ProducedAt.IsZero() {
		out["producedAt"] = rev.ProducedAt.Format(time.RFC3339)
	}
	if !rev.ThisUpdate.IsZero() {
		out["thisUpdate"] = rev.ThisUpdate.Format(time.RFC3339)
	}
	if !rev.NextUpdate.IsZero() {
		out["nextUpdate"] = rev.NextUpdate.Format(time.RFC3339)
	}
	if !rev.CheckedAt.IsZero() {
		out["checkedAt"] = rev.CheckedAt.Format(time.RFC3339)
	}
	if !rev.RevokedAt.IsZero() {
		out["revokedAt"] = rev.RevokedAt.Format(time.RFC3339)
	}
	if rev.Reason != "" {
		out["reason"] = rev.Reason
	}
	return out
}

func parseAtFlag(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("--at must be RFC3339 (e.g. 2026-01-15T00:00:00Z): %w", err)
	}
	return &t, nil
}

// ---- lint -------------------------------------------------------------------

func newPKICertLintCmd(def envDef) *cobra.Command {
	var formatRaw, profile string
	cmd := &cobra.Command{
		Use:   "lint FILE|-",
		Short: "Run gempki profile checks against a certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsCertLint)
			if err != nil {
				return err
			}
			if profile == "" {
				return fmt.Errorf("--profile is required (smbauth | epavau | idp)")
			}
			certs, err := loadCertChain(args[0])
			if err != nil {
				return err
			}
			return runCertLint(cmd.Context(), def, certs, f, profile)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	cmd.Flags().StringVar(&profile, "profile", "", "profile: smbauth | epavau | idp")
	return cmd
}

func runCertLint(ctx context.Context, def envDef, certs []*x509.Certificate, f outputFormat, profile string) error {
	httpClient := newHTTPClient()
	ts, err := resolveTrustStoreFor(ctx, def, "", httpClient)
	if err != nil {
		return err
	}
	intermediates := append([]*x509.Certificate(nil), certs[1:]...)
	if tsl, terr := loadTSLCached(ctx, httpClient, def.TSLURL); terr == nil {
		for _, c := range gempki.IntermediateCAsFromTSL(tsl) {
			if c.Cert != nil {
				intermediates = append(intermediates, c.Cert)
			}
		}
	} else {
		slog.Warn("TSL load failed; lint chain build will rely on roots only", "env", def.Env, "err", terr)
	}
	opts := certVerifyOpts{Profile: profile, WithOCSP: false, resolvedFrom: "explicit"}
	v := buildValidator(def, ts, opts)
	result, err := v.Validate(ctx, append([]*x509.Certificate{certs[0]}, intermediates...))
	if err != nil {
		return err
	}
	if f == formatJSON {
		return printJSON(verifyResultJSON(result, opts))
	}
	return renderVerifyResultText(result, opts)
}
