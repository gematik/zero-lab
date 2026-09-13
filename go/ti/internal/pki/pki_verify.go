package pki

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/tsl"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

// ---- verify -----------------------------------------------------------------

// verifyFlags is the flag set shared by `ti pki verify` and `ti pki <env>
// verify`. Both spellings run the same validation, so they must offer the same
// flags; bundling them here is what keeps the two from drifting apart.
type verifyFlags struct {
	formatRaw         string
	rootsPath         string
	intermediatesPath string
	profile           string
	atRaw             string
	issuerPath        string
	ocspResponder     string
	ocspMaxAge        time.Duration
	withOCSP          bool
	insecure          bool
}

func (vf *verifyFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&vf.formatRaw, "format", string(formatText), "output format: text, json")
	cmd.Flags().StringVar(&vf.rootsPath, "roots", "", "PEM file of trust anchors (default: env embedded roots)")
	cmd.Flags().StringVar(&vf.intermediatesPath, "intermediates", "", "PEM file of additional candidate intermediates")
	cmd.Flags().StringVar(&vf.profile, "profile", gempki.ProfileAuto, "profile-driven EE checks. '"+gempki.ProfileAuto+"' (default) picks the profile from the certificate; '"+gempki.ProfileNone+"' disables profile checks (chain-only). Explicit profiles: "+strings.Join(gempki.ProfileNames(), " | ")+". See `ti pki profiles list` for what each one validates.")
	cmd.Flags().BoolVar(&vf.withOCSP, "ocsp", false, "evaluate revocation via OCSP (AIA-driven). Profiles enable OCSP automatically per their gemSpec policy; this flag is for use without --profile.")
	cmd.Flags().StringVar(&vf.atRaw, "at", "", "validate at a specific time (RFC3339; default: now)")
	cmd.Flags().StringVar(&vf.issuerPath, "issuer", "", "issuing CA certificate PEM/DER, for a CA the TSL does not publish (default: resolved from the TSL)")
	cmd.Flags().StringVar(&vf.ocspResponder, "ocsp-responder", "", "query this OCSP responder instead of the one named in the certificate's AIA")
	cmd.Flags().DurationVar(&vf.ocspMaxAge, "ocsp-max-age", gempki.DefaultMaxResponseAge, "treat OCSP responses whose producedAt is older than this as unknown (TI responders sign on demand; raise it for cached responses)")
	// Removed in v0.21; registered hidden purely so the old spelling gets a
	// pointer at `ti pki inspect` instead of cobra's bare "unknown flag".
	cmd.Flags().BoolVar(&vf.insecure, "insecure", false, "")
	_ = cmd.Flags().MarkHidden("insecure")
	_ = cmd.RegisterFlagCompletionFunc("profile", completeProfile)
}

// parse validates the flags and turns them into the shape runCertVerify wants.
func (vf *verifyFlags) parse() (outputFormat, certVerifyOpts, error) {
	if vf.insecure {
		return "", certVerifyOpts{}, fmt.Errorf("--insecure has been removed; use `ti pki inspect FILE` to decode a certificate without validating it")
	}
	f, err := parseOutputFormat(vf.formatRaw, formatsVerify)
	if err != nil {
		return "", certVerifyOpts{}, err
	}
	if err := validateProfileName(vf.profile); err != nil {
		return "", certVerifyOpts{}, err
	}
	at, err := parseAtFlag(vf.atRaw)
	if err != nil {
		return "", certVerifyOpts{}, err
	}
	return f, certVerifyOpts{
		RootsPath:         vf.rootsPath,
		IntermediatesPath: vf.intermediatesPath,
		IssuerPath:        vf.issuerPath,
		Profile:           vf.profile,
		WithOCSP:          vf.withOCSP,
		OCSPResponder:     vf.ocspResponder,
		OCSPMaxAge:        vf.ocspMaxAge,
		At:                at,
	}, nil
}

// newPKIEnvVerifyCmd is `ti pki <env> verify` — the environment is named by the
// caller.
func newPKIEnvVerifyCmd(def common.EnvDef) *cobra.Command {
	var vf verifyFlags
	cmd := &cobra.Command{
		Use:   "verify FILE|-",
		Short: "Build a chain and validate against the env's gematik TI roots",
		Args:  cobra.ExactArgs(1),
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
			return runCertVerify(cmd.Context(), def, certs, f, opts)
		},
	}
	vf.register(cmd)
	return cmd
}

type certVerifyOpts struct {
	RootsPath         string
	IntermediatesPath string
	IssuerPath        string
	Profile           string
	WithOCSP          bool
	OCSPResponder     string
	OCSPMaxAge        time.Duration
	At                *time.Time

	// httpClient + TSLResponders feed the OCSP path inside buildValidator
	// so a delegated responder (TI-style cross-CA OCSP, e.g. KOMP-CAxx
	// answering for SMCB-CAxx) can be authorized via the TSL listing.
	httpClient    *http.Client
	tslResponders []*x509.Certificate
	intermediates []*x509.Certificate
	roots         *gempki.TrustStore

	// detectedEnvName and detection are set only by `ti pki verify`; the
	// per-env command names its environment and leaves both empty.
	detectedEnvName string
	detection       *gempki.TrustDomainResult

	// Auto-detection bookkeeping (populated when Profile == "auto"):
	//   detectedType — what DetectCertificateType returned for the EE
	//   resolvedFrom — "auto", "explicit", or "none" (drives display)
	//   profileMissing — auto ran but no profile accepts the detected type
	//   profileAmbiguous — auto ran, multiple profiles accept the type,
	//                      none owns the default → user must pick
	//   profileCandidates — when ambiguous, the profile names that match
	detectedType      gempki.CertificateType
	resolvedFrom      string
	selectReason      gempki.ProfileSelectReason
	selectDetail      string
	profileMissing    bool
	profileAmbiguous  bool
	profileCandidates []string
}

func runCertVerify(ctx context.Context, def common.EnvDef, certs []*x509.Certificate, f outputFormat, opts certVerifyOpts) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificate parsed from input")
	}
	// Resolve --profile auto / none into a concrete profile name. Selection
	// runs against the EE (certs[0]) and drives both the validator choice and
	// the "Profile" line in the output.
	switch strings.ToLower(opts.Profile) {
	case "", gempki.ProfileAuto:
		sel := gempki.SelectProfileForCert(certs[0])
		opts.detectedType = sel.Type
		opts.resolvedFrom = "auto"
		opts.selectReason = sel.Reason
		opts.selectDetail = sel.Detail
		switch sel.Reason {
		case gempki.ProfileSelectedByCert, gempki.ProfileSelectedByDefault:
			opts.Profile = sel.Profile.Name
			slog.Debug("gempki: profile auto-selected",
				"subject", certs[0].Subject.CommonName,
				"type", string(sel.Type),
				"profile", opts.Profile,
				"reason", string(sel.Reason),
				"detail", sel.Detail)
		case gempki.ProfileSelectAmbiguous:
			opts.profileAmbiguous = true
			opts.Profile = ""
			opts.profileCandidates = profileNames(sel.Candidates)
			slog.Debug("gempki: profile auto-selection is ambiguous",
				"subject", certs[0].Subject.CommonName,
				"type", string(sel.Type),
				"candidates", opts.profileCandidates)
		default:
			opts.profileMissing = true
			opts.Profile = ""
			slog.Debug("gempki: no profile matches",
				"subject", certs[0].Subject.CommonName,
				"type", string(sel.Type),
				"detail", sel.Detail)
		}
	case gempki.ProfileNone:
		opts.resolvedFrom = "none"
		opts.Profile = ""
	default:
		opts.resolvedFrom = "explicit"
		opts.detectedType = gempki.DetectCertificateType(certs[0])
	}
	httpClient := common.NewHTTPClient()
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
	// --issuer is --intermediates narrowed to the one CA that matters: the
	// certificate's own issuer, for the case where the TSL does not publish it
	// and the chain would otherwise not build at all.
	if opts.IssuerPath != "" {
		issuer, err := loadCertChain(opts.IssuerPath)
		if err != nil {
			return fmt.Errorf("load --issuer: %w", err)
		}
		intermediates = append(intermediates, issuer...)
	}
	// Always merge TSL intermediates — SMC-B/HBA chains rely on issuer CAs
	// that gematik publishes through the TSL, not the embedded roots. Also
	// pull TSL-listed OCSP responders so [buildValidator] can authorize a
	// delegated responder via the TSL-match path. A TSL fetch failure is
	// logged but not fatal; chain build proceeds with whatever we have.
	var tslResponders []*x509.Certificate
	list, terr := common.LoadTSLCached(ctx, httpClient, def.TSLURL)
	if terr != nil {
		slog.Warn("TSL load failed; chain build will rely on roots + supplied intermediates only", "env", def.Env, "err", terr)
	} else {
		for _, c := range tsl.IntermediateCAs(list) {
			if c.Cert != nil {
				intermediates = append(intermediates, c.Cert)
			}
		}
		for _, c := range tsl.OCSPResponders(list) {
			if c.Cert != nil {
				tslResponders = append(tslResponders, c.Cert)
			}
		}
	}
	opts.httpClient = httpClient
	opts.tslResponders = tslResponders
	opts.intermediates = intermediates
	opts.roots = ts

	v := buildValidator(ts, opts)
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
		if p, ok := gempki.LookupProfile(opts.Profile); ok &&
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
		return common.PrintJSON(verifyResultJSON(result, opts))
	}
	return renderVerifyResultText(result, opts)
}

// profileNames maps profiles to their names for the candidate list.
func profileNames(ps []*gempki.Profile) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

func resolveTrustStoreFor(ctx context.Context, def common.EnvDef, rootsPath string, httpClient *http.Client) (*gempki.TrustStore, error) {
	if rootsPath == "" {
		return gempki.FetchRoots(ctx, def.Env, httpClient)
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

func buildValidator(ts *gempki.TrustStore, opts certVerifyOpts) *gempki.Validator {
	var v *gempki.Validator
	if p, ok := gempki.LookupProfile(opts.Profile); ok {
		v = p.Validator(ts, opts.detectedType)
	} else {
		v = &gempki.Validator{TrustStore: ts, RevocationMode: gempki.RevocationModeDisabled}
	}
	if opts.At != nil {
		at := *opts.At
		v.TimeFunc = func() time.Time { return at }
	}
	// A profile carries its own revocation mode (see `ti pki profiles list`);
	// without one, --ocsp opts in to SoftFail and otherwise revocation stays
	// off so a plain chain check costs no network round trip.
	if opts.Profile == "" && !opts.WithOCSP {
		return v
	}
	client := opts.httpClient
	if client == nil {
		client = common.NewHTTPClient()
	}
	v.Revocation = &gempki.OCSPChecker{
		HTTPClient:     client,
		ResponderURL:   opts.OCSPResponder,
		MaxResponseAge: opts.OCSPMaxAge,
		TSLResponders:  opts.tslResponders,
		Intermediates:  opts.intermediates,
		Roots:          opts.roots,
	}
	if opts.Profile == "" {
		v.RevocationMode = gempki.RevocationModeSoftFail
	}
	return v
}

func renderVerifyResultText(result *gempki.ValidationResult, opts certVerifyOpts) error {
	kv := common.NewKVWriter()
	// Lead with which certificate was judged and, for `ti pki verify`, where.
	// Everything else the certificate contains is `ti pki inspect`'s job — this
	// command answers one question and shows the evidence for that answer.
	if opts.detectedEnvName != "" {
		kv.KV("Environment", opts.detectedEnvName+" (auto)")
	}
	if len(result.Chain) > 0 && result.Chain[0] != nil {
		ee := result.Chain[0]
		kv.KV("Subject", ee.Subject.CommonName)
		kv.KV("Issuer", ee.Issuer.CommonName)
	}
	kv.Section("Validation")
	verdict := "VALID"
	if !result.Valid {
		verdict = "INVALID"
	}
	kv.KV("Result", verdict)
	if opts.detectedType != gempki.CertTypeUnknown {
		kv.KV("Type", string(opts.detectedType))
	}
	kv.KV("Chain length", fmt.Sprintf("%d", len(result.Chain)))
	if len(result.Chain) > 0 && result.Chain[0] != nil {
		kv.KV("Expires", result.Chain[0].NotAfter.Format(time.RFC3339))
	}
	if opts.At != nil {
		kv.KV("Evaluated At", opts.At.Format(time.RFC3339))
	}
	switch {
	case opts.Profile != "" && opts.resolvedFrom == "auto":
		kv.KV("Profile", opts.Profile+" (auto)")
	case opts.Profile != "":
		kv.KV("Profile", opts.Profile)
	case opts.resolvedFrom == "none":
		kv.KV("Profile", "(none — chain-only)")
	}
	if len(result.Errors) > 0 {
		kv.Section("Errors")
		for _, e := range result.Errors {
			// The label is the code; gempki's own "gempki[code]: " prefix would only repeat it.
			kv.KV(string(e.Code), strings.TrimPrefix(e.Error(), fmt.Sprintf("gempki[%s]: ", e.Code)))
		}
		kv.EndSection()
	}
	if len(result.Warnings) > 0 {
		kv.Section("Warnings")
		for _, w := range result.Warnings {
			kv.KV(string(w.Code), strings.TrimPrefix(w.String(), fmt.Sprintf("gempki[%s] warning: ", w.Code)))
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

func writeRevocationDetail(kv *common.KVWriter, rev *gempki.RevocationResult) {
	kv.KV("Status", string(rev.Status))
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
	// The certificate block stays deliberately thin: `ti pki inspect --format
	// json` is the full decode, and duplicating it here is how the two drift.
	if len(r.Chain) > 0 && r.Chain[0] != nil {
		ee := r.Chain[0]
		out["certificate"] = map[string]any{
			"subject":  ee.Subject.CommonName,
			"issuer":   ee.Issuer.CommonName,
			"notAfter": ee.NotAfter.Format(time.RFC3339),
		}
	}
	if opts.detectedEnvName != "" {
		out["environment"] = opts.detectedEnvName
		det := map[string]any{}
		if opts.detection != nil {
			det["trustDomain"] = string(opts.detection.Domain)
			det["method"] = string(opts.detection.Method)
			det["detail"] = opts.detection.Detail
		}
		if opts.detectedEnvName == "ref" {
			det["alsoCovers"] = []string{"dev"}
			det["testNotRuledOut"] = true
		}
		out["environmentDetection"] = det
	}
	if opts.detectedType != gempki.CertTypeUnknown {
		out["type"] = string(opts.detectedType)
		out["typeOID"] = opts.detectedType.OID().String()
	}
	if opts.At != nil {
		out["evaluatedAt"] = opts.At.Format(time.RFC3339)
	}
	if opts.Profile != "" {
		out["profile"] = opts.Profile
		out["profileFrom"] = opts.resolvedFrom
		if opts.resolvedFrom == "auto" {
			out["profileSelectedBy"] = string(opts.selectReason)
			out["profileSelectDetail"] = opts.selectDetail
		}
	} else if opts.resolvedFrom == "none" {
		out["profile"] = "none"
	}
	return out
}

func revocationJSON(rev *gempki.RevocationResult) map[string]any {
	out := map[string]any{
		"status": string(rev.Status),
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
