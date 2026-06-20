package gemidp_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/pkcs12"
	"golang.org/x/oauth2"
)

// TestGemIDP_SMCB authenticates against the gematik IDP-Dienst (reference env) using a real
// SMC-B identity loaded from a PKCS#12 file. It is env-guarded and skips unless an SMC-B P12 and
// the IDP client config are provided. This exercises the full Brainpool path end to end,
// including the jwx-free JOSE in brainpool/josebp (sign/verify/JWE/JWK).
//
// Required env:
//
//	GEMIDP_SMCB_P12           path to the SMC-B .p12/.pfx file
//	GEMIDP_CLIENT_ID          registered client id at the IDP
//	GEMIDP_BASE_URL           IDP base URL (reference)
//	GEMIDP_REDIRECT_URI       client redirect URI
//	GEMIDP_SCOPE              space-separated scopes
//
// Optional:
//
//	GEMIDP_SMCB_P12_PASSWORD  P12 password (default "00")
func TestGemIDP_SMCB(t *testing.T) {
	p12Path := os.Getenv("GEMIDP_SMCB_P12")
	if p12Path == "" {
		t.Skip("GEMIDP_SMCB_P12 not set — skipping SMC-B gematik IDP test")
	}
	if os.Getenv("GEMIDP_CLIENT_ID") == "" {
		t.Skip("GEMIDP_CLIENT_ID not set — skipping (IDP client config required)")
	}
	password := os.Getenv("GEMIDP_SMCB_P12_PASSWORD")
	if password == "" {
		password = "00"
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))

	prk, cert, err := loadSMCBAuthIdentity(p12Path, password)
	if err != nil {
		t.Fatalf("load SMC-B AUT identity from %s: %v", p12Path, err)
	}
	t.Logf("SMC-B AUT identity: subject=%q curve=%s", cert.Subject.String(), prk.Curve.Params().Name)

	cfg := gemidp.ClientConfig{
		UserAgent:   "zero-lab-testcase",
		Environment: gemidp.EnvironmentReference,
		BaseURL:     os.Getenv("GEMIDP_BASE_URL"),
		ClientID:    os.Getenv("GEMIDP_CLIENT_ID"),
		RedirectURI: os.Getenv("GEMIDP_REDIRECT_URI"),
		Scopes:      strings.Split(os.Getenv("GEMIDP_SCOPE"), " "),
	}
	client, err := gemidp.NewClientFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	verifier := oauth2.GenerateVerifier()
	authURL, err := client.AuthenticationURL("state", "nonce", verifier)
	if err != nil {
		t.Fatal(err)
	}

	authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Idp:        client.Idp,
		SignerFunc: gemidp.SignWithSoftkey(prk, cert),
	})
	if err != nil {
		t.Fatal(err)
	}

	codeRedirectURL, err := authenticator.Authenticate(authURL)
	if err != nil {
		t.Fatalf("authenticate with SMC-B: %v", err)
	}

	tokenResponse, err := client.ExchangeForIdentity(codeRedirectURL.Code, verifier)
	if err != nil {
		t.Fatalf("exchange code for identity: %v", err)
	}

	claims := make(map[string]any)
	if err := tokenResponse.Claims(&claims); err != nil {
		t.Fatal(err)
	}

	report := buildSMCBReport(smcbReportData{
		p12Path:  p12Path,
		cert:     cert,
		curve:    prk.Curve.Params().Name,
		baseURL:  cfg.BaseURL,
		clientID: cfg.ClientID,
		scope:    strings.Join(cfg.Scopes, " "),
		claims:   claims,
		idToken:  tokenResponse.IDTokenRaw,
	})
	t.Logf("\n%s", report)

	reportPath := os.Getenv("GEMIDP_SMCB_REPORT")
	if reportPath == "" {
		reportPath = filepath.Join("test-reports", fmt.Sprintf("smcb-%s.md", time.Now().UTC().Format("20060102-150405")))
	}
	if dir := filepath.Dir(reportPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Logf("warning: failed to create report dir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(reportPath, []byte(report), 0o644); err != nil {
		t.Logf("warning: failed to write report to %s: %v", reportPath, err)
	} else {
		t.Logf("test report written to %s", reportPath)
	}
}

type smcbReportData struct {
	p12Path  string
	cert     *x509.Certificate
	curve    string
	baseURL  string
	clientID string
	scope    string
	claims   map[string]any
	idToken  string
}

// buildSMCBReport renders a human-reviewable Markdown report of the SMC-B authentication run.
func buildSMCBReport(d smcbReportData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# gemidp SMC-B authentication — test report\n\n")
	fmt.Fprintf(&b, "_Generated %s_\n\n", time.Now().UTC().Format(time.RFC3339))

	fmt.Fprintf(&b, "## SMC-B identity (PKCS#12)\n\n")
	fmt.Fprintf(&b, "- File: `%s`\n", d.p12Path)
	fmt.Fprintf(&b, "- Subject CN: %s\n", d.cert.Subject.CommonName)
	fmt.Fprintf(&b, "- Organization: %s\n", strings.Join(d.cert.Subject.Organization, ", "))
	fmt.Fprintf(&b, "- Telematik-ID (subject serial): %s\n", d.cert.Subject.SerialNumber)
	fmt.Fprintf(&b, "- Signing curve: %s\n", d.curve)
	fmt.Fprintf(&b, "- Certificate validity: %s – %s\n", d.cert.NotBefore.Format("2006-01-02"), d.cert.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(&b, "- Issuer CN: %s\n\n", d.cert.Issuer.CommonName)

	fmt.Fprintf(&b, "## Authentication flow\n\n")
	fmt.Fprintf(&b, "- IDP: `%s` (reference)\n", d.baseURL)
	fmt.Fprintf(&b, "- Client: `%s`\n", d.clientID)
	fmt.Fprintf(&b, "- Scope: `%s`\n", d.scope)
	for _, step := range []string{
		"Loaded SMC-B AUT identity from PKCS#12",
		"Built authorization URL",
		"Signed the IDP challenge (BP256R1 via brainpool/josebp)",
		"Received the authorization code",
		"Exchanged the code for an identity token",
		"Parsed the identity claims",
	} {
		fmt.Fprintf(&b, "- [x] %s\n", step)
	}

	fmt.Fprintf(&b, "\n## Identity claims\n\n| Claim | Value |\n|---|---|\n")
	order := []string{
		"iss", "aud", "azp", "sub", "display_name", "given_name", "family_name",
		"organizationName", "organizationIK", "idNummer", "professionOID",
		"acr", "amr", "auth_time", "iat", "exp", "nonce", "jti",
	}
	seen := map[string]bool{}
	for _, k := range order {
		if v, ok := d.claims[k]; ok {
			fmt.Fprintf(&b, "| `%s` | %s |\n", k, formatClaimValue(k, v))
			seen[k] = true
		}
	}
	var rest []string
	for k := range d.claims {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		fmt.Fprintf(&b, "| `%s` | %s |\n", k, formatClaimValue(k, d.claims[k]))
	}

	if d.idToken != "" {
		fmt.Fprintf(&b, "\n## Identity token (id_token, decrypted JWT)\n\n```\n%s\n```\n", d.idToken)
	}

	fmt.Fprintf(&b, "\n## Result: ✅ PASS\n")
	return b.String()
}

func formatClaimValue(key string, v any) string {
	if f, ok := v.(float64); ok {
		switch key {
		case "auth_time", "iat", "exp", "nbf":
			return fmt.Sprintf("%d (%s)", int64(f), time.Unix(int64(f), 0).UTC().Format(time.RFC3339))
		}
	}
	switch val := v.(type) {
	case nil:
		return "—"
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%v", val)
	case []any:
		parts := make([]string, len(val))
		for i, e := range val {
			parts[i] = fmt.Sprintf("%v", e)
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", val)
	}
}

// loadSMCBAuthIdentity loads the authentication (AUT) identity from an SMC-B PKCS#12 file: the
// EC certificate with KeyUsage digitalSignature (and not contentCommitment, which marks OSIG),
// plus its matching Brainpool private key. The repo's brainpool parsers are used because stdlib
// crypto/x509 does not know the Brainpool curves.
func loadSMCBAuthIdentity(path, password string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	bags, err := pkcs12.Decode(data, []byte(password))
	if err != nil {
		return nil, nil, fmt.Errorf("decode pkcs12: %w", err)
	}

	// Parse every private key (Brainpool-aware).
	var keys []*ecdsa.PrivateKey
	for _, kb := range bags.PrivateKeys {
		raw, err := brainpool.ParsePKCS8PrivateKey(kb.Raw)
		if err != nil {
			continue
		}
		if k, ok := raw.(*ecdsa.PrivateKey); ok {
			keys = append(keys, k)
		}
	}

	for _, cb := range bags.Certificates {
		cert, err := brainpool.ParseCertificate(cb.Raw)
		if err != nil {
			continue // CA / unparseable
		}
		// AUT: digitalSignature set, contentCommitment (OSIG) not set.
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			continue
		}
		if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
			continue
		}
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		for _, k := range keys {
			if k.PublicKey.X.Cmp(pub.X) == 0 && k.PublicKey.Y.Cmp(pub.Y) == 0 {
				return k, cert, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no AUT identity (EC digitalSignature cert + matching key) found in %s", path)
}
