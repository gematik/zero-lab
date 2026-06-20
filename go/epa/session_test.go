package epa_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/gemidp"
)

// The epa integration tests are env-guarded (like gemidp/smcb_test.go): they skip unless an SMC-B
// PKCS#12 and the ePA config are provided, and they go as far as the available config allows. The
// only operation needing VSDM material is Entitle, which lives in its own test (TestEPA_Entitle).
//
// Config via env (safe in ./.env):
//
//	EPA_SMCB_P12           path to the SMC-B .p12/.pfx file (gate; or use EPA_SMCB_CERT+KEY)
//	EPA_SMCB_P12_PASSWORD  P12 password (default "00")
//	EPA_SMCB_CERT          PEM certificate path (alternative to P12; needs EPA_SMCB_KEY)
//	EPA_SMCB_KEY           PEM private-key path (alternative to P12; needs EPA_SMCB_CERT)
//	EPA_ENV                ePA environment: dev|test|ref|prod (default "ref")
//	EPA_P1_INSURANT_ID     KVNR for provider 1 (default "X110600196"; set empty to skip provider 1)
//	EPA_P2_INSURANT_ID     KVNR for provider 2 (default "X110611629"; set empty to skip provider 2)
//	EPA_KVNRS_FILE         file with one KVNR per line (TestEPA_RecordsAvailability)
//	EPA_REPORT             report output directory/prefix (default test-reports/epa-<name>-<ts>.md)
//
// NEVER in ./.env, shell environment only (used only by TestEPA_Entitle):
//
//	VSDM_HMAC_KEY, VSDM_HMAC_KID

type providerCase struct {
	provider   epa.ProviderNumber
	insurantID string
}

type epaTestConfig struct {
	p12Path    string
	p12Pass    string
	certPath   string
	keyPath    string
	env        epa.Env
	providers  []providerCase
	reportPath string
}

// loadIdentity loads the SMC-B AUT identity from the configured PKCS#12 (preferred) or PEM pair.
func (cfg epaTestConfig) loadIdentity() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if cfg.p12Path != "" {
		return epa.LoadIdentityP12(cfg.p12Path, cfg.p12Pass)
	}
	certData, err := os.ReadFile(cfg.certPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := brainpool.ParseCertificatePEM(certData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", cfg.certPath, err)
	}
	keyData, err := os.ReadFile(cfg.keyPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := brainpool.ParsePrivateKeyPEM(keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", cfg.keyPath, err)
	}
	return key, cert, nil
}

// identitySource is a human label for the loaded identity (for reports).
func (cfg epaTestConfig) identitySource() string {
	if cfg.p12Path != "" {
		return cfg.p12Path
	}
	return cfg.certPath + " + " + cfg.keyPath
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadEPAConfig(t *testing.T) epaTestConfig {
	t.Helper()
	p12 := os.Getenv("EPA_SMCB_P12")
	certPath := os.Getenv("EPA_SMCB_CERT")
	keyPath := os.Getenv("EPA_SMCB_KEY")
	if p12 == "" && (certPath == "" || keyPath == "") {
		t.Skip("EPA_SMCB_P12 (or EPA_SMCB_CERT + EPA_SMCB_KEY) not set — skipping epa integration test")
	}
	env, err := epa.EnvFromString(envOr("EPA_ENV", "ref"))
	if err != nil {
		t.Fatalf("EPA_ENV: %v", err)
	}

	var providers []providerCase
	for _, pc := range []struct {
		provider epa.ProviderNumber
		envKey   string
		def      string
	}{
		{epa.ProviderNumber1, "EPA_P1_INSURANT_ID", "X110600196"},
		{epa.ProviderNumber2, "EPA_P2_INSURANT_ID", "X110611629"},
	} {
		id, ok := os.LookupEnv(pc.envKey)
		if !ok {
			id = pc.def // unset → default
		}
		if id == "" {
			continue // explicitly empty → skip this provider
		}
		providers = append(providers, providerCase{pc.provider, id})
	}

	return epaTestConfig{
		p12Path:    p12,
		p12Pass:    envOr("EPA_SMCB_P12_PASSWORD", "00"),
		certPath:   certPath,
		keyPath:    keyPath,
		env:        env,
		providers:  providers,
		reportPath: os.Getenv("EPA_REPORT"),
	}
}

// providePNFromShellEnv reads the VSDM HMAC material from the shell environment (never from .env)
// at call time. It is only ever invoked by Entitle, which TestEPA_Entitle gates on VSDM presence.
func providePNFromShellEnv(provideHCV epa.ProvideHCVFunc) epa.ProvidePNFunc {
	return func(insurantID string) (string, error) {
		hmacKey := os.Getenv("VSDM_HMAC_KEY")
		hmacKid := os.Getenv("VSDM_HMAC_KID")
		if hmacKey == "" || hmacKid == "" {
			return "", fmt.Errorf("VSDM_HMAC_KEY/VSDM_HMAC_KID not set in environment")
		}
		pn, err := epa.CalculatePNv2(hmacKey, hmacKid, provideHCV)
		if err != nil {
			return "", err
		}
		return pn(insurantID)
	}
}

func debugLogger() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

// establishAuthorizedSession loads the SMC-B identity from the configured PKCS#12, opens a VAU
// channel to the given provider's aggregator, and runs the full authorization handshake (client
// attest, IDP authentication via gemidp, auth code). No VSDM material is required.
func establishAuthorizedSession(t *testing.T, cfg epaTestConfig, provider epa.ProviderNumber) (*epa.Session, *x509.Certificate) {
	t.Helper()

	key, cert, err := cfg.loadIdentity()
	if err != nil {
		t.Fatalf("load SMC-B identity from %s: %v", cfg.identitySource(), err)
	}
	t.Logf("SMC-B AUT identity: subject=%q curve=%s", cert.Subject.String(), key.Curve.Params().Name)

	provideHCV := func(string) ([]byte, error) { return epa.CalculateHCV("20241023", "Berliner Str.___") }
	certFn := func() (*x509.Certificate, error) { return cert, nil }
	sf := &epa.SecurityFunctions{
		AuthnSignFunc:           brainpool.SignFuncPrivateKey(key),
		AuthnCertFunc:           certFn,
		ClientAssertionSignFunc: brainpool.SignFuncPrivateKey(key),
		ClientAssertionCertFunc: certFn,
		ProvidePN:               providePNFromShellEnv(provideHCV),
		ProvideHCV:              provideHCV,
	}

	client, err := epa.NewClient(cfg.env, provider, sf,
		epa.WithInsecureSkipVerify(), epa.WithTimeout(30*time.Second))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	session, err := client.OpenSession()
	if err != nil {
		t.Fatalf("OpenSession (VAU handshake): %v", err)
	}

	clientAttest, err := session.CreateClientAttest()
	if err != nil {
		t.Fatalf("CreateClientAttest: %v", err)
	}

	authzURI, err := session.SendAuthorizationRequestSC()
	if err != nil {
		t.Fatalf("SendAuthorizationRequestSC: %v", err)
	}
	t.Logf("authorization URI: %s", authzURI)

	authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Idp:        gemidp.GetIdpByEnvironment(epa.IDPEnvironment(cfg.env)),
		SignerFunc: gemidp.SignWithSoftkey(key, cert),
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	codeRedirectURL, err := authenticator.Authenticate(authzURI)
	if err != nil {
		t.Fatalf("authenticate with gematik IDP: %v", err)
	}

	if err := session.SendAuthCodeSC(epa.SendAuthCodeSCtype{
		AuthorizationCode: codeRedirectURL.Code,
		ClientAttest:      clientAttest,
	}); err != nil {
		t.Fatalf("SendAuthCodeSC: %v", err)
	}

	return session, cert
}

// TestEPA_Connect runs the full connect/authorize flow plus record-status and consent queries for
// every configured provider. It needs no VSDM material.
func TestEPA_Connect(t *testing.T) {
	cfg := loadEPAConfig(t)
	debugLogger()

	for _, pc := range cfg.providers {
		t.Run(fmt.Sprintf("provider%d", pc.provider), func(t *testing.T) {
			session, cert := establishAuthorizedSession(t, cfg, pc.provider)
			defer session.Close()

			steps := []string{
				"Loaded SMC-B AUT identity",
				"Opened VAU channel",
				"Created client attest (ES256)",
				"Sent authorization request",
				"Authenticated with gematik IDP",
				"Sent authorization code",
			}
			data := epaReportData{
				title: "epa connect", cert: cert, cfg: cfg,
				provider: pc.provider, insurantID: pc.insurantID,
				entitled: "not attempted (see TestEPA_Entitle)",
			}

			exists, err := session.GetRecordStatus(pc.insurantID)
			if err != nil {
				t.Fatalf("GetRecordStatus(%s): %v", pc.insurantID, err)
			}
			data.hasRecordStatus = true
			data.recordExists = exists
			steps = append(steps, fmt.Sprintf("Queried record status (exists=%v)", exists))
			t.Logf("record exists for %s on provider %d: %v", pc.insurantID, pc.provider, exists)

			consent, err := session.GetConsentDecisionInformation(pc.insurantID)
			if err != nil {
				t.Fatalf("GetConsentDecisionInformation(%s): %v", pc.insurantID, err)
			}
			data.consent = consent
			steps = append(steps, fmt.Sprintf("Queried consent decisions (%d)", len(consent.Data)))
			t.Logf("consent decisions for %s: %v", pc.insurantID, consent.Data)

			data.steps = steps
			writeEPAReport(t, cfg, fmt.Sprintf("connect-p%d", pc.provider), buildEPAReport(data))
		})
	}
}

// TestEPA_Entitle is the only VSDM-dependent test. Run it in a separate shell with VSDM_HMAC_KEY and
// VSDM_HMAC_KID exported (they must never be stored in .env). It writes a report per provider.
func TestEPA_Entitle(t *testing.T) {
	if os.Getenv("VSDM_HMAC_KEY") == "" || os.Getenv("VSDM_HMAC_KID") == "" {
		t.Skip("VSDM_HMAC_KEY/VSDM_HMAC_KID not set — skipping entitlement (export them in your shell, not .env)")
	}
	cfg := loadEPAConfig(t)
	debugLogger()

	for _, pc := range cfg.providers {
		t.Run(fmt.Sprintf("provider%d", pc.provider), func(t *testing.T) {
			session, cert := establishAuthorizedSession(t, cfg, pc.provider)
			defer session.Close()

			err := session.Entitle(pc.insurantID)
			data := epaReportData{
				title: "epa entitle", cert: cert, cfg: cfg,
				provider: pc.provider, insurantID: pc.insurantID,
				steps: []string{
					"Loaded SMC-B AUT identity",
					"Opened VAU channel + authorized",
				},
			}
			if err != nil {
				data.entitled = "❌ " + err.Error()
			} else {
				data.entitled = "✅ success"
			}
			data.steps = append(data.steps, "Entitled insurant "+pc.insurantID+": "+data.entitled)
			writeEPAReport(t, cfg, fmt.Sprintf("entitle-p%d", pc.provider), buildEPAReport(data))

			if err != nil {
				t.Fatalf("Entitle(%s): %v", pc.insurantID, err)
			}
		})
	}
}

// TestEPA_RecordsAvailability checks record status for a list of KVNRs from EPA_KVNRS_FILE against
// provider 1. It uses the /information endpoint (no VAU session) and needs no VSDM material.
func TestEPA_RecordsAvailability(t *testing.T) {
	cfg := loadEPAConfig(t)
	kvnrsFile := os.Getenv("EPA_KVNRS_FILE")
	if kvnrsFile == "" {
		t.Skip("EPA_KVNRS_FILE not set — skipping records availability test")
	}
	debugLogger()

	file, err := os.Open(kvnrsFile)
	if err != nil {
		t.Skipf("EPA_KVNRS_FILE %s not readable — skipping: %v", kvnrsFile, err)
	}
	defer file.Close()
	var recordIds []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			recordIds = append(recordIds, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading %s: %v", kvnrsFile, err)
	}

	key, cert, err := cfg.loadIdentity()
	if err != nil {
		t.Fatalf("load SMC-B identity from %s: %v", cfg.identitySource(), err)
	}
	certFn := func() (*x509.Certificate, error) { return cert, nil }
	sf := &epa.SecurityFunctions{
		AuthnSignFunc:           brainpool.SignFuncPrivateKey(key),
		AuthnCertFunc:           certFn,
		ClientAssertionSignFunc: brainpool.SignFuncPrivateKey(key),
		ClientAssertionCertFunc: certFn,
	}
	client, err := epa.NewClient(cfg.env, epa.ProviderNumber1, sf,
		epa.WithInsecureSkipVerify(), epa.WithTimeout(30*time.Second))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	for _, recordId := range recordIds {
		exists, err := client.GetRecordStatus(recordId)
		if err != nil {
			t.Fatalf("GetRecordStatus(%s): %v", recordId, err)
		}
		if exists {
			t.Logf("record %s exists", recordId)
		} else {
			t.Errorf("record %s does not exist", recordId)
		}
	}
}

type epaReportData struct {
	title           string
	cert            *x509.Certificate
	cfg             epaTestConfig
	provider        epa.ProviderNumber
	insurantID      string
	steps           []string
	hasRecordStatus bool
	recordExists    bool
	consent         *epa.GetConsentDecisionInformationType
	entitled        string
}

func buildEPAReport(d epaReportData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — provider %d — test report\n\n", d.title, d.provider)
	fmt.Fprintf(&b, "_Generated %s_\n\n", time.Now().UTC().Format(time.RFC3339))

	fmt.Fprintf(&b, "## SMC-B identity (PKCS#12)\n\n")
	fmt.Fprintf(&b, "- Identity: `%s`\n", d.cfg.identitySource())
	fmt.Fprintf(&b, "- Subject CN: %s\n", d.cert.Subject.CommonName)
	fmt.Fprintf(&b, "- Organization: %s\n", strings.Join(d.cert.Subject.Organization, ", "))
	fmt.Fprintf(&b, "- Signing curve: %s\n", curveName(d.cert))
	fmt.Fprintf(&b, "- Certificate validity: %s – %s\n\n", d.cert.NotBefore.Format("2006-01-02"), d.cert.NotAfter.Format("2006-01-02"))

	fmt.Fprintf(&b, "## ePA connection\n\n")
	fmt.Fprintf(&b, "- Environment: `%s`\n", d.cfg.env)
	fmt.Fprintf(&b, "- Provider: `%d` (`%s`)\n", d.provider, epa.ResolveBaseURL(d.cfg.env, d.provider))
	fmt.Fprintf(&b, "- Insurant (KVNR): `%s`\n", d.insurantID)
	fmt.Fprintf(&b, "\n## Flow\n\n")
	for _, step := range d.steps {
		fmt.Fprintf(&b, "- [x] %s\n", step)
	}

	if d.hasRecordStatus {
		fmt.Fprintf(&b, "\n## Record status\n\n- Record exists: %v\n", d.recordExists)
	}
	if d.consent != nil {
		fmt.Fprintf(&b, "\n## Consent decisions\n\n| Function | Decision |\n|---|---|\n")
		for _, c := range d.consent.Data {
			fmt.Fprintf(&b, "| `%s` | %s |\n", c.FunctionId, c.Decision)
		}
	}
	if d.entitled != "" {
		fmt.Fprintf(&b, "\n## Entitlement\n\n- %s\n", d.entitled)
	}

	fmt.Fprintf(&b, "\n## Result: ✅ PASS\n")
	return b.String()
}

func curveName(cert *x509.Certificate) string {
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return pub.Curve.Params().Name
	}
	return cert.SignatureAlgorithm.String()
}

func writeEPAReport(t *testing.T, cfg epaTestConfig, name, report string) {
	t.Helper()
	t.Logf("\n%s", report)
	path := cfg.reportPath
	if path == "" {
		path = filepath.Join("test-reports", fmt.Sprintf("epa-%s-%s.md", name, time.Now().UTC().Format("20060102-150405")))
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Logf("warning: failed to create report dir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(report), 0o644); err != nil {
		t.Logf("warning: failed to write report to %s: %v", path, err)
	} else {
		t.Logf("test report written to %s", path)
	}
}
