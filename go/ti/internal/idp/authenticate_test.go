package idp

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/gematik/zero-lab/go/ti/internal/epa"
	"github.com/gematik/zero-lab/go/ti/internal/smcb"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"
)

const refAuthURL = "https://idp-ref.app.ti-dienste.de/auth?client_id=eRezeptApp&redirect_uri=https%3A%2F%2Fpep.example%2Foauth2%2Fcallback&response_type=code&scope=openid+e-rezept&state=s&nonce=n&code_challenge=c&code_challenge_method=S256"

func TestParseAuthorizationURL(t *testing.T) {
	deepLink := "authenticator://?" + url.Values{"challenge_path": {refAuthURL + "&cardType=SMC-B&callback=DIRECT"}}.Encode()

	for name, tc := range map[string]struct {
		in       string
		wantErr  string
		cardType string
	}{
		"deep link":       {in: deepLink, cardType: "SMC-B"},
		"plain":           {in: refAuthURL},
		"whitespace":      {in: "  " + refAuthURL + "\n"},
		"no challenge":    {in: "authenticator://?callback=DIRECT", wantErr: "challenge_path"},
		"http":            {in: strings.Replace(refAuthURL, "https://", "http://", 1), wantErr: "https"},
		"no client":       {in: "https://idp-ref.app.ti-dienste.de/auth?scope=openid", wantErr: "client_id"},
		"not a url":       {in: "::", wantErr: "missing protocol scheme"},
		"other deep link": {in: "authenticator://?challenge_path=ftp%3A%2F%2Fx", wantErr: "https"},
	} {
		t.Run(name, func(t *testing.T) {
			auth, err := parseAuthorizationURL(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			q := auth.URL.Query()
			if q.Get("cardType") != "" || q.Get("callback") != "" {
				t.Errorf("authenticator parameters not stripped: %s", auth.URL)
			}
			if auth.ClientID != "eRezeptApp" || auth.Scope != "openid e-rezept" || auth.Redirect != "https://pep.example/oauth2/callback" {
				t.Errorf("parsed %+v", auth)
			}
			if auth.IDP != "https://idp-ref.app.ti-dienste.de" || auth.CardType != tc.cardType {
				t.Errorf("idp %q card %q", auth.IDP, auth.CardType)
			}
			if q.Get("code_challenge") != "c" {
				t.Errorf("IDP parameters must survive: %s", auth.URL)
			}
		})
	}
}

func TestTrustedIDP(t *testing.T) {
	for host, want := range map[string]gemidp.Environment{
		"idp.app.ti-dienste.de":                      gemidp.EnvironmentProduction,
		"idp-ref.app.ti-dienste.de":                  gemidp.EnvironmentReference,
		"idp-test.app.ti-dienste.de":                 gemidp.EnvironmentTest,
		"idp-ref.zentral.idp.splitdns.ti-dienste.de": gemidp.EnvironmentReference,
		"idp.zentral.idp.splitdns.ti-dienste.de":     gemidp.EnvironmentProduction,
	} {
		auth := &authorization{URL: &url.URL{Scheme: "https", Host: host}}
		if err := trustedIDP(auth); err != nil {
			t.Errorf("%s: %v", host, err)
		} else if auth.Env != want {
			t.Errorf("%s: env %v, want %v", host, auth.Env, want)
		}
	}
	for _, host := range []string{"idp-ref.app.ti-dienste.de.evil.example", "evil.example", "localhost:8080"} {
		if err := trustedIDP(&authorization{URL: &url.URL{Scheme: "https", Host: host}}); err == nil {
			t.Errorf("%s accepted", host)
		}
	}
}

func stubIdentity() *smcb.Identity {
	return &smcb.Identity{
		Sign:   func([]byte) ([]byte, error) { return []byte("sig"), nil },
		Cert:   func() (*x509.Certificate, error) { return nil, errors.New("no cert in stub") },
		Source: "stub",
	}
}

func TestConsentSigner(t *testing.T) {
	auth, _ := parseAuthorizationURL(refAuthURL)
	challenge := gemidp.Challenge{Challenge: "c", UserConsent: gemidp.UserConsent{RequestedScopes: map[string]string{"openid": "id"}}}

	for name, tc := range map[string]struct {
		yes      bool
		ask      func(string) (bool, error)
		wantCode string
	}{
		"yes flag":    {yes: true, ask: func(string) (bool, error) { t.Fatal("asked despite --yes"); return false, nil }},
		"answer y":    {ask: func(string) (bool, error) { return true, nil }},
		"answer n":    {ask: func(string) (bool, error) { return false, nil }, wantCode: "consent_declined"},
		"no terminal": {ask: func(string) (bool, error) { return false, common.ErrNoTerminal }, wantCode: "consent_required"},
	} {
		t.Run(name, func(t *testing.T) {
			signed := false
			var consent *gemidp.UserConsent
			sign := func(gemidp.Challenge) (string, error) { signed = true; return "jws", nil }
			devnull, _ := os.Open(os.DevNull)
			defer devnull.Close()
			signer := consentSigner(auth, stubIdentity(), tc.yes, tc.ask, sign, &consent)
			out, err := signer(challenge)
			if tc.wantCode != "" {
				var f *failure
				if !errors.As(err, &f) || f.Code != tc.wantCode {
					t.Fatalf("err = %v, want code %s", err, tc.wantCode)
				}
				if signed {
					t.Fatal("signed without consent")
				}
			} else if err != nil || out != "jws" || !signed {
				t.Fatalf("out=%q err=%v signed=%v", out, err, signed)
			}
			if consent == nil || consent.RequestedScopes["openid"] != "id" {
				t.Errorf("consent not recorded: %+v", consent)
			}
		})
	}
}

// The auth flags are one set shared with the ePA commands; a flag on one
// that is missing or worded differently on the other is a bug.
func TestAuthFlagsMatchEPA(t *testing.T) {
	authCmd, err := find(NewCmd(), "idp authenticate")
	if err != nil {
		t.Fatal(err)
	}
	connectCmd, err := find(epa.NewCmd(), "epa connect")
	if err != nil {
		t.Fatal(err)
	}
	authCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "yes" {
			return
		}
		other := connectCmd.Flags().Lookup(f.Name)
		if other == nil {
			t.Errorf("--%s exists on idp authenticate but not on epa connect", f.Name)
			return
		}
		if other.Usage != f.Usage || other.DefValue != f.DefValue {
			t.Errorf("--%s differs: %q/%q vs %q/%q", f.Name, f.Usage, f.DefValue, other.Usage, other.DefValue)
		}
	})
}

func find(root *cobra.Command, path string) (*cobra.Command, error) {
	cmd, rest, err := root.Find(strings.Fields(path)[1:])
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New(path + ": not found")
	}
	return cmd, nil
}

// TestAuthenticateE2E signs a real challenge from the RU IDP with a real
// SMC-B P12. It needs a registered client and skips without the env vars.
func TestAuthenticateE2E(t *testing.T) {
	p12 := os.Getenv("TI_TEST_SMCB_P12")
	clientID := os.Getenv("TI_TEST_IDP_CLIENT_ID")
	if p12 == "" || clientID == "" {
		t.Skip("TI_TEST_SMCB_P12 and TI_TEST_IDP_CLIENT_ID not set; skipping IDP e2e")
	}
	client, err := gemidp.NewClientFromConfig(gemidp.ClientConfig{
		Environment:       gemidp.EnvironmentReference,
		ClientID:          clientID,
		RedirectURI:       os.Getenv("TI_TEST_IDP_REDIRECT_URI"),
		Scopes:            strings.Fields(os.Getenv("TI_TEST_IDP_SCOPE")),
		AuthenticatorMode: true,
		UserAgent:         "ti-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	deepLink, err := client.AuthenticationURL("state-e2e", "nonce-e2e", oauth2.GenerateVerifier())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(deepLink, "authenticator://") {
		t.Fatalf("expected an authenticator:// link, got %s", deepLink)
	}

	method := p12Method{path: p12, password: envOr("TI_TEST_SMCB_P12_PASSWORD", "00")}
	res, err := authenticate(context.Background(), deepLink, method, true, nil)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if res.Code == "" || res.State != "state-e2e" || !strings.Contains(res.RedirectURL, "code=") {
		t.Errorf("result %+v", res)
	}
	if res.Consent == nil || len(res.Consent.RequestedScopes) == 0 {
		t.Errorf("consent missing: %+v", res.Consent)
	}
	if res.CardType != "SMC-B" || res.ClientID != clientID {
		t.Errorf("result %+v", res)
	}
}

type p12Method struct{ path, password string }

func (m p12Method) Name() string { return "p12" }
func (m p12Method) Identity(context.Context) (*smcb.Identity, error) {
	return smcb.FromP12(m.path, smcb.DefaultAlias, m.password)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
