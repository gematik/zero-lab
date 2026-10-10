package ti

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/epa/vau"
)

// fakeRunner answers each run from a script keyed by the command words, and records
// what it was asked.
type fakeRunner struct {
	t       *testing.T
	answers map[string]string
	errors  map[string]*Error
	calls   [][]string
	stdins  [][]byte
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	f.stdins = append(f.stdins, stdin)
	key := strings.Join(args[:2], " ")
	if err, ok := f.errors[key]; ok {
		return nil, err
	}
	answer, ok := f.answers[key]
	if !ok {
		f.t.Fatalf("unexpected ti call: %v", args)
	}
	return []byte(answer), nil
}

const inspectAnswer = `{"schema":1,"source":{"kind":"p12","name":"smcb.p12"},"telematik_id":"1-2-ARZT-1",
"signing":{"alg":"ES256","curve":"brainpoolP256r1"},
"certificate":{"subject":"CN=Praxis TEST-ONLY,O=gematik,C=DE","pem":"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
"admission":{"profession_items":["Betriebsstaette Arzt"],"profession_oids":[{"oid":"1.2.276.0.76.4.50","name":"x"}],"registration_number":"1-2-ARZT-1"}},"chain":[]}`

func TestIdentitySourceArgs(t *testing.T) {
	cases := []struct {
		source IdentitySource
		want   string
		err    bool
	}{
		{IdentitySource{P12Path: "a.p12"}, "--p12 a.p12", false},
		{IdentitySource{P12Path: "a.p12", P12PasswordPath: "pw"}, "--p12 a.p12 --p12-password-path pw", false},
		{IdentitySource{P12Path: "a.p12", P12Password: "00"}, "--p12 a.p12 --p12-password 00", false},
		{IdentitySource{CertPath: "c.pem", KeyPath: "k.pem"}, "--cert c.pem --key k.pem", false},
		{IdentitySource{Card: "SMC-B-7"}, "--card SMC-B-7", false},
		{IdentitySource{Card: "SMC-B-7", Connector: "praxis"}, "--card SMC-B-7 --connector praxis", false},
		{IdentitySource{CertPath: "c.pem"}, "", true},
		{IdentitySource{P12Path: "a.p12", Card: "x"}, "", true},
		{IdentitySource{}, "", true},
	}
	for _, c := range cases {
		args, err := c.source.Args()
		if c.err {
			if err == nil {
				t.Errorf("%+v: expected an error", c.source)
			}
			continue
		}
		if err != nil {
			t.Errorf("%+v: %v", c.source, err)
		}
		if got := strings.Join(args, " "); got != c.want {
			t.Errorf("%+v: %q, want %q", c.source, got, c.want)
		}
	}
}

func TestIdentityInspectAndSign(t *testing.T) {
	runner := &fakeRunner{t: t, answers: map[string]string{
		"identity inspect": inspectAnswer,
		"identity sign":    `{"schema":1,"jws":"h.p.s","alg":"ES256","header":{},"identity":{}}`,
	}}
	id, err := NewIdentity(context.Background(), runner, IdentitySource{P12Path: "smcb.p12", P12PasswordPath: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject() != "CN=Praxis TEST-ONLY,O=gematik,C=DE" || id.CommonName() != "Praxis TEST-ONLY" {
		t.Errorf("subject %q, CN %q", id.Subject(), id.CommonName())
	}
	if id.TelematikID() != "1-2-ARZT-1" || id.Curve() != "brainpoolP256r1" {
		t.Errorf("telematik %q curve %q", id.TelematikID(), id.Curve())
	}
	if string(id.CertificateDER()) != "\x01\x02\x03" {
		t.Errorf("DER %x", id.CertificateDER())
	}
	a := id.Admission()
	if a == nil || a.RegistrationNumber != "1-2-ARZT-1" || a.ProfessionOIDs[0] != "1.2.276.0.76.4.50" || a.ProfessionItems[0] != "Betriebsstaette Arzt" {
		t.Errorf("admission %+v", a)
	}
	if want := "identity inspect --p12 smcb.p12 --p12-password-path pw"; strings.Join(runner.calls[0], " ") != want {
		t.Errorf("inspect args %v", runner.calls[0])
	}

	jws, err := id.SignJWT(context.Background(),
		map[string]any{"typ": "JWT", "alg": "BP256R1", "cty": "NJWT", "x5c": []string{"ignored"}},
		map[string]any{"nonce": "n", "iat": 1})
	if err != nil {
		t.Fatal(err)
	}
	if jws != "h.p.s" {
		t.Errorf("jws %q", jws)
	}
	call := strings.Join(runner.calls[1], " ")
	for _, want := range []string{"identity sign --claims - --p12 smcb.p12 --p12-password-path pw", "--typ JWT", "--alg BP256R1", `--header cty="NJWT"`} {
		if !strings.Contains(call, want) {
			t.Errorf("sign args %q lack %q", call, want)
		}
	}
	if strings.Contains(call, "x5c") {
		t.Errorf("x5c is the tool's: %q", call)
	}
	var claims map[string]any
	if err := json.Unmarshal(runner.stdins[1], &claims); err != nil || claims["nonce"] != "n" {
		t.Errorf("claims on stdin: %s", runner.stdins[1])
	}
}

func TestAuthenticatorArgsAndRefusal(t *testing.T) {
	runner := &fakeRunner{t: t, answers: map[string]string{
		"idpd authenticate": `{"schema":1,"code":"C","state":"s1","redirect_url":"https://rp/cb?code=C","idp":{"issuer":"i"},"identity":{},"challenge":{},"warnings":["idp_certificates_unverified"]}`,
	}}
	a := &Authenticator{Runner: runner, Source: IdentitySource{Card: "SMC-B-7"}, Env: "ref"}
	redirect, err := a.Authenticate(context.Background(), "https://idp/auth?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Code != "C" || redirect.State != "s1" {
		t.Errorf("%+v", redirect)
	}
	if want := "idpd authenticate --auth-url https://idp/auth?x=1 --card SMC-B-7 --env ref"; strings.Join(runner.calls[0], " ") != want {
		t.Errorf("args %v", runner.calls[0])
	}

	refused := &fakeRunner{t: t, errors: map[string]*Error{
		"idpd authenticate": {Kind: "idpd_error", Message: "IDP refused: access_denied: Karte unbekannt (gematik_code 2030)", ExitCode: 3},
	}}
	a.Runner = refused
	_, err = a.Authenticate(context.Background(), "https://idp/auth")
	var tiErr *Error
	if !errors.As(err, &tiErr) || tiErr.Kind != "idpd_error" || !strings.Contains(err.Error(), "Karte unbekannt") {
		t.Errorf("refusal: %v", err)
	}
}

func TestVerifierReadsBothVerdicts(t *testing.T) {
	runner := &fakeRunner{t: t,
		answers: map[string]string{
			"pki verify-signature": `{"schema":1,"valid":true,"hash":"SHA-256","signature_format":"der","data_bytes":3,"certificate":{}}`,
		},
		errors: map[string]*Error{
			// Not valid is exit 1 with a report.
			"pki verify": {Kind: "", ExitCode: 1, Stdout: []byte(`{"schema":1,"valid":false,"environment":{"name":"ref"},"profile":{"name":"epa-vau-aut"},"errors":[{"code":"cert_revoked","message":"revoked"}],"warnings":[]}`)},
		}}
	v := &Verifier{Runner: runner, Offline: true}
	verdict, err := v.VerifyVAU(context.Background(), &vau.CertData{Cert: []byte{1}, CA: []byte{2}, RCAChain: [][]byte{{3}}}, []byte("keys"), []byte("sig"))
	if err != nil {
		t.Fatal(err)
	}
	if verdict.ChainValid || !verdict.SignatureValid || verdict.OK() {
		t.Errorf("%+v", verdict)
	}
	if verdict.Environment != "ref" || verdict.Profile != "epa-vau-aut" || verdict.ChainErrors[0] != "cert_revoked: revoked" || verdict.SignatureFormat != "der" {
		t.Errorf("%+v", verdict)
	}
	verify := strings.Join(runner.calls[0], " ")
	if !strings.HasPrefix(verify, "pki verify ") || !strings.Contains(verify, "--env auto") || !strings.Contains(verify, "--offline") {
		t.Errorf("verify args %q", verify)
	}
	chain := runner.calls[0][2]
	if _, err := os.Stat(chain); !os.IsNotExist(err) {
		t.Errorf("temp dir %s not removed", filepath.Dir(chain))
	}
}

func TestParseErrorAndSchema(t *testing.T) {
	err := parseError(4, []byte("diag line\n{\"schema\":1,\"error\":{\"kind\":\"p12_password\",\"message\":\"wrong\",\"hint\":\"pass it\"}}\n"), nil)
	if err.Kind != "p12_password" || err.Message != "wrong" || err.Hint != "pass it" || err.ExitCode != 4 {
		t.Errorf("%+v", err)
	}
	if err := parseError(2, []byte("usage: nope"), nil); err.Kind != "" || err.Message != "usage: nope" {
		t.Errorf("%+v", err)
	}
	if checkSchema([]byte(`{"schema":2}`)) == nil || checkSchema([]byte(`nope`)) == nil || checkSchema([]byte(`{"schema":1}`)) != nil {
		t.Error("schema check")
	}
	if got := redact([]string{"--p12-password", "secret", "--p12", "a"}); got[1] != "***" || got[3] != "a" {
		t.Errorf("%v", got)
	}
}

// The real binary, when present: the contract check a program makes at start-up.
func TestBinaryVersion(t *testing.T) {
	if _, err := exec.LookPath("ti"); err != nil && os.Getenv("EPA_TI_BIN") == "" {
		t.Skip("no ti binary (EPA_TI_BIN or PATH)")
	}
	b, err := NewBinary()
	if err != nil {
		t.Fatal(err)
	}
	v, err := b.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "ti" || v.Version == "" {
		t.Errorf("%+v", v)
	}
}
