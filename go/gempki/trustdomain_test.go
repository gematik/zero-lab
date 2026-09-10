package gempki_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
)

// embeddedRoot returns the first compiled-in root of the given environment.
// Real gematik data, no network.
func embeddedRoot(t *testing.T, env gempki.Environment) *x509.Certificate {
	t.Helper()
	ts, err := gempki.EmbeddedLoader{Env: env}.Load(context.Background())
	if err != nil {
		t.Fatalf("loading embedded roots for %s: %v", env, err)
	}
	roots := ts.Roots()
	if len(roots) == 0 {
		t.Fatalf("no embedded roots for %s", env)
	}
	return roots[0]
}

func TestDetectTrustDomainByRootIdentity(t *testing.T) {
	tests := []struct {
		env  gempki.Environment
		want gempki.TrustDomain
	}{
		{gempki.EnvProd, gempki.TrustDomainProd},
		{gempki.EnvRef, gempki.TrustDomainNonProd},
		{gempki.EnvTest, gempki.TrustDomainNonProd},
		{gempki.EnvDev, gempki.TrustDomainNonProd},
	}
	for _, tt := range tests {
		t.Run(string(tt.env), func(t *testing.T) {
			root := embeddedRoot(t, tt.env)
			got := gempki.DetectTrustDomain([]*x509.Certificate{root})
			if got.Domain != tt.want {
				t.Errorf("Domain = %q, want %q (detail: %s)", got.Domain, tt.want, got.Detail)
			}
			if got.Method != gempki.MethodRootIdentity {
				t.Errorf("Method = %q, want %q", got.Method, gempki.MethodRootIdentity)
			}
		})
	}
}

// TestDetectTrustDomainByChain mints EE → SubCA under a real embedded root. The
// root itself is kept out of the input so the root-identity phase cannot answer,
// and neither synthetic cert carries a TEST-ONLY marker, so only the chain phase
// can decide.
func TestDetectTrustDomainByChain(t *testing.T) {
	for _, tt := range []struct {
		env  gempki.Environment
		want gempki.TrustDomain
	}{
		{gempki.EnvProd, gempki.TrustDomainProd},
		{gempki.EnvRef, gempki.TrustDomainNonProd},
	} {
		t.Run(string(tt.env), func(t *testing.T) {
			root := embeddedRoot(t, tt.env)
			subCA := caUnder(t, root, pkix.Name{CommonName: "SOME.KOMP-CA1"})
			ee := issuedBy(t, subCA, pkix.Name{CommonName: "some-service.example.de"})

			got := gempki.DetectTrustDomain([]*x509.Certificate{ee, subCA})
			if got.Domain != tt.want {
				t.Errorf("Domain = %q, want %q (detail: %s)", got.Domain, tt.want, got.Detail)
			}
			if got.Method != gempki.MethodChain {
				t.Errorf("Method = %q, want %q (steps: %v)", got.Method, gempki.MethodChain, got.Steps)
			}
		})
	}
}

func TestDetectTrustDomainByMarkers(t *testing.T) {
	tests := []struct {
		name    string
		subject pkix.Name
		issuer  pkix.Name
		ocsp    []string
		want    gempki.TrustDomain
	}{
		{
			name:    "TEST-ONLY in subject CN",
			subject: pkix.Name{CommonName: "Arztpraxis Bernd Rosenstrauch TEST-ONLY"},
			issuer:  pkix.Name{CommonName: "GEM.SMCB-CA51 TEST-ONLY"},
			want:    gempki.TrustDomainNonProd,
		},
		{
			name:    "NOT-VALID in issuer O",
			subject: pkix.Name{CommonName: "some-service.example.de"},
			issuer:  pkix.Name{CommonName: "SomeCA", Organization: []string{"gematik GmbH NOT-VALID"}},
			want:    gempki.TrustDomainNonProd,
		},
		{
			name:    "test OCSP host",
			subject: pkix.Name{CommonName: "some-service.example.de"},
			issuer:  pkix.Name{CommonName: "SomeCA"},
			ocsp:    []string{"http://ocsp-testref.root-ca.ti-dienste.de/ocsp"},
			want:    gempki.TrustDomainNonProd,
		},
		{
			name:    "prod OCSP host, no markers",
			subject: pkix.Name{CommonName: "some-service.example.de"},
			issuer:  pkix.Name{CommonName: "SomeCA"},
			ocsp:    []string{"http://ocsp.root-ca.ti-dienste.de/ocsp"},
			want:    gempki.TrustDomainProd,
		},
		{
			// The asymmetry rule: no TEST-ONLY marker is not evidence of prod.
			name:    "no markers and no TI endpoint is undecidable",
			subject: pkix.Name{CommonName: "example.com"},
			issuer:  pkix.Name{CommonName: "Some Public CA"},
			want:    gempki.TrustDomainUnknown,
		},
		{
			// A prod-looking endpoint loses to an explicit test marker.
			name:    "conflicting signals resolve to non-prod",
			subject: pkix.Name{CommonName: "svc TEST-ONLY"},
			issuer:  pkix.Name{CommonName: "SomeCA"},
			ocsp:    []string{"http://ocsp.root-ca.ti-dienste.de/ocsp"},
			want:    gempki.TrustDomainNonProd,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := selfSigned(t, tt.subject, tt.issuer, tt.ocsp)
			got := gempki.DetectTrustDomain([]*x509.Certificate{c})
			if got.Domain != tt.want {
				t.Errorf("Domain = %q, want %q (detail: %q, steps: %v)", got.Domain, tt.want, got.Detail, got.Steps)
			}
			if tt.want != gempki.TrustDomainUnknown && got.Method != gempki.MethodMarkers {
				t.Errorf("Method = %q, want %q", got.Method, gempki.MethodMarkers)
			}
		})
	}
}

func TestDetectTrustDomainRecordsTrace(t *testing.T) {
	c := selfSigned(t, pkix.Name{CommonName: "example.com"}, pkix.Name{CommonName: "example.com"}, nil)
	got := gempki.DetectTrustDomain([]*x509.Certificate{c})
	if got.Domain != gempki.TrustDomainUnknown {
		t.Fatalf("Domain = %q, want unknown", got.Domain)
	}
	if len(got.Steps) != 3 {
		t.Fatalf("Steps = %v, want one per phase", got.Steps)
	}
	for i, want := range []gempki.TrustDomainMethod{gempki.MethodRootIdentity, gempki.MethodChain, gempki.MethodMarkers} {
		if got.Steps[i].Method != want {
			t.Errorf("Steps[%d].Method = %q, want %q", i, got.Steps[i].Method, want)
		}
		if got.Steps[i].Outcome == "" {
			t.Errorf("Steps[%d] has no outcome", i)
		}
	}
}

func TestDetectTrustDomainNoInput(t *testing.T) {
	if got := gempki.DetectTrustDomain(nil); got.Domain != gempki.TrustDomainUnknown {
		t.Errorf("Domain = %q, want unknown", got.Domain)
	}
}

// --- helpers ---------------------------------------------------------------

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func selfSigned(t *testing.T, subject, issuer pkix.Name, ocsp []string) *x509.Certificate {
	t.Helper()
	// Signed against a separate parent template: CreateCertificate takes the
	// issuer DN from the parent, so a self-signed template could never carry a
	// different issuer name.
	parentKey := newKey(t)
	parent := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               issuer,
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		OCSPServer:   ocsp,
	}
	return mint(t, tmpl, parent, &key.PublicKey, parentKey)
}

// caUnder mints an intermediate CA that looks issued by parent: same issuer DN,
// same AKI. CreateCertificate insists the signing key match the parent
// template's public key, and we obviously don't hold a gematik root key — so
// the parent template is a copy of the real root with our own public key swapped
// in. BuildChain only walks topology, so that is enough to link the two.
func caUnder(t *testing.T, parent *x509.Certificate, subject pkix.Name) *x509.Certificate {
	t.Helper()
	signerKey := newKey(t)
	stand := *parent
	stand.PublicKey = &signerKey.PublicKey

	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		SubjectKeyId:          []byte{0xCA, 0xFE, 0xBA, 0xBE},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	return mint(t, tmpl, &stand, &key.PublicKey, signerKey)
}

// issuedBy mints an end entity issued by parent — CreateCertificate copies the
// issuer DN and AKI from the parent template. The signature is not checked by
// BuildChain (topology only), which is why signing with a throwaway key rather
// than the parent's own key is enough.
func issuedBy(t *testing.T, parent *x509.Certificate, subject pkix.Name) *x509.Certificate {
	t.Helper()
	signerKey := newKey(t)
	stand := *parent
	stand.PublicKey = &signerKey.PublicKey

	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	return mint(t, tmpl, &stand, &key.PublicKey, signerKey)
}

func mint(t *testing.T, tmpl, parent *x509.Certificate, pub any, signer any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return c
}
