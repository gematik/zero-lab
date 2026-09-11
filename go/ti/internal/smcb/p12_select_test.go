package smcb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/pkcs12"
)

// bundle mints a bundle with one AUT-shaped and one OSIG-shaped identity, in
// that order when autFirst, so selection cannot be mistaken for "first wins".
// With roundTrip the bags go through the PKCS#12 encoder and decoder, which
// today keeps localKeyId but drops friendlyName — so only the alias-free
// cases can use it.
func bundle(t *testing.T, autFirst, roundTrip bool) *pkcs12.Bags {
	t.Helper()
	aut := identity(t, "aut", x509.KeyUsageDigitalSignature)
	osig := identity(t, "osig", x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment)
	bags := &pkcs12.Bags{}
	for _, id := range orderOf(autFirst, aut, osig) {
		bags.Certificates = append(bags.Certificates, id.cert)
		bags.PrivateKeys = append(bags.PrivateKeys, id.key)
	}
	if !roundTrip {
		return bags
	}
	der, err := pkcs12.Encode(bags, []byte("00"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := pkcs12.Decode(der, []byte("00"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return decoded
}

type testIdentity struct {
	cert pkcs12.CertificateBag
	key  pkcs12.PrivateKeyBag
}

func orderOf(autFirst bool, aut, osig testIdentity) []testIdentity {
	if autFirst {
		return []testIdentity{aut, osig}
	}
	return []testIdentity{osig, aut}
}

func identity(t *testing.T, name string, usage x509.KeyUsage) testIdentity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     usage,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	localKeyID := []byte(name)
	return testIdentity{
		cert: pkcs12.CertificateBag{Raw: certDER, FriendlyName: name, LocalKeyID: localKeyID},
		key:  pkcs12.PrivateKeyBag{Raw: keyDER, FriendlyName: name, LocalKeyID: localKeyID},
	}
}

func TestSelectPair_PrefersAuthCertWithDefaultAlias(t *testing.T) {
	for _, autFirst := range []bool{true, false} {
		for _, roundTrip := range []bool{false, true} {
			cert, key, err := selectPair(bundle(t, autFirst, roundTrip), DefaultAlias)
			if err != nil {
				t.Fatalf("autFirst=%v roundTrip=%v: %v", autFirst, roundTrip, err)
			}
			if cert.Subject.CommonName != "aut" {
				t.Errorf("autFirst=%v roundTrip=%v: selected %q, want the C.AUT pair", autFirst, roundTrip, cert.Subject.CommonName)
			}
			if string(key.LocalKeyID) != "aut" {
				t.Errorf("autFirst=%v roundTrip=%v: key %x does not belong to the selected cert", autFirst, roundTrip, key.LocalKeyID)
			}
		}
	}
}

func TestSelectPair_ExplicitAliasWins(t *testing.T) {
	cert, _, err := selectPair(bundle(t, true, false), "osig")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "osig" {
		t.Errorf("selected %q, want osig", cert.Subject.CommonName)
	}
	if _, _, err := selectPair(bundle(t, true, false), "nope"); err == nil {
		t.Error("unknown alias must be an error")
	}
}

func TestSelectPair_SinglePairIgnoresAlias(t *testing.T) {
	osig := identity(t, "only", x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment)
	bags := &pkcs12.Bags{Certificates: []pkcs12.CertificateBag{osig.cert}, PrivateKeys: []pkcs12.PrivateKeyBag{osig.key}}
	cert, _, err := selectPair(bags, "whatever")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "only" {
		t.Errorf("selected %q", cert.Subject.CommonName)
	}
}
