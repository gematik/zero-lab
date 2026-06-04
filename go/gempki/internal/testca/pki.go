package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

// Node is a generated certificate paired with its private key.
//
// Cert is the parsed certificate (brainpool-aware via the sibling brainpool
// package — DON'T parse the DER with crypto/x509.ParseCertificate directly).
// Key is nil for cross-signed entries where the key lives on the original
// node.
type Node struct {
	Cert *x509.Certificate
	DER  []byte
	Key  *ecdsa.PrivateKey
}

// TestPKI is the assembled fixture. Phase 0 ships a minimal but
// representative set; later phases extend the struct as their validators
// arrive (Expired, Revoked, RogueRoot, RSA_Rogue, etc.).
type TestPKI struct {
	// Brainpool branch.
	RCA1     *Node // Brainpool P256r1 root
	SubCAHBA *Node // Brainpool P256r1 SubCA under RCA1
	EEArzt   *Node // Brainpool P256r1 EE with Admission(Arzt)

	// NIST branch (TI 2.0).
	RCA7      *Node // NIST P-256 root
	SubCAKomp *Node // NIST P-256 SubCA under RCA7
	EEZeta    *Node // NIST P-256 EE with EKU=serverAuth, SAN=zeta.ti-dienste.de

	// Cross-signing: brainpool RCA1 cross-signs NIST RCA7's key, so the
	// brainpool branch can transitively trust the NIST root during migration.
	CrossCertRCA1ForRCA7 *Node // Subject=RCA7, Issuer=RCA1, Key=nil

	// Mixed-curve chain: brainpool SubCA under RCA1, NIST EE under that SubCA.
	SubCAMixed *Node // Brainpool SubCA under RCA1
	EEMixed    *Node // NIST EE under SubCAMixed

	// Rogue root (NIST, not in any trust store) for unknown-CA tests.
	RogueRoot *Node
	EERogue   *Node

	// Time-edge EEs (Brainpool, under SubCAHBA unless noted).
	EEExpired     *Node // notAfter in the past
	EENotYetValid *Node // notBefore in the future

	// Expired SubCA + child whose own dates are fine. Use to confirm the
	// validator surfaces the parent's expiry separately from the EE.
	SubCAExpired   *Node
	EEUnderExpired *Node
}

// New generates a fresh test PKI. Reasonably fast (~50ms on Apple M-class).
// Each call produces fresh keys; tests should generally call once at
// TestMain or use sync.Once if multiple tests need the same fixture.
func New() (*TestPKI, error) {
	now := time.Now().UTC().Truncate(time.Second)
	tenYears := now.Add(10 * 365 * 24 * time.Hour)
	fiveYears := now.Add(5 * 365 * 24 * time.Hour)

	pki := &TestPKI{}

	// Brainpool root RCA1.
	rca1Key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen RCA1 key: %w", err)
	}
	pki.RCA1, err = selfSign(rca1Key, "GEM.RCA1 TEST-ONLY", now, tenYears)
	if err != nil {
		return nil, err
	}

	// Brainpool SubCA HBA under RCA1.
	subHBAKey, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen SubCAHBA key: %w", err)
	}
	pki.SubCAHBA, err = issue(subHBAKey, "GEM.SubCA-HBA TEST-ONLY", pki.RCA1, now, fiveYears, caOpts())
	if err != nil {
		return nil, err
	}

	// Brainpool EE Arzt under SubCAHBA, with Admission extension.
	eeArztKey, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen EEArzt key: %w", err)
	}
	admExt, err := AdmissionExtension(
		"Arzt",
		asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 30}, // gemSpec_OID Arzt person
		"80276001081234567890",
	)
	if err != nil {
		return nil, err
	}
	eeArztOpts := eeOpts()
	eeArztOpts.ExtraExtensions = append(eeArztOpts.ExtraExtensions, admExt)
	pki.EEArzt, err = issue(eeArztKey, "Dr. Arzt TEST-ONLY", pki.SubCAHBA, now, fiveYears, eeArztOpts)
	if err != nil {
		return nil, err
	}

	// NIST root RCA7.
	rca7Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen RCA7 key: %w", err)
	}
	pki.RCA7, err = selfSign(rca7Key, "GEM.RCA7 TEST-ONLY", now, tenYears)
	if err != nil {
		return nil, err
	}

	// NIST SubCA Komp under RCA7.
	subKompKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen SubCAKomp key: %w", err)
	}
	pki.SubCAKomp, err = issue(subKompKey, "GEM.SubCA-Komp TEST-ONLY", pki.RCA7, now, fiveYears, caOpts())
	if err != nil {
		return nil, err
	}

	// NIST EE ZETA with SAN + serverAuth.
	eeZetaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen EEZeta key: %w", err)
	}
	zetaOpts := eeOpts()
	zetaOpts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	zetaOpts.DNSNames = []string{"zeta.ti-dienste.de"}
	pki.EEZeta, err = issue(eeZetaKey, "zeta.ti-dienste.de TEST-ONLY", pki.SubCAKomp, now, fiveYears, zetaOpts)
	if err != nil {
		return nil, err
	}

	// Cross-sign: RCA1 (brainpool) issues a cert binding RCA7's name + key.
	crossOpts := caOpts()
	crossOpts.Subject = pkix.Name{CommonName: "GEM.RCA7 TEST-ONLY", Country: []string{"DE"}}
	crossOpts.NotBefore = now
	crossOpts.NotAfter = tenYears
	crossOpts.Serial = randomSerial()
	crossDER, err := CreateCertificate(crossOpts, &rca7Key.PublicKey, pki.RCA1.Cert, rca1Key)
	if err != nil {
		return nil, fmt.Errorf("cross-sign RCA1→RCA7: %w", err)
	}
	crossCert, err := brainpool.ParseCertificate(crossDER)
	if err != nil {
		return nil, fmt.Errorf("parse cross cert: %w", err)
	}
	pki.CrossCertRCA1ForRCA7 = &Node{Cert: crossCert, DER: crossDER}

	// Mixed: brainpool SubCA under RCA1, NIST EE under it.
	subMixedKey, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen SubCAMixed key: %w", err)
	}
	pki.SubCAMixed, err = issue(subMixedKey, "GEM.SubCA-Mixed TEST-ONLY", pki.RCA1, now, fiveYears, caOpts())
	if err != nil {
		return nil, err
	}
	eeMixedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen EEMixed key: %w", err)
	}
	pki.EEMixed, err = issue(eeMixedKey, "mixed-curve-ee TEST-ONLY", pki.SubCAMixed, now, fiveYears, eeOpts())
	if err != nil {
		return nil, err
	}

	// Rogue root (NIST, untrusted) + EE.
	rogueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen RogueRoot key: %w", err)
	}
	pki.RogueRoot, err = selfSign(rogueKey, "ROGUE-ROOT NOT-VALID", now, tenYears)
	if err != nil {
		return nil, err
	}
	eeRogueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen EERogue key: %w", err)
	}
	pki.EERogue, err = issue(eeRogueKey, "rogue-ee NOT-VALID", pki.RogueRoot, now, fiveYears, eeOpts())
	if err != nil {
		return nil, err
	}

	// Time-edge fixtures.
	pastFrom := now.Add(-2 * 365 * 24 * time.Hour)
	pastTo := now.Add(-24 * time.Hour)
	futureFrom := now.Add(24 * time.Hour)
	futureTo := now.Add(365 * 24 * time.Hour)

	eeExpiredKey, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen EEExpired key: %w", err)
	}
	pki.EEExpired, err = issue(eeExpiredKey, "EE-Expired TEST-ONLY", pki.SubCAHBA, pastFrom, pastTo, eeOpts())
	if err != nil {
		return nil, err
	}

	eeNotYetKey, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen EENotYetValid key: %w", err)
	}
	pki.EENotYetValid, err = issue(eeNotYetKey, "EE-NotYetValid TEST-ONLY", pki.SubCAHBA, futureFrom, futureTo, eeOpts())
	if err != nil {
		return nil, err
	}

	// Expired SubCA + a child whose own dates are fine. ValidatePath should
	// flag the SubCA but not the EE — the chain still fails overall.
	subExpKey, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen SubCAExpired key: %w", err)
	}
	pki.SubCAExpired, err = issue(subExpKey, "GEM.SubCA-Expired TEST-ONLY", pki.RCA1, pastFrom, pastTo, caOpts())
	if err != nil {
		return nil, err
	}
	eeUnderExpKey, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen EEUnderExpired key: %w", err)
	}
	pki.EEUnderExpired, err = issue(eeUnderExpKey, "EE-UnderExpired TEST-ONLY", pki.SubCAExpired, now, fiveYears, eeOpts())
	if err != nil {
		return nil, err
	}

	return pki, nil
}

// selfSign builds a self-signed root with the canonical TI root profile:
// IsCA=true, BasicConstraints critical, KeyUsage=keyCertSign|cRLSign.
func selfSign(key *ecdsa.PrivateKey, cn string, notBefore, notAfter time.Time) (*Node, error) {
	opts := caOpts()
	opts.Subject = pkix.Name{CommonName: cn, Country: []string{"DE"}}
	opts.NotBefore = notBefore
	opts.NotAfter = notAfter
	opts.Serial = randomSerial()
	der, err := CreateCertificate(opts, &key.PublicKey, nil, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign %s: %w", cn, err)
	}
	cert, err := brainpool.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", cn, err)
	}
	return &Node{Cert: cert, DER: der, Key: key}, nil
}

// issue signs a child cert under issuer with the given options template.
func issue(key *ecdsa.PrivateKey, cn string, issuer *Node, notBefore, notAfter time.Time, base CertOptions) (*Node, error) {
	base.Subject = pkix.Name{CommonName: cn, Country: []string{"DE"}}
	base.NotBefore = notBefore
	base.NotAfter = notAfter
	base.Serial = randomSerial()
	der, err := CreateCertificate(base, &key.PublicKey, issuer.Cert, issuer.Key)
	if err != nil {
		return nil, fmt.Errorf("issue %s: %w", cn, err)
	}
	cert, err := brainpool.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", cn, err)
	}
	return &Node{Cert: cert, DER: der, Key: key}, nil
}

func caOpts() CertOptions {
	return CertOptions{
		IsCA:             true,
		BasicConstraints: true,
		KeyUsage:         x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func eeOpts() CertOptions {
	return CertOptions{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func randomSerial() *big.Int {
	s, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	return s
}
