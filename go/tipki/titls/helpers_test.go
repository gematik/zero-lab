// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package titls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

const corpusDir = "../../../spec/pki-validation/testdata/"

// at is 2026-01-01T00:00:00Z, the reference time of every corpus case.
var at = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type manifest struct {
	Trust map[string]struct {
		Profile string   `json:"profile"`
		Roots   []string `json:"roots"`
		TSLCAs  *[]struct {
			Cert  string   `json:"cert"`
			Types []string `json:"types"`
		} `json:"tsl_cas"`
	} `json:"trust"`
	Cases []corpusCase `json:"cases"`
}

type corpusCase struct {
	Name          string   `json:"name"`
	Trust         string   `json:"trust"`
	Chain         []string `json:"chain"`
	Host          string   `json:"host"`
	At            string   `json:"at"`
	StapledOCSP   *string  `json:"stapled_ocsp"`
	ResponderOCSP *string  `json:"responder_ocsp"`
	CRL           *string  `json:"crl"`
	Expect        string   `json:"expect"`
	Warnings      []string `json:"warnings"`
}

func corpusFile(t testing.TB, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(corpusDir + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func optionalFile(t testing.TB, name *string) []byte {
	t.Helper()
	if name == nil {
		return nil
	}
	return corpusFile(t, *name)
}

func corpusDER(t testing.TB, name string) []byte {
	t.Helper()
	block, _ := pem.Decode(corpusFile(t, name))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s: no certificate", name)
	}
	return block.Bytes
}

func corpusCert(t testing.TB, name string) *x509.Certificate {
	t.Helper()
	cert, err := tipki.ParseCertificate(corpusDER(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func readManifest(t testing.TB) manifest {
	t.Helper()
	var m manifest
	if err := json.Unmarshal(corpusFile(t, "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// corpusStore is the corpus's ti trust: its root, and its CA as a verified TSL would list it.
func corpusStore(t testing.TB, m manifest, trust string) *tipki.TrustStore {
	t.Helper()
	material := m.Trust[trust]
	if material.TSLCAs == nil {
		return nil
	}
	store := &tipki.TrustStore{CATypes: map[string][]x509.OID{}}
	for _, root := range material.Roots {
		store.Roots = append(store.Roots, corpusCert(t, root))
	}
	for _, ca := range *material.TSLCAs {
		cert := corpusCert(t, ca.Cert)
		store.Intermediates = append(store.Intermediates, tipki.Intermediate{Certificate: cert, Provider: "TEST-ONLY"})
		for _, name := range ca.Types {
			certType, err := tipki.ParseCertificateType(name)
			if err != nil {
				t.Fatal(err)
			}
			store.CATypes[string(cert.Raw)] = append(store.CATypes[string(cert.Raw)], certType.OID())
		}
	}
	return store
}

// network answers OCSP and CRL requests with fixed bytes, nil for a source that does not answer, and counts
// what it is asked.
type network struct {
	ocsp, crl []byte
	asked     atomic.Int64
}

var errDown = errors.New("down")

func (n *network) OCSP(context.Context, string, []byte) ([]byte, error) {
	n.asked.Add(1)
	if n.ocsp == nil {
		return nil, errDown
	}
	return n.ocsp, nil
}

func (n *network) CRL(context.Context, string) ([]byte, error) {
	n.asked.Add(1)
	if n.crl == nil {
		return nil, errDown
	}
	return n.crl, nil
}

// fixedClock is a clock a test moves.
type fixedClock struct{ now atomic.Pointer[time.Time] }

func newClock(now time.Time) *fixedClock {
	clock := &fixedClock{}
	clock.set(now)
	return clock
}

func (c *fixedClock) set(now time.Time) { c.now.Store(&now) }
func (c *fixedClock) Now() time.Time    { return *c.now.Load() }

// responder is tipki's OCSP checker over n, on clock, with its own result cache off so that every question
// reaches the network.
func responder(n *network, clock *fixedClock) *tipki.OCSPChecker {
	checker := tipki.NewOCSPChecker(OCSPTransport(n))
	checker.Now, checker.CacheTTL = clock.Now, 0
	return checker
}

// issued is a test certificate with its key; keys exist only for the test's run.
type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// issue signs template with parent's key, or self-signs it when parent is nil.
func issue(t testing.TB, template *x509.Certificate, parent *issued) *issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = serial
	signerCert, signerKey := template, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &issued{cert: cert, key: key}
}

func caTemplate(name string, notBefore time.Time) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{Country: []string{"DE"}, Organization: []string{"TEST-ONLY"}, CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func serverTemplate(host string, notBefore time.Time) *x509.Certificate {
	return &x509.Certificate{
		Subject:      pkix.Name{Country: []string{"DE"}, Organization: []string{"TEST-ONLY"}, CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
}

var (
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidOCSPBasic     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidCertHash      = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 13}
)

type ocspCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	Serial        *big.Int
}

type ocspSingle struct {
	CertID     ocspCertID
	Good       asn1.Flag        `asn1:"tag:0"`
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type ocspData struct {
	Responder  asn1.RawValue
	ProducedAt time.Time `asn1:"generalized"`
	Responses  []ocspSingle
}

type ocspBasic struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

type ocspBytes struct {
	Type     asn1.ObjectIdentifier
	Response []byte
}

type ocspResponse struct {
	Status asn1.Enumerated
	Bytes  ocspBytes `asn1:"explicit,tag:0"`
}

// goodOCSP is a "good" response about cert, signed by its issuer itself, produced at produced and valid
// for an hour; withCertHash adds the TI's certHash extension.
func goodOCSP(t testing.TB, cert *x509.Certificate, issuer *issued, produced time.Time, withCertHash bool) []byte {
	t.Helper()
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	nameHash, keyHash := sha256.Sum256(issuer.cert.RawSubject), sha256.Sum256(spki.Key.Bytes)
	single := ocspSingle{
		CertID: ocspCertID{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			NameHash:      nameHash[:], KeyHash: keyHash[:], Serial: cert.SerialNumber,
		},
		ThisUpdate: produced.UTC().Truncate(time.Second),
		NextUpdate: produced.Add(time.Hour).UTC().Truncate(time.Second),
	}
	if withCertHash {
		certHash := sha256.Sum256(cert.Raw)
		value, err := asn1.Marshal(struct {
			Algorithm pkix.AlgorithmIdentifier
			Hash      []byte
		}{pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, certHash[:]})
		if err != nil {
			t.Fatal(err)
		}
		single.Extensions = []pkix.Extension{{Id: oidCertHash, Value: value}}
	}
	tbs, err := asn1.Marshal(ocspData{
		Responder:  asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: issuer.cert.RawSubject},
		ProducedAt: produced.UTC().Truncate(time.Second),
		Responses:  []ocspSingle{single},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbs)
	signature, err := issuer.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	basic, err := asn1.Marshal(ocspBasic{
		TBS:       asn1.RawValue{FullBytes: tbs},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA2},
		Signature: asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := asn1.Marshal(ocspResponse{Bytes: ocspBytes{Type: oidOCSPBasic, Response: basic}})
	if err != nil {
		t.Fatal(err)
	}
	return response
}
