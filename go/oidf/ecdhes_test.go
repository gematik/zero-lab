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

package oidf

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josecipher "github.com/go-jose/go-jose/v4/cipher"

	"github.com/gematik/zero-lab/go/openid"
)

func ecdhKey(t testing.TB, key *ecdsa.PrivateKey) *ecdh.PrivateKey {
	t.Helper()
	agreement, err := key.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return agreement
}

// hsmSigner stands for a key in an HSM: a crypto.Signer and nothing else, so no code can reach for its private part.
type hsmSigner struct{ key *ecdsa.PrivateKey }

func (s hsmSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s hsmSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand, digest, opts)
}

// failingSigner is a signer whose HSM does not answer.
type failingSigner struct{ key *ecdsa.PrivateKey }

func (s failingSigner) Public() crypto.PublicKey { return s.key.Public() }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("HSM unavailable")
}

// hsmAgreement stands for an ID token key in an HSM, and counts its use.
type hsmAgreement struct {
	key   *ecdh.PrivateKey
	calls *atomic.Int64
}

func (a hsmAgreement) Public() crypto.PublicKey { return a.key.Public() }

func (a hsmAgreement) ECDH(remote *ecdh.PublicKey) ([]byte, error) {
	a.calls.Add(1)
	return a.key.ECDH(remote)
}

func selfSignedCertificate(t testing.TB, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func newTestKeys(t testing.TB) Keys {
	t.Helper()
	return Keys{
		Sign: hsmSigner{newTestKey(t)}, SignKID: "sign-kid",
		Decrypt: ecdhKey(t, newTestKey(t)), DecryptKID: "enc-kid",
		Client: selfSignedCertificate(t, newTestKey(t)), ClientKID: "client-kid",
	}
}

func TestKeysRule1_AnHSMSignerSignsTheStatement(t *testing.T) {
	key := newTestKey(t)
	rp := literalRelyingParty(t, hsmSigner{key})
	signed, err := rp.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openid.VerifyJWS(signed, keySetOf(key, "sign-kid"), trustAnchorKeys); err != nil {
		t.Fatal(err)
	}
	object, err := jose.ParseSignedCompact(string(signed), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if header := object.Signatures[0].Protected; header.KeyID != "sign-kid" || header.Algorithm != string(jose.ES256) {
		t.Errorf("header = %+v", header)
	}

	rp.keys.Sign = failingSigner{key}
	if _, err := rp.SignEntityStatement(); err == nil || !strings.Contains(err.Error(), "HSM unavailable") {
		t.Errorf("a failing signer: %v", err)
	}
}

func TestA_23194_TheIDTokenIsDecryptedThroughKeyAgreement(t *testing.T) {
	stub := newLoginStub(t)
	calls := new(atomic.Int64)
	stub.client.rp.keys.Decrypt = hsmAgreement{ecdhKey(t, stub.encKey), calls}
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	if _, err := stub.client.Exchange(t.Context(), openid.Login{Nonce: "n", Verifier: testVerifier}, "code"); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("%d key agreements", n)
	}
}

// gemSpec_IDP_FD A_23195: the ID token is decrypted with the key its header's kid names.
func TestA_23195_AnIDTokenForAnotherKIDIsRefused(t *testing.T) {
	stub := newLoginStub(t)
	signed := signJWS(t, stub.sigKey, "k", validIDTokenClaims())
	for kid, accept := range map[string]bool{"enc": true, "": true, "another": false} {
		encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: stub.encKey.Public(), KeyID: kid}, nil)
		if err != nil {
			t.Fatal(err)
		}
		object, err := encrypter.Encrypt([]byte(signed))
		if err != nil {
			t.Fatal(err)
		}
		if stub.idToken, err = object.CompactSerialize(); err != nil {
			t.Fatal(err)
		}
		_, err = stub.client.Exchange(t.Context(), openid.Login{Nonce: "n", Verifier: testVerifier}, "code")
		if accept && err != nil {
			t.Errorf("kid %q: %v", kid, err)
		}
		if !accept && !errors.Is(err, ErrIDTokenEncryption) {
			t.Errorf("kid %q: %v", kid, err)
		}
	}
}

// RFC 7518 §4.6.2: the content key comes out of the Concat KDF exactly as go-jose's own ECDH-ES derives it, with and
// without apu and apv, and a whole JWE decrypts to the same plaintext both ways.
func TestRFC7518_4_6_2_TheContentKeyIsDerivedAsGoJoseDerivesIt(t *testing.T) {
	recipient := newTestKey(t)
	ephemeral := newTestKey(t)
	for _, party := range [][2][]byte{{nil, nil}, {[]byte("Alice"), []byte("Bob")}, {make([]byte, maxPartyInfoBytes), nil}} {
		want := josecipher.DeriveECDHES(string(jose.A256GCM), party[0], party[1], recipient, &ephemeral.PublicKey, contentKeyBytes)
		z, err := ecdhKey(t, recipient).ECDH(ecdhKey(t, ephemeral).PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if got := concatKDF(z, string(jose.A256GCM), party[0], party[1]); string(got) != string(want) {
			t.Errorf("apu %q: %x, go-jose derives %x", party[0], got, want)
		}
	}

	plaintext := signJWS(t, newTestKey(t), "k", validIDTokenClaims())
	token := encryptForTest(t, recipient.Public(), jose.ECDH_ES, jose.A256GCM, plaintext)
	decrypt := func(key any) string {
		object, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := object.Decrypt(key)
		if err != nil {
			t.Fatal(err)
		}
		return string(decrypted)
	}
	byGoJose := decrypt(recipient)
	byAgreement := decrypt(opaqueDecrypter{agreement: ecdhKey(t, recipient), kid: "enc"})
	if byGoJose != plaintext || byAgreement != byGoJose {
		t.Errorf("go-jose %q, key agreement %q", byGoJose, byAgreement)
	}
}

// epkMember is a P-256 public key as the epk header carries it.
func epkMember(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	point := ecdhKey(t, key).PublicKey().Bytes()
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(point[33:]),
	}
}

func ecdhesHeader(epk any) jose.Header {
	return jose.Header{Algorithm: string(jose.ECDH_ES), ExtraHeaders: map[jose.HeaderKey]any{"enc": "A256GCM", "epk": epk}}
}

func TestRFC7518_4_6_AnEPKOffTheCurveIsRefused(t *testing.T) {
	calls := new(atomic.Int64)
	decrypter := opaqueDecrypter{agreement: hsmAgreement{ecdhKey(t, newTestKey(t)), calls}, kid: "enc"}
	epk := epkMember(t, newTestKey(t))
	y, err := base64.RawURLEncoding.DecodeString(epk["y"].(string))
	if err != nil {
		t.Fatal(err)
	}
	y[len(y)-1] ^= 1
	epk["y"] = base64.RawURLEncoding.EncodeToString(y)
	if _, err := decrypter.DecryptKey(nil, ecdhesHeader(epk)); !errors.Is(err, ErrIDTokenEncryption) || !strings.Contains(err.Error(), "no point of P-256") {
		t.Errorf("err = %v", err)
	}
	if calls.Load() != 0 {
		t.Error("the key agreed with a point off the curve")
	}
}

// RFC 7518 §4.6 and the relying party's registration: everything but ECDH-ES with A256GCM, a public P-256 epk and
// bounded apu and apv is refused before the key is used.
func TestRFC7518_4_6_TheHeaderIsReadStrictly(t *testing.T) {
	calls := new(atomic.Int64)
	decrypter := opaqueDecrypter{agreement: hsmAgreement{ecdhKey(t, newTestKey(t)), calls}, kid: "enc"}
	ephemeral := newTestKey(t)
	with := func(change func(jose.Header) jose.Header) jose.Header {
		header := ecdhesHeader(epkMember(t, ephemeral))
		return change(header)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, header := range map[string]jose.Header{
		"key wrapping":  with(func(h jose.Header) jose.Header { h.Algorithm = string(jose.ECDH_ES_A256KW); return h }),
		"A128GCM":       with(func(h jose.Header) jose.Header { h.ExtraHeaders["enc"] = "A128GCM"; return h }),
		"no enc":        with(func(h jose.Header) jose.Header { delete(h.ExtraHeaders, "enc"); return h }),
		"compressed":    with(func(h jose.Header) jose.Header { h.ExtraHeaders["zip"] = "DEF"; return h }),
		"another kid":   with(func(h jose.Header) jose.Header { h.KeyID = "another"; return h }),
		"no epk":        with(func(h jose.Header) jose.Header { delete(h.ExtraHeaders, "epk"); return h }),
		"epk not a JWK": with(func(h jose.Header) jose.Header { h.ExtraHeaders["epk"] = "x"; return h }),
		"epk with d": with(func(h jose.Header) jose.Header {
			h.ExtraHeaders["epk"].(map[string]any)["d"] = "AAAA"
			return h
		}),
		"epk RSA": with(func(h jose.Header) jose.Header {
			h.ExtraHeaders["epk"].(map[string]any)["kty"] = "RSA"
			return h
		}),
		"epk P-384": with(func(h jose.Header) jose.Header {
			h.ExtraHeaders["epk"] = map[string]any{
				"kty": "EC", "crv": "P-384",
				"x": base64.RawURLEncoding.EncodeToString(p384.X.FillBytes(make([]byte, 48))),
				"y": base64.RawURLEncoding.EncodeToString(p384.Y.FillBytes(make([]byte, 48))),
			}
			return h
		}),
		"epk x padded": with(func(h jose.Header) jose.Header {
			epk := h.ExtraHeaders["epk"].(map[string]any)
			epk["x"] = epk["x"].(string) + "="
			return h
		}),
		"apu too long": with(func(h jose.Header) jose.Header {
			h.ExtraHeaders["apu"] = base64.RawURLEncoding.EncodeToString(make([]byte, maxPartyInfoBytes+1))
			return h
		}),
		"apv no base64url": with(func(h jose.Header) jose.Header { h.ExtraHeaders["apv"] = "a+b/"; return h }),
		"apu a number":     with(func(h jose.Header) jose.Header { h.ExtraHeaders["apu"] = 1.0; return h }),
	} {
		if _, err := decrypter.DecryptKey(nil, header); !errors.Is(err, ErrIDTokenEncryption) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := decrypter.DecryptKey([]byte{1}, ecdhesHeader(epkMember(t, ephemeral))); !errors.Is(err, ErrIDTokenEncryption) {
		t.Errorf("an encrypted key: %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the key was used %d times", n)
	}
	if _, err := decrypter.DecryptKey(nil, ecdhesHeader(epkMember(t, ephemeral))); err != nil {
		t.Errorf("the registered header: %v", err)
	}
}

func TestServerRule17_AClientCertificateThatIsNotOfItsKeyIsRefused(t *testing.T) {
	keys := newTestKeys(t)
	keys.Client = selfSignedCertificate(t, newTestKey(t))
	keys.Client.PrivateKey = newTestKey(t)
	if err := keys.check(); !errors.Is(err, ErrKeys) || !strings.Contains(err.Error(), "not of its key") {
		t.Errorf("err = %v", err)
	}
}

// gemSpec_IDP_FD A_23196 and servers.md rule 17: keys that are missing, not P-256, without their kid or a client
// certificate that cannot be presented as published stop the start.
func TestA_23196_KeysThatAreNotAsRequiredAreRefused(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Keys){
		"no signing key":           func(k *Keys) { k.Sign = nil },
		"P-384 signing key":        func(k *Keys) { k.Sign = p384 },
		"no ID token key":          func(k *Keys) { k.Decrypt = nil },
		"X25519 ID token key":      func(k *Keys) { k.Decrypt = x25519 },
		"P-384 ID token key":       func(k *Keys) { k.Decrypt = ecdhKey(t, p384) },
		"P-384 client key":         func(k *Keys) { k.Client = selfSignedCertificate(t, p384) },
		"no signing kid":           func(k *Keys) { k.SignKID = "" },
		"no ID token kid":          func(k *Keys) { k.DecryptKID = "" },
		"no client kid":            func(k *Keys) { k.ClientKID = "" },
		"client without its Leaf":  func(k *Keys) { k.Client.Leaf = nil },
		"client without its chain": func(k *Keys) { k.Client.Certificate = nil },
		"client Leaf not presented": func(k *Keys) {
			k.Client.Leaf = selfSignedCertificate(t, k.Client.PrivateKey.(*ecdsa.PrivateKey)).Leaf
		},
		"client key no signer": func(k *Keys) { k.Client.PrivateKey = "not a key" },
	} {
		keys := newTestKeys(t)
		change(&keys)
		if err := keys.check(); !errors.Is(err, ErrKeys) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := newTestKeys(t).check(); err != nil {
		t.Errorf("keys as required: %v", err)
	}
}

// Servers rule 17: a key given as a nil pointer of its type is missing, and is refused rather than panicking on its
// first use.
func TestServerRule17_ANilKeyOfAKeyTypeIsRefused(t *testing.T) {
	for name, change := range map[string]func(*Keys){
		"signing key":    func(k *Keys) { k.Sign = (*ecdsa.PrivateKey)(nil) },
		"ID token key":   func(k *Keys) { k.Decrypt = (*ecdh.PrivateKey)(nil) },
		"client key":     func(k *Keys) { k.Client.PrivateKey = (*ecdsa.PrivateKey)(nil) },
		"untyped client": func(k *Keys) { k.Client.PrivateKey = nil },
	} {
		keys := newTestKeys(t)
		change(&keys)
		if err := keys.check(); !errors.Is(err, ErrKeys) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// gemSpec_IDP_FD A_23195: the kid selects one key, so two keys under one kid are refused.
func TestA_23195_TwoKeysUnderOneKIDAreRefused(t *testing.T) {
	for name, change := range map[string]func(*Keys){
		"signing and ID token": func(k *Keys) { k.DecryptKID = k.SignKID },
		"signing and client":   func(k *Keys) { k.ClientKID = k.SignKID },
		"ID token and client":  func(k *Keys) { k.ClientKID = k.DecryptKID },
	} {
		keys := newTestKeys(t)
		change(&keys)
		if err := keys.check(); !errors.Is(err, ErrKeys) || !strings.Contains(err.Error(), "share a kid") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// gemSpec_IDP_FD A_23194 and A_23183: the relying party publishes its signing key in the statement's jwks, and the
// ID token key with use enc and the client certificate as x5c in its openid_relying_party jwks, under the kids given.
func TestA_23183_TheKeysArePublishedUnderTheirKIDs(t *testing.T) {
	stub := newFederationStub(t)
	keys := newTestKeys(t)
	rp, err := New(t.Context(), testRelyingPartyConfig(t, stub), keys)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := rp.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Jwks struct {
			Keys []map[string]any `json:"keys"`
		} `json:"jwks"`
		Metadata struct {
			OpenidRelyingParty struct {
				Jwks struct {
					Keys []map[string]any `json:"keys"`
				} `json:"jwks"`
			} `json:"openid_relying_party"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(unverifiedPayload(t, signed), &claims); err != nil {
		t.Fatal(err)
	}
	published := map[string]map[string]any{}
	for _, key := range append(claims.Jwks.Keys, claims.Metadata.OpenidRelyingParty.Jwks.Keys...) {
		published[key["kid"].(string)] = key
		if _, private := key["d"]; private {
			t.Errorf("%s: published its private part", key["kid"])
		}
	}
	if len(claims.Jwks.Keys) != 1 || claims.Jwks.Keys[0]["kid"] != "sign-kid" || claims.Jwks.Keys[0]["alg"] != "ES256" {
		t.Errorf("statement jwks = %v", claims.Jwks.Keys)
	}
	if enc := published["enc-kid"]; enc == nil || enc["use"] != "enc" || enc["alg"] != "ECDH-ES" || enc["crv"] != "P-256" {
		t.Errorf("ID token key = %v", enc)
	}
	client := published["client-kid"]
	x5c, _ := client["x5c"].([]any)
	if client == nil || client["use"] != "sig" || len(x5c) != 1 || x5c[0] != base64.StdEncoding.EncodeToString(keys.Client.Leaf.Raw) {
		t.Errorf("client key = %v", client)
	}
}

// FuzzDecryptIDToken feeds arbitrary compact JWEs to the ID token decryption. Invariants: it never panics, and it
// decrypts nothing but what was encrypted to its key, which only the seed is.
func FuzzDecryptIDToken(f *testing.F) {
	key := newTestKey(f)
	const plaintext = "the ID token"
	f.Add(encryptForTest(f, key.Public(), jose.ECDH_ES, jose.A256GCM, plaintext))
	f.Add(encryptForTest(f, newTestKey(f).Public(), jose.ECDH_ES, jose.A256GCM, plaintext))
	for _, seed := range []string{"", "a.b.c.d.e", "e30....", "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9....", "....."} {
		f.Add(seed)
	}
	decrypter := opaqueDecrypter{agreement: ecdhKey(f, key), kid: "enc"}
	f.Fuzz(func(t *testing.T, token string) {
		object, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
		if err != nil {
			return
		}
		decrypted, err := object.Decrypt(decrypter)
		if err == nil && string(decrypted) != plaintext {
			t.Fatalf("decrypted %q", decrypted)
		}
	})
}
