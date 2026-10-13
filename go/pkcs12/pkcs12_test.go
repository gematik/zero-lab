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

package pkcs12_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy/ber"
)

// newIdentity returns a fresh self-signed certificate and its PKCS#8 key; no
// key material is committed to the repository.
func newIdentity(kind string) (certDER, keyDER []byte, err error) {
	var key crypto.Signer
	switch kind {
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkcs12 test " + kind + " TEST-ONLY"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if certDER, err = x509.CreateCertificate(rand.Reader, template, template, key.Public(), key); err != nil {
		return nil, nil, err
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(key)
	return certDER, keyDER, err
}

func identity(t testing.TB, kind string) (certDER, keyDER []byte) {
	t.Helper()
	certDER, keyDER, err := newIdentity(kind)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyDER
}

func testBags(t testing.TB) *pkcs12.Bags {
	t.Helper()
	certDER, keyDER := identity(t, "ec")
	id := []byte{1, 2, 3, 4}
	return &pkcs12.Bags{
		Certificates: []pkcs12.CertificateBag{{Raw: certDER, FriendlyName: "Zertifikat ä", LocalKeyID: id}},
		PrivateKeys:  []pkcs12.PrivateKeyBag{{Raw: keyDER, FriendlyName: "Schlüssel ä", LocalKeyID: id}},
	}
}

func TestEncodeDecode(t *testing.T) {
	bags := testBags(t)
	password := []byte("päss😀")
	options := map[string]func(*pkcs12.EncodeOptions){
		"default": func(*pkcs12.EncodeOptions) {},
		"AES-128": func(o *pkcs12.EncodeOptions) {
			o.KeyEncryption, o.CertEncryption = pkcs12.OIDAes128CBC, pkcs12.OIDAes128CBC
		},
		"AES-192": func(o *pkcs12.EncodeOptions) {
			o.KeyEncryption, o.CertEncryption = pkcs12.OIDAes192CBC, pkcs12.OIDAes192CBC
		},
		"SHA-384":            func(o *pkcs12.EncodeOptions) { o.MacAlgorithm = pkcs12.OIDSHA384 },
		"SHA-512":            func(o *pkcs12.EncodeOptions) { o.MacAlgorithm = pkcs12.OIDSHA512 },
		"no MAC":             func(o *pkcs12.EncodeOptions) { o.IncludeMAC = false },
		"plain certificates": func(o *pkcs12.EncodeOptions) { o.CertEncryption = nil },
		"one iteration":      func(o *pkcs12.EncodeOptions) { o.Iterations = 1 },
	}
	for name, modify := range options {
		t.Run(name, func(t *testing.T) {
			opts := pkcs12.DefaultEncodeOptions()
			modify(opts)
			data, err := pkcs12.EncodeWithOptions(bags, password, opts)
			if err != nil {
				t.Fatal(err)
			}
			if der, err := ber.ToDER(data); err != nil || !bytes.Equal(der, data) {
				t.Errorf("output is not DER: %v", err)
			}
			got, err := pkcs12.Decode(data, password)
			if err != nil {
				t.Fatal(err)
			}
			assertBags(t, got, bags)
		})
	}
}

func assertBags(t *testing.T, got, want *pkcs12.Bags) {
	t.Helper()
	if len(got.Certificates) != len(want.Certificates) || len(got.PrivateKeys) != len(want.PrivateKeys) {
		t.Fatalf("%d certificates and %d keys, want %d and %d",
			len(got.Certificates), len(got.PrivateKeys), len(want.Certificates), len(want.PrivateKeys))
	}
	for i := range want.Certificates {
		g, w := got.Certificates[i], want.Certificates[i]
		if !bytes.Equal(g.Raw, w.Raw) || g.FriendlyName != w.FriendlyName || !bytes.Equal(g.LocalKeyID, w.LocalKeyID) {
			t.Errorf("certificate %d differs: %q %x", i, g.FriendlyName, g.LocalKeyID)
		}
	}
	for i := range want.PrivateKeys {
		g, w := got.PrivateKeys[i], want.PrivateKeys[i]
		if !bytes.Equal(g.Raw, w.Raw) || g.FriendlyName != w.FriendlyName || !bytes.Equal(g.LocalKeyID, w.LocalKeyID) {
			t.Errorf("key %d differs: %q %x", i, g.FriendlyName, g.LocalKeyID)
		}
	}
}

func TestEncodeEmptyBags(t *testing.T) {
	data, err := pkcs12.Encode(&pkcs12.Bags{}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	bags, err := pkcs12.Decode(data, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bags.Certificates) != 0 || len(bags.PrivateKeys) != 0 {
		t.Error("empty bags decode to contents")
	}
}

// TestEncodeSeparatePasswords decodes with the low-level API, since keys,
// certificates and MAC each use their own password.
func TestEncodeSeparatePasswords(t *testing.T) {
	bags := testBags(t)
	opts := pkcs12.DefaultEncodeOptions()
	opts.KeyPassword, opts.CertPassword = []byte("key"), []byte("cert")
	data, err := pkcs12.EncodeWithOptions(bags, []byte("mac"), opts)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pkcs12.VerifyMAC(pfx, []byte("mac")); err != nil {
		t.Fatal(err)
	}
	authSafe, err := pkcs12.ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		t.Fatal(err)
	}
	var sawKey, sawCert bool
	for _, ci := range authSafe.ContentInfos {
		switch {
		case ci.ContentType.Equal(pkcs12.OIDData):
			// The key safe: Data with shrouded key bags.
			var octets []byte
			if _, err := asn1.Unmarshal(ci.Content, &octets); err != nil {
				t.Fatal(err)
			}
			sc, err := pkcs12.ParseSafeContents(octets)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pkcs12.DecryptShroudedKeyBag(sc.Bags[0].BagValue, []byte("cert")); err == nil {
				t.Error("key decrypts with the certificate password")
			}
			key, err := pkcs12.DecryptShroudedKeyBag(sc.Bags[0].BagValue, []byte("key"))
			if err != nil || !bytes.Equal(key, bags.PrivateKeys[0].Raw) {
				t.Errorf("key with KeyPassword: %v", err)
			}
			sawKey = true
		case ci.ContentType.Equal(pkcs12.OIDEncryptedData):
			if _, err := pkcs12.DecryptEncryptedData(ci, []byte("cert")); err != nil {
				t.Errorf("certificates with CertPassword: %v", err)
			}
			sawCert = true
		}
	}
	if !sawKey || !sawCert {
		t.Errorf("key safe %v, encrypted certificate safe %v", sawKey, sawCert)
	}
}

func TestEncodeDoesNotModifyOptions(t *testing.T) {
	opts := pkcs12.DefaultEncodeOptions()
	if _, err := pkcs12.EncodeWithOptions(testBags(t), []byte("x"), opts); err != nil {
		t.Fatal(err)
	}
	if opts.KeyPassword != nil || opts.CertPassword != nil {
		t.Error("EncodeWithOptions set passwords in the caller's options")
	}
}

func TestEncodeRejects(t *testing.T) {
	bags := testBags(t)
	tests := map[string]struct {
		modify func(*pkcs12.EncodeOptions)
		bags   *pkcs12.Bags
	}{
		"zero iterations":     {modify: func(o *pkcs12.EncodeOptions) { o.Iterations = 0 }},
		"SHA-1 MAC":           {modify: func(o *pkcs12.EncodeOptions) { o.MacAlgorithm = pkcs12.OIDSHA1 }},
		"Triple DES keys":     {modify: func(o *pkcs12.EncodeOptions) { o.KeyEncryption = pkcs12.OIDPBEWithSHAAnd3KeyTripleDESCBC }},
		"unknown cipher":      {modify: func(o *pkcs12.EncodeOptions) { o.CertEncryption = asn1.ObjectIdentifier{1, 2, 3} }},
		"non-BMP name":        {bags: &pkcs12.Bags{Certificates: []pkcs12.CertificateBag{{Raw: bags.Certificates[0].Raw, FriendlyName: "😀"}}}},
		"nil bags":            {bags: nil},
		"too many iterations": {modify: func(o *pkcs12.EncodeOptions) { o.Iterations = 1 << 30 }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := pkcs12.DefaultEncodeOptions()
			if tt.modify != nil {
				tt.modify(opts)
			}
			b := bags
			if tt.modify == nil {
				b = tt.bags
			}
			if _, err := pkcs12.EncodeWithOptions(b, []byte("x"), opts); err == nil {
				t.Error("no error")
			}
		})
	}
}

// TestEncodeReadByOpenSSL checks the files against the most widespread reader.
func TestEncodeReadByOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	bags := testBags(t)
	for _, mac := range []asn1.ObjectIdentifier{pkcs12.OIDSHA256, pkcs12.OIDSHA512} {
		opts := pkcs12.DefaultEncodeOptions()
		opts.MacAlgorithm = mac
		data, err := pkcs12.EncodeWithOptions(bags, []byte("pass"), opts)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "out.p12")
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("openssl", "pkcs12", "-in", file, "-passin", "pass:pass", "-nodes").CombinedOutput()
		if err != nil {
			t.Fatalf("openssl: %v\n%s", err, out)
		}
		var block *pem.Block
		if i := bytes.Index(out, []byte("-----BEGIN CERTIFICATE")); i >= 0 {
			block, _ = pem.Decode(out[i:])
		}
		if block == nil || !bytes.Equal(block.Bytes, bags.Certificates[0].Raw) {
			t.Errorf("openssl does not return the certificate:\n%s", out)
		}
		info, _ := exec.Command("openssl", "pkcs12", "-in", file, "-passin", "pass:pass", "-info", "-noout").CombinedOutput()
		for _, want := range []string{"PBES2, PBKDF2, AES-256-CBC", "PRF hmacWith" + macName(mac), "MAC: " + macName(mac)} {
			if !bytes.Contains(bytes.ToUpper(info), bytes.ToUpper([]byte(want))) {
				t.Errorf("openssl -info lacks %q:\n%s", want, info)
			}
		}
	}
}

func macName(oid asn1.ObjectIdentifier) string {
	if oid.Equal(pkcs12.OIDSHA512) {
		return "sha512"
	}
	return "sha256"
}

func TestParseRejects(t *testing.T) {
	valid, err := pkcs12.Encode(testBags(t), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	versionTwo := bytes.Clone(valid)
	versionTwo[bytes.Index(versionTwo, []byte{0x02, 0x01, 0x03})+2] = 2

	tests := map[string][]byte{
		"empty":       nil,
		"too small":   {0x30, 0x03, 0x02, 0x01, 0x03},
		"BER":         append([]byte{0x30, 0x80}, valid[2:]...),
		"not DER":     []byte("-----BEGIN CERTIFICATE-----"),
		"truncated":   valid[:len(valid)/2],
		"trailing":    append(bytes.Clone(valid), 0),
		"version two": versionTwo,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := pkcs12.Parse(data); !errors.Is(err, pkcs12.ErrInvalidPFX) {
				t.Errorf("error = %v, want ErrInvalidPFX", err)
			}
		})
	}
	if _, err := pkcs12.Parse(tests["BER"]); !strings.Contains(err.Error(), "legacy.Decode") {
		t.Errorf("BER error does not point to package legacy: %v", err)
	}
}

func TestDecodeWrongPasswordAndTampering(t *testing.T) {
	bags := testBags(t)
	data, err := pkcs12.Encode(bags, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkcs12.Decode(data, []byte("wrong")); !errors.Is(err, pkcs12.ErrAuthentication) {
		t.Errorf("wrong password: %v, want ErrAuthentication", err)
	}
	tampered := bytes.Clone(data)
	tampered[len(tampered)-120] ^= 1
	if _, err := pkcs12.Decode(tampered, []byte("right")); !errors.Is(err, pkcs12.ErrAuthentication) {
		t.Errorf("tampered: %v, want ErrAuthentication", err)
	}

	opts := pkcs12.DefaultEncodeOptions()
	opts.IncludeMAC = false
	noMAC, err := pkcs12.EncodeWithOptions(bags, []byte("right"), opts)
	if err != nil {
		t.Fatal(err)
	}
	// Without MAC a wrong password surfaces as bad padding, or in 1 of 256
	// cases as plaintext that does not parse.
	_, err = pkcs12.Decode(noMAC, []byte("wrong"))
	if !errors.Is(err, pkcs12.ErrDecryption) && !errors.Is(err, pkcs12.ErrParse) {
		t.Errorf("wrong password without MAC: %v", err)
	}
}

func TestIterationLimits(t *testing.T) {
	data, err := pkcs12.Encode(testBags(t), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	pfx.MacData.Iterations = 1 << 30
	if err := pkcs12.VerifyMAC(pfx, []byte("x")); !errors.Is(err, pkcs12.ErrLimitExceeded) {
		t.Errorf("MAC: %v, want ErrLimitExceeded", err)
	}
	pfx.MacData.Iterations = 0
	if err := pkcs12.VerifyMAC(pfx, []byte("x")); !errors.Is(err, pkcs12.ErrParse) {
		t.Errorf("MAC with 0 iterations: %v, want ErrParse", err)
	}

	alg := &pkcs12.EncryptionAlgorithm{
		Algorithm: pkcs12.OIDPBES2,
		KDF:       &pkcs12.PBKDF2Params{Salt: []byte("salt"), Iterations: 1 << 30, PRF: pkcs12.OIDHMACSHA256},
		Cipher:    &pkcs12.CipherParams{Algorithm: pkcs12.OIDAes256CBC, IV: make([]byte, 16)},
	}
	if _, err := pkcs12.DecryptPBES2(alg, []byte("x"), make([]byte, 16)); !errors.Is(err, pkcs12.ErrLimitExceeded) {
		t.Errorf("PBKDF2: %v, want ErrLimitExceeded", err)
	}
	pbe := &pkcs12.EncryptionAlgorithm{Algorithm: pkcs12.OIDPBEWithSHAAnd3KeyTripleDESCBC, Salt: []byte("salt"), Iterations: 1 << 30}
	if _, err := pkcs12.DecryptLegacyPBE(pbe, []byte("x"), make([]byte, 8)); !errors.Is(err, pkcs12.ErrLimitExceeded) {
		t.Errorf("PKCS#12 PBE: %v, want ErrLimitExceeded", err)
	}
}

func TestDecryptPBES2Algorithms(t *testing.T) {
	alg := func(prf, cipher asn1.ObjectIdentifier) *pkcs12.EncryptionAlgorithm {
		return &pkcs12.EncryptionAlgorithm{
			Algorithm: pkcs12.OIDPBES2,
			KDF:       &pkcs12.PBKDF2Params{Salt: []byte("salt"), Iterations: 1, PRF: prf},
			Cipher:    &pkcs12.CipherParams{Algorithm: cipher, IV: make([]byte, 16)},
		}
	}
	unknown := asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 127}
	if _, err := pkcs12.DecryptPBES2(alg(unknown, pkcs12.OIDAes256CBC), nil, make([]byte, 16)); !errors.Is(err, pkcs12.ErrUnsupportedAlgorithm) {
		t.Errorf("unknown PRF: %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := pkcs12.DecryptPBES2(alg(pkcs12.OIDHMACSHA256, unknown), nil, make([]byte, 16)); !errors.Is(err, pkcs12.ErrUnsupportedAlgorithm) {
		t.Errorf("unknown cipher: %v, want ErrUnsupportedAlgorithm", err)
	}
	// Up to v0.99.3 this package wrote the digest OID as PRF; such files
	// must stay readable.
	if _, err := pkcs12.DecryptPBES2(alg(pkcs12.OIDSHA256, pkcs12.OIDAes256CBC), nil, make([]byte, 16)); errors.Is(err, pkcs12.ErrUnsupportedAlgorithm) {
		t.Errorf("digest OID as PRF: %v", err)
	}
	keyLength := alg(pkcs12.OIDHMACSHA256, pkcs12.OIDAes256CBC)
	keyLength.KDF.KeyLength = 16
	if _, err := pkcs12.DecryptPBES2(keyLength, nil, make([]byte, 16)); !errors.Is(err, pkcs12.ErrParse) {
		t.Errorf("keyLength that does not fit: %v, want ErrParse", err)
	}
	rc2 := &pkcs12.EncryptionAlgorithm{Algorithm: pkcs12.OIDPBEWithSHAAnd128BitRC2CBC, Salt: []byte("s"), Iterations: 1}
	if _, err := pkcs12.DecryptLegacyPBE(rc2, nil, make([]byte, 8)); !errors.Is(err, pkcs12.ErrUnsupportedAlgorithm) {
		t.Errorf("RC2 in package pkcs12: %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestExtractBagsRejectsPublicKeyModes(t *testing.T) {
	signedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	pfx := &pkcs12.PFX{Version: 3, AuthSafe: pkcs12.ContentInfo{ContentType: signedData}}
	if _, err := pkcs12.ExtractBags(pfx, nil); !errors.Is(err, pkcs12.ErrUnsupportedAlgorithm) {
		t.Errorf("signed authSafe: %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestGetFriendlyName(t *testing.T) {
	attr := func(value ...byte) []pkcs12.PKCS12Attribute {
		return []pkcs12.PKCS12Attribute{{ID: pkcs12.OIDFriendlyName, Values: [][]byte{value}}}
	}
	tests := []struct {
		attrs []pkcs12.PKCS12Attribute
		want  string
		ok    bool
	}{
		{attr(0x1e, 0x04, 0x00, 'A', 0x00, 0xe4), "Aä", true},
		{attr(0x1e, 0x04, 0xd8, 0x3d, 0xde, 0x00), "😀", true}, // surrogate pair, as Windows writes it
		{attr(0x1e, 0x03, 0x00, 'A', 0x00), "", false},        // odd length
		{attr(0x0c, 0x01, 'A'), "", false},                    // UTF8String instead of BMPString
		{nil, "", false},
	}
	for _, tt := range tests {
		got, ok := pkcs12.GetFriendlyName(tt.attrs)
		if got != tt.want || ok != tt.ok {
			t.Errorf("GetFriendlyName(% x) = %q, %v, want %q, %v", tt.attrs, got, ok, tt.want, tt.ok)
		}
	}
}

func TestFindMatchingPairs(t *testing.T) {
	bags := &pkcs12.Bags{
		Certificates: []pkcs12.CertificateBag{{Raw: []byte("ca")}, {Raw: []byte("leaf"), LocalKeyID: []byte{1}}, {Raw: []byte("other"), LocalKeyID: []byte{2}}},
		PrivateKeys:  []pkcs12.PrivateKeyBag{{Raw: []byte("key"), LocalKeyID: []byte{1}}},
	}
	pairs := bags.FindMatchingPairs()
	if len(pairs) != 1 || string(pairs[0].Certificate.Raw) != "leaf" || string(pairs[0].PrivateKey.Raw) != "key" {
		t.Errorf("FindMatchingPairs = %+v", pairs)
	}
	if c := bags.FindCertificate([]byte{2}); c == nil || string(c.Raw) != "other" {
		t.Errorf("FindCertificate = %+v", c)
	}
	if k := bags.FindPrivateKey([]byte{9}); k != nil {
		t.Errorf("FindPrivateKey of an unknown ID = %+v", k)
	}
}

func FuzzDecode(f *testing.F) {
	data, err := pkcs12.Encode(testBags(f), []byte("x"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data, []byte("x"))
	f.Fuzz(func(t *testing.T, data, password []byte) {
		bags, err := pkcs12.Decode(data, password)
		if err == nil && bags == nil {
			t.Fatal("nil Bags without error")
		}
	})
}
