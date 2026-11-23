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

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The corpus is TEST-ONLY data, written again from the keys committed in
// testdata/keys: the certificates (fixed instants, serial numbers from their
// names, RFC 6979 ECDSA), the passwords, the expectations and the cases that
// OpenSSL does not write (the random one included) come out the same on every
// run. A run writes only what is missing in -out; FORCE=1 writes everything
// (spec/fixtures.sh, and the test data rule of docs/design/testing.md).
//
// Randomised on every run that writes them: the files of the cases with an
// "openssl" source, in every encoding, because `openssl pkcs12 -export` draws
// salts and IVs that the command cannot fix. The expectations do not depend on
// them.

// The validity of every certificate; the corpus is not validated against a
// time, so these only keep the certificates the same.
var (
	notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

// material is the key and certificate set of the corpus.
type material struct {
	ca    entity
	leafs map[string]entity // by key type
}

type entity struct {
	certDER, keyDER []byte
	certPEM, keyPEM string // file paths
	certSHA, keySHA string
	publicKeySHA    string
}

func generate(manifestPath, out, openssl string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s: %w", manifestPath, err)
	}
	if err := os.MkdirAll(filepath.Join(out, "material"), 0o700); err != nil {
		return err
	}
	testdata := filepath.Dir(manifestPath)
	mat, err := newMaterial(filepath.Join(testdata, "keys"), filepath.Join(out, "material"))
	if err != nil {
		return err
	}

	var expected []Expected
	for _, c := range m.Cases {
		password, err := casePassword(c, testdata)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		decodePassword := password
		if c.DecodePassword != nil {
			decodePassword = []byte(*c.DecodePassword)
		}
		passwordFile := c.ID + ".password"
		if err := write(filepath.Join(out, passwordFile), decodePassword); err != nil {
			return err
		}
		want, err := expectation(c, mat)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		if err := writeEncodings(c, mat, testdata, out, openssl, password); err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		for _, encoding := range c.Encodings {
			file := c.ID + "." + encoding + ".p12"
			codes := c.Expect.Codes
			if c.Expect.Code != "" {
				codes = []string{c.Expect.Code}
			}
			profile := c.Profile
			if encoding == "ber" {
				profile = "legacy"
			}
			expected = append(expected, Expected{
				ID: c.ID, Encoding: encoding, File: file, PasswordFile: passwordFile,
				Rules: c.Rules, Profile: profile, Codes: codes, Result: want,
			})
		}
	}
	data, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		return err
	}
	// The index of every case, so it follows the manifest even when the
	// files it lists are already there.
	data = append(data, '\n')
	file := filepath.Join(out, "expected.json")
	if old, err := os.ReadFile(file); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return os.WriteFile(file, data, 0o600)
}

// force is FORCE=1: write every output again, not only the missing ones.
var force = os.Getenv("FORCE") != ""

// write writes an output that is missing, or every output under FORCE.
func write(file string, data []byte) error {
	if !force {
		if _, err := os.Stat(file); err == nil {
			return nil
		}
	}
	return os.WriteFile(file, data, 0o600)
}

// writeEncodings writes the case's files that are missing. It produces the
// case only then, so a run does not call openssl for files that exist.
func writeEncodings(c Case, mat *material, testdata, out, openssl string, password []byte) error {
	missing := force
	for _, encoding := range c.Encodings {
		if _, err := os.Stat(filepath.Join(out, c.ID+"."+encoding+".p12")); err != nil {
			missing = true
		}
	}
	if !missing {
		return nil
	}
	base, err := produce(c, mat, testdata, openssl, password)
	if err != nil {
		return err
	}
	// A mutation alters the file as produced, so a case can carry it into
	// every encoding: a BER encoding of a patched file is still patched.
	if c.Mutation != nil {
		if base, err = mutate(base, *c.Mutation); err != nil {
			return err
		}
	}
	for _, encoding := range c.Encodings {
		data := base
		switch encoding {
		case "der", "as-is":
		case "ber":
			if data, err = toBER(base, 512); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown encoding %q", encoding)
		}
		if err := write(filepath.Join(out, c.ID+"."+encoding+".p12"), data); err != nil {
			return err
		}
	}
	return nil
}

// casePassword returns the password the case's file is written with.
func casePassword(c Case, testdata string) ([]byte, error) {
	if c.PasswordFile == "" {
		return []byte(c.Password), nil
	}
	b, err := os.ReadFile(filepath.Join(testdata, c.PasswordFile))
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(b, "\r\n"), nil
}

// produce returns the case's file as produced, before encoding and mutation.
func produce(c Case, mat *material, testdata, openssl string, password []byte) ([]byte, error) {
	switch {
	case c.File != "":
		return os.ReadFile(filepath.Join(testdata, c.File))
	case c.Raw == "random":
		data := stream("random "+c.ID, 1024)
		data[0] = 0x30 // looks like a SEQUENCE, so decoders get past the first byte
		return data, nil
	case c.Raw == "pem":
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mat.ca.certDER}), nil
	case c.OpenSSL != nil:
		leaf, ok := mat.leafs[c.Key]
		if !ok {
			return nil, fmt.Errorf("unknown key type %q", c.Key)
		}
		tmp, err := os.MkdirTemp("", "p12conformance")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		file := filepath.Join(tmp, c.ID+".p12")
		args := []string{
			"pkcs12", "-export", "-in", leaf.certPEM, "-inkey", leaf.keyPEM, "-out", file,
			"-passout", "env:P12_PASSWORD",
		}
		if c.Chain {
			args = append(args, "-certfile", mat.ca.certPEM)
		}
		args = append(args, c.OpenSSL...)
		cmd := exec.Command(openssl, args...)
		cmd.Env = append(os.Environ(), "P12_PASSWORD="+string(password))
		if msg, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("openssl %s: %w\n%s", strings.Join(c.OpenSSL, " "), err, msg)
		}
		return os.ReadFile(file)
	}
	return nil, errors.New("no source")
}

// stream returns n bytes of SHA-256 in counter mode over label: data that
// looks random and is the same on every run.
func stream(label string, n int) []byte {
	var out []byte
	for i := uint32(0); len(out) < n; i++ {
		sum := sha256.Sum256(binary.BigEndian.AppendUint32([]byte(label), i))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// expectation resolves the symbolic contents of a case into the Result a
// conformant decoder reports.
func expectation(c Case, mat *material) (Result, error) {
	want := Result{Code: "ok", MAC: c.Expect.MAC, Certificates: []Item{}, Keys: []Item{}}
	name := func(symbol, digest string) string {
		if n, ok := c.Expect.FriendlyNames[symbol]; ok {
			return n
		}
		return c.Expect.FriendlyNames[digest]
	}
	for _, s := range c.Expect.Certificates {
		e, err := mat.entity(s, c.Key)
		if err != nil {
			return want, err
		}
		want.Certificates = append(want.Certificates, Item{SHA256: e.certSHA, FriendlyName: name(s, e.certSHA)})
	}
	for _, s := range c.Expect.Keys {
		e, err := mat.entity(s, c.Key)
		if err != nil {
			return want, err
		}
		want.Keys = append(want.Keys, Item{SHA256: e.keySHA, PublicKeySHA256: e.publicKeySHA, FriendlyName: name(s+"-key", e.keySHA)})
	}
	for _, d := range c.Expect.CertificatesSHA256 {
		want.Certificates = append(want.Certificates, Item{SHA256: d, FriendlyName: name("", d)})
	}
	for i, d := range c.Expect.KeysSHA256 {
		item := Item{SHA256: d, FriendlyName: name("", d)}
		if i < len(c.Expect.KeysPublicSHA256) {
			item.PublicKeySHA256 = c.Expect.KeysPublicSHA256[i]
		}
		want.Keys = append(want.Keys, item)
	}
	want.Pairs = make([][2]int, 0, c.Expect.Pairs)
	for i := range c.Expect.Pairs {
		// Pair indices are not compared, only their number (see verify).
		want.Pairs = append(want.Pairs, [2]int{i, i})
	}
	return want, nil
}

func (m *material) entity(symbol, key string) (entity, error) {
	switch symbol {
	case "ca":
		return m.ca, nil
	case "leaf":
		if e, ok := m.leafs[key]; ok {
			return e, nil
		}
	}
	return entity{}, fmt.Errorf("unknown entity %q", symbol)
}

func newMaterial(keys, dir string) (*material, error) {
	caKey, err := loadKey(keys, "ca", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) })
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          serialOf("ca"),
		Subject:               pkix.Name{CommonName: "PKCS#12 conformance CA TEST-ONLY"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	m := &material{leafs: map[string]entity{}}
	if m.ca, err = newEntity(dir, keys, "ca", caKey, caTemplate, caTemplate, caKey); err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(m.ca.certDER)
	if err != nil {
		return nil, err
	}

	for _, k := range []struct {
		name     string
		generate func() (crypto.Signer, error)
	}{
		{"rsa", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }},
		{"ec", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }},
	} {
		key, err := loadKey(keys, k.name, k.generate)
		if err != nil {
			return nil, err
		}
		leaf := &x509.Certificate{
			SerialNumber: serialOf(k.name),
			Subject:      pkix.Name{CommonName: "PKCS#12 conformance " + k.name + " TEST-ONLY"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		if m.leafs[k.name], err = newEntity(dir, keys, k.name, key, leaf, caCert, caKey); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// loadKey reads keys/name.key, a PKCS#8 PEM. A missing key is generated and
// written once, never again, also not under FORCE: the corpus stays the same
// only as long as its keys do.
func loadKey(keys, name string, generate func() (crypto.Signer, error)) (crypto.Signer, error) {
	file := filepath.Join(keys, name+".key")
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		key, err := generate()
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(keys, 0o700); err != nil {
			return nil, err
		}
		return key, os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: no PKCS#8 PEM", file)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", file)
	}
	return signer, nil
}

// serialOf derives a positive 64-bit serial number from a name, as serial_of
// of spec/fixtures.sh does, so an added certificate takes no other's number.
func serialOf(name string) *big.Int {
	sum := sha256.Sum256([]byte(name))
	serial, _ := new(big.Int).SetString("1"+hex.EncodeToString(sum[:])[:15], 16)
	return serial
}

// newEntity signs the certificate with a nil random source: ECDSA then signs
// per RFC 6979 and RSA PKCS #1 v1.5 is deterministic anyway, so the
// certificate is the same on every run. openssl reads the key from keys/.
func newEntity(dir, keys, name string, key crypto.Signer, template, parent *x509.Certificate, parentKey crypto.Signer) (entity, error) {
	var e entity
	var err error
	if e.certDER, err = x509.CreateCertificate(nil, template, parent, key.Public(), parentKey); err != nil {
		return e, err
	}
	if e.keyDER, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		return e, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return e, err
	}
	e.certSHA, e.keySHA, e.publicKeySHA = digest(e.certDER), digest(e.keyDER), digest(spki)
	e.certPEM = filepath.Join(dir, name+".crt.pem")
	e.keyPEM = filepath.Join(keys, name+".key")
	return e, write(e.certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.certDER}))
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mutate(data []byte, m Mutation) ([]byte, error) {
	data = slices.Clone(data)
	switch m.Kind {
	case "truncate":
		return data[:len(data)/2], nil
	case "append":
		b, err := hex.DecodeString(m.Hex)
		return append(data, b...), err
	case "flip":
		if m.Offset < 1 || m.Offset > len(data) {
			return nil, fmt.Errorf("flip offset %d out of range", m.Offset)
		}
		data[len(data)-m.Offset] ^= 0x01
		return data, nil
	case "patch":
		find, err := hex.DecodeString(m.Find)
		if err != nil {
			return nil, err
		}
		replace, err := hex.DecodeString(m.Replace)
		if err != nil {
			return nil, err
		}
		if !bytes.Contains(data, find) {
			return nil, fmt.Errorf("patch: %s not found", m.Find)
		}
		return bytes.ReplaceAll(data, find, replace), nil
	case "mac-iterations":
		return setMACIterations(data, m.Value)
	case "keybag-ber":
		return keyBagsToBER(data)
	case "friendly-name-segments":
		return segmentFriendlyNames(data)
	}
	return nil, fmt.Errorf("unknown mutation %q", m.Kind)
}

// setMACIterations rewrites the iterations of the MacData. MacData sits at the
// top level of the PFX, outside the octets the MAC covers, so the rest of the
// file stays valid. The input must be DER.
func setMACIterations(der []byte, iterations int64) ([]byte, error) {
	var pfx struct {
		Version  int
		AuthSafe asn1.RawValue
		MacData  struct {
			Mac        asn1.RawValue
			MacSalt    []byte
			Iterations int64 `asn1:"optional,default:1"`
		}
	}
	rest, err := asn1.Unmarshal(der, &pfx)
	if err != nil {
		return nil, fmt.Errorf("mac-iterations: input is not a DER PFX with MacData: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("mac-iterations: trailing data after the PFX")
	}
	pfx.MacData.Iterations = iterations
	return asn1.Marshal(pfx)
}

// oidKeyBagDER is the DER encoding of the keyBag OID (RFC 7292 §4.2.1).
var oidKeyBagDER = []byte{0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01}

// keyBagsToBER writes the PrivateKeyInfo of every keyBag in BER, as toBER
// does with a whole file: indefinite lengths, OCTET STRINGs over 512 bytes
// segmented. toBER leaves the octets of the authSafe and of the safes as they
// are, so no other case reaches BER inside a keyBag. The rewrite changes the
// authSafe octets; a case using it has no MAC.
func keyBagsToBER(der []byte) ([]byte, error) {
	out, n, err := rewriteKeyBags(der)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("keybag-ber: no keyBag found")
	}
	return out, nil
}

// keyBagToBER rewrites the rest of a keyBag after its bagId: the value
// [0] EXPLICIT in BER, the attributes as they are.
func keyBagToBER(rest []byte) ([]byte, error) {
	// SafeBag ::= SEQUENCE { bagId, bagValue [0] EXPLICIT, bagAttributes OPTIONAL }
	valueIdent, _, _, value, valueSize, err := readTLV(rest)
	if err != nil {
		return nil, err
	}
	ber, err := toBER(value, 512)
	if err != nil {
		return nil, err
	}
	return append(appendTLV(nil, valueIdent, ber), rest[valueSize:]...), nil
}

// oidFriendlyNameDER is the DER encoding of the friendlyName OID (PKCS #9).
var oidFriendlyNameDER = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14}

// segmentFriendlyNames writes the BMPString of every friendlyName attribute
// as a constructed string of one-character segments, as BER allows for
// every string type (X.690 §8.23). toBER segments OCTET STRINGs only, so this
// is the case for the other string types. The rewrite changes the authSafe
// octets; a case using it has no MAC.
func segmentFriendlyNames(der []byte) ([]byte, error) {
	out, n, err := rewriteElements(der, oidFriendlyNameDER, func(rest []byte) ([]byte, error) {
		// Attribute ::= SEQUENCE { attrId, attrValues SET OF BMPString }
		setIdent, _, _, values, _, err := readTLV(rest)
		if err != nil {
			return nil, err
		}
		var set []byte
		for len(values) > 0 {
			ident, _, _, value, size, err := readTLV(values)
			if err != nil || ident[0] != 0x1e {
				return nil, errors.New("friendly-name-segments: friendlyName is no BMPString")
			}
			set = append(set, ident[0]|0x20, 0x80)
			for len(value) > 0 {
				k := min(2, len(value))
				set = appendTLV(set, ident, value[:k])
				value = value[k:]
			}
			set = append(set, 0, 0)
			values = values[size:]
		}
		return appendTLV(nil, setIdent, set), nil
	})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("friendly-name-segments: no friendlyName found")
	}
	return out, nil
}

// rewriteKeyBags returns der with each keyBag's value in BER and the number of
// keyBags.
func rewriteKeyBags(der []byte) ([]byte, int, error) {
	return rewriteElements(der, oidKeyBagDER, keyBagToBER)
}

// rewriteElements walks the DER elements of der, and the OCTET STRINGs whose
// contents are DER elements themselves (the authSafe and its safes), and
// returns der with the rest of every constructed element that starts with
// oid rewritten by rewrite, and the number of such elements.
func rewriteElements(der, oid []byte, rewrite func(rest []byte) ([]byte, error)) ([]byte, int, error) {
	var out []byte
	total := 0
	for len(der) > 0 {
		ident, compound, isOctetString, content, size, err := readTLV(der)
		if err != nil {
			return nil, 0, err
		}
		switch {
		case compound && bytes.HasPrefix(content, oid):
			rest, err := rewrite(content[len(oid):])
			if err != nil {
				return nil, 0, err
			}
			out = appendTLV(out, ident, append(slices.Clone(oid), rest...))
			total++
		case compound || isOctetString:
			inner, n, err := rewriteElements(content, oid, rewrite)
			if err != nil || n == 0 {
				// Not DER inside (an OCTET STRING of other content), or nothing to rewrite.
				out = append(out, der[:size]...)
				break
			}
			out = appendTLV(out, ident, inner)
			total += n
		default:
			out = append(out, der[:size]...)
		}
		der = der[size:]
	}
	return out, total, nil
}
