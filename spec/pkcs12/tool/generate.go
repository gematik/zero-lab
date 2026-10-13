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

// material is the key and certificate set of one generator run. Keys exist
// only for the run; nothing is committed (see CONFORMANCE.md, Corpus).
type material struct {
	dir   string
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
	mat, err := newMaterial(filepath.Join(out, "material"))
	if err != nil {
		return err
	}
	testdata := filepath.Dir(manifestPath)

	var expected []Expected
	for _, c := range m.Cases {
		base, password, err := produce(c, mat, testdata, out, openssl)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		decodePassword := password
		if c.DecodePassword != nil {
			decodePassword = []byte(*c.DecodePassword)
		}
		passwordFile := c.ID + ".password"
		if err := os.WriteFile(filepath.Join(out, passwordFile), decodePassword, 0o600); err != nil {
			return err
		}
		want, err := expectation(c, mat)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		for _, encoding := range c.Encodings {
			data := base
			switch encoding {
			case "der", "as-is":
			case "ber":
				if data, err = toBER(base, 512); err != nil {
					return fmt.Errorf("case %s: %w", c.ID, err)
				}
			default:
				return fmt.Errorf("case %s: unknown encoding %q", c.ID, encoding)
			}
			if c.Mutation != nil {
				if data, err = mutate(data, *c.Mutation); err != nil {
					return fmt.Errorf("case %s: %w", c.ID, err)
				}
			}
			file := c.ID + "." + encoding + ".p12"
			if err := os.WriteFile(filepath.Join(out, file), data, 0o600); err != nil {
				return err
			}
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
	return os.WriteFile(filepath.Join(out, "expected.json"), append(data, '\n'), 0o600)
}

// produce returns the case's file as produced (before encoding and mutation)
// and the password it was produced with.
func produce(c Case, mat *material, testdata, out, openssl string) ([]byte, []byte, error) {
	password := []byte(c.Password)
	if c.PasswordFile != "" {
		b, err := os.ReadFile(filepath.Join(testdata, c.PasswordFile))
		if err != nil {
			return nil, nil, err
		}
		password = bytes.TrimRight(b, "\r\n")
	}
	switch {
	case c.File != "":
		data, err := os.ReadFile(filepath.Join(testdata, c.File))
		return data, password, err
	case c.Raw == "random":
		data := make([]byte, 1024)
		_, err := rand.Read(data)
		data[0] = 0x30 // looks like a SEQUENCE, so decoders get past the first byte
		return data, password, err
	case c.Raw == "pem":
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mat.ca.certDER}), password, nil
	case c.OpenSSL != nil:
		leaf, ok := mat.leafs[c.Key]
		if !ok {
			return nil, nil, fmt.Errorf("unknown key type %q", c.Key)
		}
		file := filepath.Join(out, "material", c.ID+".openssl.p12")
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
			return nil, nil, fmt.Errorf("openssl %s: %w\n%s", strings.Join(c.OpenSSL, " "), err, msg)
		}
		data, err := os.ReadFile(file)
		return data, password, err
	}
	return nil, nil, errors.New("no source")
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

func newMaterial(dir string) (*material, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PKCS#12 conformance CA TEST-ONLY"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	m := &material{dir: dir, leafs: map[string]entity{}}
	if m.ca, err = newEntity(dir, "ca", caKey, caTemplate, caTemplate, caKey); err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(m.ca.certDER)
	if err != nil {
		return nil, err
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	for i, k := range []struct {
		name string
		key  crypto.Signer
	}{{"rsa", rsaKey}, {"ec", ecKey}} {
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject:      pkix.Name{CommonName: "PKCS#12 conformance " + k.name + " TEST-ONLY"},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		if m.leafs[k.name], err = newEntity(dir, k.name, k.key, leaf, caCert, caKey); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func newEntity(dir, name string, key crypto.Signer, template, parent *x509.Certificate, parentKey crypto.Signer) (entity, error) {
	var e entity
	var err error
	if e.certDER, err = x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey); err != nil {
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
	e.keyPEM = filepath.Join(dir, name+".key.pem")
	if err := os.WriteFile(e.certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.certDER}), 0o600); err != nil {
		return e, err
	}
	return e, os.WriteFile(e.keyPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: e.keyDER}), 0o600)
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
