// Command interop is the Go oracle of jwz-brainpool's interop fixtures, on
// go/brainpool/josebp.
//
//	go run . gen   <keys.json> <out.json>             tokens josebp makes, for jwz
//	go run . check <keys.json> <jwz.json> <out.json>  josebp's verdicts on jwz's tokens
//
// josebp signs and verifies compact JWS only and encrypts JWE without decrypting it,
// so it checks jwz's compact JWS and skips the rest.
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/brainpool/josebp"
)

// library names the oracle in the fixtures.
var library = "go/brainpool/josebp (" + runtime.Version() + ")"

type testCase struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Serialization string   `json:"serialization"`
	Algs          []string `json:"algs"`
	Enc           string   `json:"enc,omitempty"`
	Keys          []string `json:"keys"`
	Payload       string   `json:"payload"`
	Token         string   `json:"token"`
}

type tokensFile struct {
	Library string     `json:"library"`
	Cases   []testCase `json:"cases"`
}

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: interop gen|check ..."))
	}
	var err error
	switch os.Args[1] {
	case "gen":
		err = gen(os.Args[2], os.Args[3])
	case "check":
		err = check(os.Args[2], os.Args[3], os.Args[4])
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "interop:", err)
	os.Exit(1)
}

func readKeys(path string) (map[string]*josebp.JSONWebKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := map[string]*josebp.JSONWebKey{}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func writeJSON(path string, value any) error {
	out, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func gen(keysPath, outPath string) error {
	keys, err := readKeys(keysPath)
	if err != nil {
		return err
	}
	file := tokensFile{Library: library}
	for _, c := range []struct{ id, alg, key string }{
		{"jws-compact-BP256R1", "BP256R1", "bp256r1"},
		// ePA: the standard ES256 on a brainpoolP256r1 key.
		{"jws-compact-ES256-brainpool", "ES256", "es256-bp"},
	} {
		private, ok := keys[c.key].Key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%s: no private key %s", c.id, c.key)
		}
		builder := josebp.NewJWTBuilder().
			Header("alg", c.alg).
			Header("typ", "JWT").
			Header("kid", c.key).
			Claim("case", c.id).
			Claim("iss", "jwz-interop")
		token, err := builder.Sign(sha256.New(), brainpool.SignFuncPrivateKey(private))
		if err != nil {
			return fmt.Errorf("%s: %w", c.id, err)
		}
		payload, err := json.Marshal(map[string]any{"case": c.id, "iss": "jwz-interop"})
		if err != nil {
			return err
		}
		file.Cases = append(file.Cases, testCase{
			ID: c.id, Kind: "jws", Serialization: "compact", Algs: []string{c.alg},
			Keys: []string{c.key}, Payload: string(payload), Token: string(token),
		})
	}
	return writeJSON(outPath, file)
}

func check(keysPath, tokensPath, outPath string) error {
	keys, err := readKeys(keysPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(tokensPath)
	if err != nil {
		return err
	}
	var tokens tokensFile
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	results := map[string]string{}
	for _, c := range tokens.Cases {
		results[c.ID] = verdict(c, keys)
	}
	return writeJSON(outPath, map[string]any{
		"library": library,
		"source":  hex.EncodeToString(digest[:]),
		"results": results,
	})
}

func verdict(c testCase, keys map[string]*josebp.JSONWebKey) string {
	if c.Kind != "jws" {
		return "skipped: josebp does not decrypt JWE"
	}
	if c.Serialization != "compact" {
		return "skipped: josebp reads compact JWS only"
	}
	private, ok := keys[c.Keys[0]].Key.(*ecdsa.PrivateKey)
	if !ok {
		return "failed: no key " + c.Keys[0]
	}
	public := &josebp.JSONWebKey{KeyType: "EC", Key: &private.PublicKey}
	token, err := josebp.ParseToken([]byte(c.Token), josebp.WithKey(public))
	if err != nil {
		return "failed: " + err.Error()
	}
	if string(token.PayloadJson) != c.Payload {
		return "failed: payload differs"
	}
	return "ok"
}
