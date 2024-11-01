package brainpool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

const (
	AlgorithmNameES256   = "ES256"
	AlgorithmNameES384   = "ES384"
	AlgorithmNameES512   = "ES512"
	AlgorithmNameBP256R1 = "BP256R1"
	AlgorithmNameBP384R1 = "BP384R1"
	AlgorithmNameBP512R1 = "BP512R1"
)

type Headers map[string]interface{}
type Claims map[string]interface{}

type JWT struct {
	Raw         []byte
	HeadersJson []byte
	PayloadJson []byte
	Signature   []byte
	Headers     Headers
	Claims      Claims
}

type JWTBuilder struct {
	headers Headers
	claims  Claims
}

func NewJWTBuilder() *JWTBuilder {
	return &JWTBuilder{
		headers: make(Headers),
		claims:  make(Claims),
	}
}

func (b *JWTBuilder) Header(key string, value interface{}) *JWTBuilder {
	b.headers[key] = value
	return b
}

func (b *JWTBuilder) Claim(key string, value interface{}) *JWTBuilder {
	b.claims[key] = value
	return b
}

type SignFunc func(hash []byte) ([]byte, error)

func HashFunctionForCurve(curve elliptic.Curve) (hash.Hash, error) {
	curveBits := curve.Params().BitSize

	// compute hash function depending on curve's bit size
	var hashFunc hash.Hash
	if curveBits == 256 {
		hashFunc = sha256.New()
	} else if curveBits == 384 {
		hashFunc = sha512.New384()
	} else if curveBits == 512 {
		hashFunc = sha512.New()
	} else {
		return nil, fmt.Errorf("unsupported curve bit size: %d", curveBits)
	}

	return hashFunc, nil
}

func AlgorithmForCurve(curve elliptic.Curve) (string, error) {
	name := curve.Params().Name

	switch name {
	case "P-256":
		return AlgorithmNameES256, nil
	case "P-384":
		return AlgorithmNameBP384R1, nil
	case "P-521":
		return AlgorithmNameES512, nil
	case "BP-256":
		return AlgorithmNameBP256R1, nil
	case "BP-384":
		return AlgorithmNameBP384R1, nil
	case "BP-521":
		return AlgorithmNameBP512R1, nil
	default:
		return "", fmt.Errorf("unsupported curve: %s", name)
	}

}

func SignFuncPrivateKey(sigPrK *ecdsa.PrivateKey) SignFunc {
	return func(hash []byte) ([]byte, error) {

		r, s, err := ecdsa.Sign(rand.Reader, sigPrK, hash)
		if err != nil {
			return nil, err
		}

		curveBits := sigPrK.Curve.Params().BitSize

		keyBytes := curveBits / 8

		// Pad rBytes and sBytes
		rBytesPadded := padBytes(r.Bytes(), keyBytes)
		sBytesPadded := padBytes(s.Bytes(), keyBytes)

		// Concatenate rBytesPadded and sBytesPadded
		signature := append(rBytesPadded, sBytesPadded...)

		return signature, nil
	}
}

func (b *JWTBuilder) Sign(hashFunc hash.Hash, signFunc SignFunc) ([]byte, error) {
	headersJson, err := json.Marshal(b.headers)
	if err != nil {
		return nil, fmt.Errorf("marshaling headers: %w", err)
	}

	claimsJson, err := json.Marshal(b.claims)
	if err != nil {
		return nil, fmt.Errorf("marshaling claims: %w", err)
	}

	payload := base64.RawURLEncoding.AppendEncode(nil, headersJson)
	payload = append(payload, '.')
	payload = base64.RawURLEncoding.AppendEncode(payload, claimsJson)

	hashFunc.Write(payload)
	digest := hashFunc.Sum(nil)
	signature, err := signFunc(digest)
	if err != nil {
		return nil, fmt.Errorf("signing payload: %w", err)
	}

	token := append(payload, '.')
	token = base64.RawURLEncoding.AppendEncode(token, signature)

	return token, nil
}

func padBytes(input []byte, length int) []byte {
	padded := make([]byte, length)
	copy(padded[length-len(input):], input)
	return padded
}

type VerifierFunc func(token *JWT) error

type VerifierErrorUnsupportedSignatureAlgorithm error

func WithKey(key *JSONWebKey) VerifierFunc {
	return func(token *JWT) error {
		switch key.Key.(type) {
		case *ecdsa.PublicKey:
			return WithEcdsaPublicKey(key.Key.(*ecdsa.PublicKey))(token)
		default:
			return fmt.Errorf("unsupported key type")
		}
	}
}

func WithEcdsaPublicKey(pubKey *ecdsa.PublicKey) VerifierFunc {
	return func(token *JWT) error {

		alg, ok := token.Headers["alg"].(string)
		if !ok {
			return fmt.Errorf("missing alg header")
		}
		// TODO: check alg against the key's curve
		if alg != AlgorithmNameBP256R1 && alg != AlgorithmNameBP384R1 && alg != AlgorithmNameBP512R1 && alg != AlgorithmNameES256 && alg != AlgorithmNameES384 && alg != AlgorithmNameES512 {
			return VerifierErrorUnsupportedSignatureAlgorithm(fmt.Errorf("unsupported signature algorithm: %s", alg))
		}

		// Decode the signature
		curveBits := pubKey.Curve.Params().BitSize

		keyBytes := curveBits / 8

		rBytes := token.Signature[:keyBytes]
		sBytes := token.Signature[keyBytes:]

		r := new(big.Int).SetBytes(rBytes)
		s := new(big.Int).SetBytes(sBytes)

		// Verify the signature
		// get all bytes of the token except the signature (before last '.')
		// we rely here on the fact that the code before verifies the token format
		rawTokenNoSig := token.Raw[:bytes.LastIndex(token.Raw, []byte{'.'})]

		hashFunc, err := HashFunctionForCurve(pubKey.Curve)
		if err != nil {
			return err
		}

		hashFunc.Write(rawTokenNoSig)
		hash := hashFunc.Sum(nil)

		if !ecdsa.Verify(pubKey, hash, r, s) {
			return fmt.Errorf("signature verification failed")
		}

		return nil
	}
}

func ParseToken(rawToken []byte, verifiers ...VerifierFunc) (*JWT, error) {
	if len(rawToken) == 0 {
		return nil, fmt.Errorf("empty token")
	}
	if len(verifiers) == 0 {
		return nil, errors.New("at least one verifier must be specified")
	}
	parts := bytes.Split(rawToken, []byte{'.'})
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	token := &JWT{
		Raw: rawToken,
	}

	var err error

	if token.HeadersJson, err = base64.RawURLEncoding.DecodeString(string(parts[0])); err != nil {
		return nil, fmt.Errorf("decoding headers: %w", err)
	}

	if err = json.Unmarshal(token.HeadersJson, &token.Headers); err != nil {
		return nil, fmt.Errorf("unmarshaling headers: %w", err)
	}

	if token.PayloadJson, err = base64.RawURLEncoding.DecodeString(string(parts[1])); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}

	if err = json.Unmarshal(token.PayloadJson, &token.Claims); err != nil {
		return nil, fmt.Errorf("unmarshaling claims: %w", err)
	}

	if token.Signature, err = base64.RawURLEncoding.DecodeString(string(parts[2])); err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	for _, verifier := range verifiers {
		if err := verifier(token); err != nil {
			return nil, fmt.Errorf("verifying token: %w", err)
		}
	}

	return token, nil
}

// See https://datatracker.ietf.org/doc/html/rfc7517
type JSONWebKey struct {
	KeyType         string              `json:"kty"`
	Use             string              `json:"use,omitempty"`
	Algortihm       string              `json:"alg,omitempty"`
	KeyID           string              `json:"kid,omitempty"`
	Key             interface{}         `json:"-"`
	CertificatesRaw [][]byte            `json:"x5c,omitempty"`
	Certificates    []*x509.Certificate `json:"-"`
	X               string              `json:"x"`
	Y               string              `json:"y"`
	D               string              `json:"d,omitempty"`
	CurveName       string              `json:"crv"`
}

func (jwk *JSONWebKey) UnmarshalJSON(data []byte) error {
	type Alias JSONWebKey
	var jwkAlias Alias
	if err := json.Unmarshal(data, &jwkAlias); err != nil {
		return err
	}

	switch jwkAlias.KeyType {
	case "EC":
		curve, err := CurveForJWA(jwkAlias.CurveName)
		if err != nil {
			return err
		}

		x, err := parseBigInt(jwkAlias.X)
		if err != nil {
			return fmt.Errorf("failed to parse x: %w", err)
		}

		y, err := parseBigInt(jwkAlias.Y)
		if err != nil {
			return fmt.Errorf("failed to parse y: %w", err)
		}

		if jwkAlias.D != "" {
			d, err := parseBigInt(jwkAlias.D)
			if err != nil {
				return fmt.Errorf("failed to parse d: %w", err)
			}

			jwkAlias.Key = &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: curve,
					X:     x,
					Y:     y,
				},
				D: d,
			}
		} else {
			jwkAlias.Key = &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			}
		}

	default:
		return fmt.Errorf("unsupported key type: %s", jwkAlias.KeyType)
	}

	if len(jwkAlias.CertificatesRaw) > 0 {
		jwkAlias.Certificates = make([]*x509.Certificate, len(jwkAlias.CertificatesRaw))
		for i, certRaw := range jwkAlias.CertificatesRaw {
			cert, err := ParseCertificate(certRaw)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}
			jwkAlias.Certificates[i] = cert
		}
	}

	*jwk = JSONWebKey(jwkAlias)
	return nil
}

func (jwk *JSONWebKey) MarshalJSON() ([]byte, error) {
	type Alias JSONWebKey
	var jwkAlias Alias = Alias(*jwk)

	if key, ok := jwk.Key.(*ecdsa.PrivateKey); ok {
		jwkAlias.D = base64.RawURLEncoding.EncodeToString(key.D.Bytes())
		jwkAlias.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
		jwkAlias.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
	} else if key, ok := jwk.Key.(*ecdsa.PublicKey); ok {
		jwkAlias.KeyType = "EC"
		jwkAlias.CurveName = JWAForCurve(key.Curve)
		jwkAlias.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
		jwkAlias.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())

	}

	if len(jwk.Certificates) > 0 {
		jwkAlias.CertificatesRaw = make([][]byte, len(jwk.Certificates))
		for i, cert := range jwk.Certificates {
			jwkAlias.CertificatesRaw[i] = cert.Raw
		}
	}

	return json.Marshal(jwkAlias)
}

func JWAForCurve(curve elliptic.Curve) string {
	switch curve.Params().Name {
	case "brainpoolP256r1":
		return "BP-256"
	case "brainpoolP384r1":
		return "BP-384"
	case "brainpoolP512r1":
		return "BP-512"
	default:
		return curve.Params().Name
	}
}

func CurveForJWA(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	case "BP-256":
		return P256r1(), nil
	case "BP-384":
		return P384r1(), nil
	case "BP-512":
		return P512r1(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

func parseBigInt(s string) (*big.Int, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return new(big.Int).SetBytes(bytes), nil
}
