package tsl

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gematik/zero-lab/go/gempki"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// DetachedSignature is the parsed contents of a gematik TSL .sig file.
//
// The gematik TSL is double-signed: an inline XMLDSig inside the XML body
// (which this package deliberately does not support) and a
// separate detached signature in a .sig file alongside the XML on the
// download point. This type represents the parsed detached signature; use
// [ParseSignature] to construct, and [DetachedSignature.VerifyOver]
// to check it against the TSL bytes.
//
// The wire format is a custom gematik container (intentionally simpler than
// CMS/PKCS#7 so verification can use fixed offsets): an outer DER SEQUENCE
// containing AlgorithmIdentifier{ecdsaWithSHA256}, the ECDSA-Sig-Value
// SEQUENCE{r,s}, and the X.509 signer certificate. See
// internal/testtsl/sign.go and the gematik examples-TelematikInterfaces
// repository (tslService/detachedSignature/README.md).
type DetachedSignature struct {
	// Signer is the TSL-Signer certificate embedded in the .sig file.
	// Already passed through [gempki.ParseCertificate], so the ECC-only crypto
	// policy applies.
	Signer *x509.Certificate

	// Raw is the original .sig DER. Useful for callers that cache the file
	// or pass it on.
	Raw []byte

	// sigDER is the raw DER-encoded ECDSA-Sig-Value SEQUENCE{r,s}, ready to
	// hand to crypto/ecdsa.VerifyASN1.
	sigDER []byte
}

// ErrRSANotSupported is returned by [ParseSignature] for the RSA-PSS .sig
// variant gematik also publishes: its container has a different shape that
// this package does not decode. The ECDSA .sig is the one to fetch.
var ErrRSANotSupported = errors.New("tsl: RSA-PSS TSL signatures are not decoded — fetch the ECDSA .sig")

// Algorithm OIDs we accept (ECDSA) and recognise so as to reject (RSA).
var (
	oidECDSAWithSHA256DetachedSig = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	oidRSASSAPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

// ParseSignature decodes the gematik detached-signature container
// from sig.
//
// Returns wrapped [ErrRSANotSupported] when the AlgorithmIdentifier names an
// RSA variant — gematik publishes both ECDSA and RSA-PSS .sig files; this
// library accepts only the ECDSA one.
func ParseSignature(sig []byte) (*DetachedSignature, error) {
	if len(sig) == 0 {
		return nil, fmt.Errorf("tsl: empty TSL detached signature")
	}

	outer := cryptobyte.String(sig)
	var inner cryptobyte.String
	if !outer.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("tsl: TSL detached signature: outer SEQUENCE missing or malformed")
	}
	if !outer.Empty() {
		return nil, fmt.Errorf("tsl: TSL detached signature: trailing bytes after outer SEQUENCE")
	}

	algOID, err := readAlgorithmIdentifier(&inner)
	if err != nil {
		return nil, err
	}
	if isRSAOID(algOID) {
		return nil, fmt.Errorf("tsl: TSL detached signature uses RSA algorithm %s: %w",
			algOID, ErrRSANotSupported)
	}
	if !algOID.Equal(oidECDSAWithSHA256DetachedSig) {
		return nil, fmt.Errorf("tsl: TSL detached signature: unsupported algorithm OID %s (want ecdsaWithSHA256)", algOID)
	}

	var sigDER cryptobyte.String
	if !inner.ReadASN1Element(&sigDER, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("tsl: TSL detached signature: ECDSA-Sig-Value missing or malformed")
	}

	var certDER cryptobyte.String
	if !inner.ReadASN1Element(&certDER, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("tsl: TSL detached signature: signer certificate missing or malformed")
	}
	if !inner.Empty() {
		return nil, fmt.Errorf("tsl: TSL detached signature: unexpected extra element (gematik format mandates exactly 3)")
	}

	signer, err := gempki.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("tsl: TSL detached signature: parse signer cert: %w", err)
	}

	return &DetachedSignature{
		Signer: signer,
		Raw:    append([]byte(nil), sig...),
		sigDER: append([]byte(nil), sigDER...),
	}, nil
}

// readAlgorithmIdentifier reads one AlgorithmIdentifier-shaped SEQUENCE
// from in. The gematik format is the minimal form: SEQUENCE { OID } with no
// parameters at all.
func readAlgorithmIdentifier(in *cryptobyte.String) (asn1.ObjectIdentifier, error) {
	var alg cryptobyte.String
	if !in.ReadASN1(&alg, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("tsl: TSL detached signature: AlgorithmIdentifier SEQUENCE missing")
	}
	var oid asn1.ObjectIdentifier
	if !alg.ReadASN1ObjectIdentifier(&oid) {
		return nil, fmt.Errorf("tsl: TSL detached signature: AlgorithmIdentifier missing OID")
	}
	// Some encodings include NULL parameters; the gematik format does not,
	// but be tolerant and just ignore any trailing bytes here.
	return oid, nil
}

func isRSAOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidRSASSAPSS) ||
		oid.Equal(oidSHA256WithRSA) ||
		oid.Equal(oidSHA384WithRSA) ||
		oid.Equal(oidSHA512WithRSA)
}

// VerifyOver checks the signature against tslBytes. It validates only the
// cryptographic signature (ECDSA over SHA-256 of tslBytes) using the embedded
// signer public key — chain validation of the signer is the caller's job.
// Use [VerifySignature] for one-shot verification with trust.
func (s *DetachedSignature) VerifyOver(tslBytes []byte) error {
	if s == nil || s.Signer == nil {
		return fmt.Errorf("tsl: VerifyOver on nil DetachedSignature")
	}
	pub, ok := s.Signer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("tsl: TSL signer public key is %T, want *ecdsa.PublicKey", s.Signer.PublicKey)
	}
	digest := sha256.Sum256(tslBytes)
	if !ecdsa.VerifyASN1(pub, digest[:], s.sigDER) {
		return errors.New("tsl: TSL detached signature does not verify against TSL bytes")
	}
	return nil
}

// VerifySignature is the one-shot entry point: parse the .sig
// bytes, chain-validate the embedded signer cert against the gempki.TrustStore
// (with the supplied intermediates), and verify the signature over tslBytes.
//
// The gempki.TrustStore passed here must contain the TSL-Signer-CA — typically
// obtained from [EmbeddedTSLSignerLoader] — NOT the GEM.RCA<n> Komponenten-PKI
// anchors. The TSL-Signer-CA is structurally a SubCA under GEM.RCA<n>, but
// for TSL verification we treat it as its own trust anchor so callers
// don't need the full Komponenten-PKI loaded.
//
// intermediates may be nil if the signer's chain is short enough to be
// covered by ts alone (the typical case: TSL-Signer EE chains directly to
// the TSL-Signer-CA anchor). opts.TimeFunc and the per-tier checks are
// honoured; most callers will pass the zero value.
func VerifySignature(
	ctx context.Context,
	tslBytes, sigBytes []byte,
	intermediates []*x509.Certificate,
	ts *gempki.TrustStore,
	opts gempki.ValidatePathOptions,
) (*DetachedSignature, error) {
	sig, err := ParseSignature(sigBytes)
	if err != nil {
		return nil, err
	}
	chain, err := gempki.BuildChain(sig.Signer, intermediates, ts)
	if err != nil {
		return nil, fmt.Errorf("tsl: TSL signer chain build: %w", err)
	}
	result, err := gempki.ValidatePath(ctx, chain, opts)
	if err != nil {
		return nil, fmt.Errorf("tsl: TSL signer path validation: %w", err)
	}
	if !result.Valid {
		return nil, fmt.Errorf("tsl: TSL signer chain rejected: %v", result.Errors)
	}
	if err := sig.VerifyOver(tslBytes); err != nil {
		return nil, err
	}
	return sig, nil
}

// LoadSignature fetches the .sig file at sigURL and parses it.
// Uses the caller's [*http.Client] and propagates ctx for cancellation and
// timeouts.
//
// The companion of [Load]; offline callers parse a local file's contents
// with [ParseSignature] instead.
func LoadSignature(ctx context.Context, httpClient *http.Client, sigURL string) (*DetachedSignature, error) {
	if sigURL == "" {
		return nil, fmt.Errorf("tsl: LoadSignature requires a sigURL")
	}
	if httpClient == nil {
		return nil, fmt.Errorf("tsl: LoadSignature requires an HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sigURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("tsl: build sig request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tsl: fetch %s: %w", sigURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsl: fetch %s: HTTP %d", sigURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("tsl: read sig body: %w", err)
	}
	return ParseSignature(body)
}

// SignatureURL returns the detached-signature URL for a TSL URL: the same
// path with ".sig" for ".xml".
func SignatureURL(tslURL string) string {
	return strings.Replace(tslURL, ".xml", ".sig", 1)
}

// SignerTrustStore returns a trust store holding env's TSL-Signer-CA
// anchor, for [VerifySignature].
func SignerTrustStore(env gempki.Environment) (*gempki.TrustStore, error) {
	anchor, err := gempki.EmbeddedTSLSignerAnchor(env)
	if err != nil {
		return nil, err
	}
	return gempki.NewTrustStore([]*x509.Certificate{anchor})
}
