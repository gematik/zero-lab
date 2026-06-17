package gempki

import (
	"crypto/x509"
	"time"
)

// RevocationStatus is the per-certificate revocation verdict derived from a
// single revocation source (OCSP, hash list, cache).
type RevocationStatus string

const (
	// RevocationStatusGood — source explicitly says the certificate is valid.
	RevocationStatusGood RevocationStatus = "good"

	// RevocationStatusRevoked — source explicitly says the certificate is revoked.
	RevocationStatusRevoked RevocationStatus = "revoked"

	// RevocationStatusUnknown — source has no information about this certificate.
	RevocationStatusUnknown RevocationStatus = "unknown"
)

// RevocationSource identifies which mechanism produced a revocation result.
type RevocationSource string

const (
	RevocationSourceOCSP     RevocationSource = "ocsp"
	RevocationSourceHashList RevocationSource = "hashlist"
	RevocationSourceCache    RevocationSource = "cache"
)

// RevocationResult is the revocation outcome for one certificate.
type RevocationResult struct {
	Status    RevocationStatus
	Source    RevocationSource
	CheckedAt time.Time
	RevokedAt time.Time // zero unless Status == Revoked
	Reason    string    // human-readable

	// OCSP fields. Populated when Source == [RevocationSourceOCSP] and the
	// response decoded successfully — useful for displaying the response
	// detail and for diagnostics.
	ResponderURL  string            // the OCSP endpoint we queried
	ProducedAt    time.Time         // BasicOCSPResponse.tbsResponseData.producedAt
	ThisUpdate    time.Time         // SingleResponse.thisUpdate
	NextUpdate    time.Time         // SingleResponse.nextUpdate (zero if absent)
	Responder     *x509.Certificate // embedded responder cert, nil if responder == issuer
	ResponderName string            // CommonName of the signer (Responder or issuer)
	RawResponse   []byte            // raw DER bytes of the OCSP response, kept for forensic dumps
}
