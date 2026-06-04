package gempki

import "time"

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
//
// This is a structural placeholder for the Phase 4 revocation subsystem; only
// the fields needed by [CertResult] are populated by the current code paths.
// Additional fields (raw OCSP DER, producedAt, nextUpdate, signer cert, …)
// arrive when OCSPChecker and HashListChecker land.
type RevocationResult struct {
	Status    RevocationStatus
	Source    RevocationSource
	CheckedAt time.Time
	RevokedAt time.Time // zero unless Status == Revoked
	Reason    string    // human-readable; structured fields TBD in Phase 4
}
