// Package brainpool implements the Brainpool elliptic curves (RFC 5639) as
// the gematik Telematikinfrastruktur uses them: the curves themselves,
// certificate and key parsing the standard library refuses for these
// curves, and the signing and key-agreement entry points behind the josebp
// JOSE layer.
//
// # Constant-time posture
//
// Only operations on a secret scalar need a constant-time implementation,
// and only brainpoolP256r1 — the curve gematik issues software-held keys
// on — has one, the formally-verified core in internal/bp256:
//
//	operation                              secret   implementation
//	ECDSA sign (SignFuncPrivateKey)        k, d     internal/bp256, RFC 6979 nonce, low-s
//	ECDH                                   d        internal/bp256
//	public key from private (parse, GenerateKey)  d  internal/bp256
//	ECDSA verify, certificate/JWK parsing  —        standard library
//	brainpoolP384r1 / P512r1, everything   —        standard library generic path
//
// The generic path is the deprecated big.Int arithmetic of crypto/elliptic,
// reached through an isomorphism onto the twisted t1 curves; it is fine for
// public data and for the curves that never hold a software key.
//
// # Where to look
//
//	curves.go   P256r1/P384r1/P512r1, the curve table, the rcurve isomorphism
//	x509.go     ParseCertificate, ValidatePublicKey, MarshalPKIXPublicKey
//	keys.go     ParsePrivateKeyPEM, ParsePKCS8PrivateKey, ParseECPrivateKey
//	sign.go     SignFunc, SignFuncPrivateKey, ECDH, GenerateKey
//	josebp/     JWS, JWE (ECDH-ES), JWK over these curves
//	internal/bp256/  the constant-time brainpoolP256r1 core and its fiat fields
//
// README.md carries the full security posture and references.
package brainpool
