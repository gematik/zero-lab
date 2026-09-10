// Package testca mints the synthetic TI-shaped PKI the gempki tests run
// against: Brainpool and NIST roots, SubCAs, end entities with admission
// extensions, cross-certificates, and the time-edge and revoked cases.
//
// It is test support and nothing else. Its helpers take *testing.T and
// fail or skip the calling test by design, the way x/tools' testenv does;
// being internal, the package only ever links into test binaries.
package testca
