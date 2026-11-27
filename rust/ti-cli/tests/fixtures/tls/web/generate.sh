#!/usr/bin/env bash
# TEST-ONLY servers for `ti pki verify --connect … --validation-profile web` (tests/verify_tls_server.rs),
# made with OpenSSL, valid around 2026-01-01T00:00:00Z, the --at of every test:
#
#   root (P-256) ── ca (P-256, signs the OCSP responses itself)
#     ├─ p256       DNS www.web.test, OCSP and CRL addresses; ocsp/p256-good.der to staple
#     ├─ rsa2048    the same on an RSA-2048 key (TLSV-041's warning); ocsp/rsa2048-good.der
#     ├─ p384       the same on a P-384 key, no OCSP response: a TLS 1.2 server that signs
#     │             its handshake with SHA-256 (ti-client's chain capture)
#     ├─ no-status  DNS www.web.test, no OCSP or CRL address (TLSV-044's warning)
#     └─ ti-type    C.FD.TLS-S's policies, DNS svc.ti.test: a TI certificate type, which
#                   --validation-profile auto takes to the TI's validation
#
# The TEST-ONLY keys of the servers and of the CAs (root.key, ca.key) are committed next to the
# certificates; a run writes only what is missing, FORCE=1 writes everything again from the same
# keys (spec/fixtures.sh, and the test data rule of docs/design/testing.md). Serial numbers come
# from the name, ECDSA signatures are deterministic, RSA PKCS#1 v1.5 (rsa2048) always is.
# Nothing here is randomised.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=$here
keys=$here
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out/ocsp"
. "$here/../../../../../../spec/fixtures.sh"

NOW=20260101000000Z
NINETY_DAYS=20260401000000Z
TEN_YEARS=20360101000000Z

cat > "$work/ext.cnf" <<'CNF'
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[web]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:www.web.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.web.test/
crlDistributionPoints = URI:http://crl.web.test/ca.crl

[ti_type]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
certificatePolicies = 1.2.276.0.76.4.163, 1.2.276.0.76.4.169
subjectAltName = DNS:svc.ti.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[web_no_status]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:www.web.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CNF

# cert name cn issuer(name|self) to section
cert() {
    local name=$1 cn=$2 issuer=$3 to=$4 section=$5
    wanted "$out/$name.pem" || return 0
    openssl req -new -key "$keys/$name.key" -subj "/C=DE/O=TEST-ONLY/CN=$cn" -out "$work/$name.csr"
    local signer=(-key "$keys/$name.key") signkey=$keys/$name.key
    if [ "$issuer" != self ]; then
        signer=(-CA "$out/$issuer.pem" -CAkey "$keys/$issuer.key") signkey=$keys/$issuer.key
    fi
    # shellcheck disable=SC2046 # sign_options prints whole options, one per line
    openssl x509 -req -in "$work/$name.csr" "${signer[@]}" -set_serial "$(serial_of "$name")" -sha256 \
        -not_before "$NOW" -not_after "$to" -extfile "$work/ext.cnf" -extensions "$section" \
        $(sign_options "$signkey") -out "$out/$name.pem" 2>/dev/null
}

key root p256
key ca p256
key p256 p256
key rsa2048 rsa2048
key p384 P-384
key no-status p256
key ti-type p256

cert root "TLSV Web Root TEST-ONLY" self "$TEN_YEARS" ca
cert ca "TLSV Web CA TEST-ONLY" root "$TEN_YEARS" ca
cert p256 www.web.test ca "$NINETY_DAYS" web
cert rsa2048 www.web.test ca "$NINETY_DAYS" web
cert p384 www.web.test ca "$NINETY_DAYS" web
cert no-status www.web.test ca "$NINETY_DAYS" web_no_status
cert ti-type svc.ti.test ca "$NINETY_DAYS" ti_type

# ocsp.sh reads the subjects' certificates from $out and the signer's key from $keys.
. "$here/../../../../../ti-pki/tests/pki/ocsp.sh"
ocsp_response p256-good p256 ca ca good - "$NINETY_DAYS" -
ocsp_response rsa2048-good rsa2048 ca ca good - "$NINETY_DAYS" -
