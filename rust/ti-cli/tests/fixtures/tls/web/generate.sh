#!/usr/bin/env bash
# TEST-ONLY servers for `ti pki verify --connect … --validation-profile web` (tests/verify_tls_server.rs),
# made with OpenSSL, valid around 2026-01-01T00:00:00Z, the --at of every test:
#
#   root (P-256) ── ca (P-256, signs the OCSP responses itself)
#     ├─ p256       DNS www.web.test, OCSP and CRL addresses; ocsp/p256-good.der to staple
#     ├─ rsa2048    the same on an RSA-2048 key (TLSV-041's warning); ocsp/rsa2048-good.der
#     ├─ no-status  DNS www.web.test, no OCSP or CRL address (TLSV-044's warning)
#     └─ ti-type    C.FD.TLS-S's policies, DNS svc.ti.test: a TI certificate type, which
#                   --validation-profile auto takes to the TI's validation
#
# The servers' keys are written next to their certificates; the CAs' live only while this runs.
# Keys are random: running it again changes every file.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=$here
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out/ocsp"

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

serial=3000
# cert name cn issuer(name|self) to section keydir
cert() {
    local name=$1 cn=$2 issuer=$3 to=$4 section=$5 keys=$6
    serial=$((serial + 1))
    openssl req -new -key "$keys/$name.key" -subj "/C=DE/O=TEST-ONLY/CN=$cn" -out "$work/$name.csr"
    local signer=(-key "$keys/$name.key")
    if [ "$issuer" != self ]; then
        signer=(-CA "$out/$issuer.pem" -CAkey "$work/$issuer.key")
    fi
    openssl x509 -req -in "$work/$name.csr" "${signer[@]}" -set_serial "$serial" -sha256 \
        -not_before "$NOW" -not_after "$to" -extfile "$work/ext.cnf" -extensions "$section" \
        -out "$out/$name.pem" 2>/dev/null
}
ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "$1" 2>/dev/null; }

ec "$work/root.key"; cert root "TLSV Web Root TEST-ONLY" self "$TEN_YEARS" ca "$work"
ec "$work/ca.key";   cert ca "TLSV Web CA TEST-ONLY" root "$TEN_YEARS" ca "$work"
ec "$out/p256.key";  cert p256 www.web.test ca "$NINETY_DAYS" web "$out"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$out/rsa2048.key" 2>/dev/null
cert rsa2048 www.web.test ca "$NINETY_DAYS" web "$out"
ec "$out/no-status.key"; cert no-status www.web.test ca "$NINETY_DAYS" web_no_status "$out"
ec "$out/ti-type.key"; cert ti-type svc.ti.test ca "$NINETY_DAYS" ti_type "$out"

# ocsp.sh reads the subjects' certificates from $out and the signer's key from $work.
. "$here/../../../../../ti-pki/tests/pki/ocsp.sh"
ocsp_response p256-good p256 ca ca good - "$NINETY_DAYS" -
ocsp_response rsa2048-good rsa2048 ca ca good - "$NINETY_DAYS" -
