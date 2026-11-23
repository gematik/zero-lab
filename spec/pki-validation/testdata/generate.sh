#!/usr/bin/env bash
# Generates the TEST-ONLY corpus of spec/pki-validation with OpenSSL, an implementation independent
# of ti-pki and go/tipki. The TEST-ONLY keys in keys/ and the output (certificates as PEM, OCSP
# responses and CRLs as DER) are committed; a run writes only what is missing, FORCE=1 writes
# everything again from the same keys (spec/fixtures.sh, and the test data rule of
# docs/design/testing.md). Every signature is deterministic (RFC 6979 ECDSA, RSA PKCS#1 v1.5), so
# no output is randomised. Everything is valid around the fixed instant 2026-01-01T00:00:00Z, the
# reference time of every case in manifest.json.
#
#   ti-root (P-256, GEM.RCA90) ── ti-ca (P-256, the TSL's CA) ── ti-ocsp (id-kp-OCSPSigning)
#     ├─ ti-good        C.FD.TLS-S, CN svc.ti.test, DNS svc.ti.test and alt.ti.test
#     ├─ ti-cn-only     C.FD.TLS-S, CN svc.ti.test, no subjectAltName
#     ├─ ti-wildcard    C.FD.TLS-S, CN and DNS *.ti.test
#     ├─ ti-zd          C.ZD.TLS-S, CN zd.ti.test
#     ├─ ti-tls-c       C.FD.TLS-C (a client type) with serverAuth
#     ├─ ti-client-eku  C.FD.TLS-S policies, but only clientAuth
#     ├─ ti-expired     C.FD.TLS-S, expired 2025-12-31
#     ├─ ti-sha1        C.FD.TLS-S, signed with ECDSA-SHA1
#     ├─ ti-p521        C.FD.TLS-S on a P-521 key
#     └─ ti-revoked     C.FD.TLS-S, revoked at its responder
#
#   web-root (P-256) ── web-ca (RSA 2048) ── web-ocsp (id-kp-OCSPSigning, P-256)
#     ├─ web-p256, web-p384, web-rsa3072   DNS www.web.test, CN other.web.test
#     ├─ web-rsa2048, web-p521             end-entity keys below the 120-bit level, or beside it
#     ├─ web-wildcard (DNS *.web.test), web-partial (DNS f*.web.test), web-cn-only (no SAN),
#     │  web-ip (IP 192.0.2.1)
#     ├─ web-client-eku, web-sha1, web-long (400 days), web-expired
#     ├─ web-revoked (OCSP revoked), web-crl-only (CRL only), web-crl-revoked (revoked in the CRL),
#     │  web-no-status (neither OCSP nor CRL)
#   web-root ── web-ca-1024 (RSA 1024) ── web-under-weak-ca
#
# ocsp/ holds the responses (ti-pki's ocsp.sh assembles them, since `openssl ocsp` can neither
# back-date nor add the certHash the TI requires); crl/ the CRLs of web-ca.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out="${1:-$here}"
keys="$out/keys"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out/ocsp" "$out/crl"
. "$here/../../fixtures.sh"

NOW=20260101000000Z
FIVE_YEARS=20310101000000Z
TEN_YEARS=20360101000000Z
NINETY_DAYS=20260401000000Z
FOUR_HUNDRED_DAYS=20270205000000Z
PAST_FROM=20240101000000Z
PAST_TO=20251231000000Z

cat > "$work/ext.cnf" <<'CNF'
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ocsp_signer]
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ti_base]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.ti.test/

[ti_fd_tls_s]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
certificatePolicies = 1.2.276.0.76.4.163, 1.2.276.0.76.4.169
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.ti.test/

[ti_good]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
certificatePolicies = 1.2.276.0.76.4.163, 1.2.276.0.76.4.169
subjectAltName = DNS:svc.ti.test, DNS:alt.ti.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.ti.test/

[ti_wildcard]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
certificatePolicies = 1.2.276.0.76.4.163, 1.2.276.0.76.4.169
subjectAltName = DNS:*.ti.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.ti.test/

[ti_zd]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
certificatePolicies = 1.2.276.0.76.4.163, 1.2.276.0.76.4.157
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.ti.test/

[ti_tls_c]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
certificatePolicies = 1.2.276.0.76.4.163, 1.2.276.0.76.4.168
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.ti.test/

[ti_client_eku]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
certificatePolicies = 1.2.276.0.76.4.163, 1.2.276.0.76.4.169
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.ti.test/

[web]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:www.web.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.web.test/
crlDistributionPoints = URI:http://crl.web.test/web-ca.crl

[web_wildcard]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:*.web.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.web.test/

[web_partial]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:f*.web.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.web.test/

[web_cn_only]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.web.test/

[web_ip]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:192.0.2.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.web.test/

[web_client_eku]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:www.web.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:http://ocsp.web.test/

[web_crl_only]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:www.web.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
crlDistributionPoints = URI:http://crl.web.test/web-ca.crl

[web_no_status]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:www.web.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CNF

# cert name cn issuer(name|self) from to section [extra x509 options...]; the key is $keys/<name>.key
cert() {
    local name=$1 cn=$2 issuer=$3 from=$4 to=$5 section=$6
    shift 6
    wanted "$out/$name.pem" || return 0
    openssl req -new -key "$keys/$name.key" -subj "/C=DE/O=TEST-ONLY/CN=$cn" -out "$work/$name.csr"
    local signer_key="$keys/$name.key"
    local signer=(-key "$signer_key")
    if [ "$issuer" != self ]; then
        signer_key="$keys/$issuer.key"
        signer=(-CA "$out/$issuer.pem" -CAkey "$signer_key")
    fi
    # shellcheck disable=SC2046 # sign_options prints whole options, one per line
    openssl x509 -req -in "$work/$name.csr" "${signer[@]}" -set_serial "$(serial_of "$name")" \
        -not_before "$from" -not_after "$to" -extfile "$work/ext.cnf" -extensions "$section" \
        $(sign_options "$signer_key") "$@" -out "$out/$name.pem" 2>/dev/null
}

# --- TI ------------------------------------------------------------------------------------

key ti-root p256;      cert ti-root "GEM.RCA90 TEST-ONLY" self "$NOW" "$TEN_YEARS" ca
key ti-ca p256;        cert ti-ca "GEM.KOMP-CA90 TEST-ONLY" ti-root "$NOW" "$FIVE_YEARS" ca
key ti-ocsp p256;      cert ti-ocsp "GEM.KOMP-CA90 OCSP TEST-ONLY" ti-ca "$NOW" "$FIVE_YEARS" ocsp_signer
key ti-good p256;      cert ti-good "svc.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_good
key ti-cn-only p256;   cert ti-cn-only "svc.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_fd_tls_s
key ti-wildcard p256;  cert ti-wildcard "*.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_wildcard
key ti-zd p256;        cert ti-zd "zd.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_zd
key ti-tls-c p256;     cert ti-tls-c "svc.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_tls_c
key ti-client-eku p256; cert ti-client-eku "svc.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_client_eku
key ti-expired p256;   cert ti-expired "svc.ti.test" ti-ca "$PAST_FROM" "$PAST_TO" ti_fd_tls_s
key ti-sha1 p256;      cert ti-sha1 "svc.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_fd_tls_s -sha1
key ti-p521 p521;      cert ti-p521 "svc.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_fd_tls_s
key ti-revoked p256;   cert ti-revoked "svc.ti.test" ti-ca "$NOW" "$FIVE_YEARS" ti_fd_tls_s

# --- Web -----------------------------------------------------------------------------------

key web-root p256;     cert web-root "TLSV Web Root TEST-ONLY" self "$NOW" "$TEN_YEARS" ca
key web-ca rsa2048;    cert web-ca "TLSV Web CA TEST-ONLY" web-root "$NOW" "$FIVE_YEARS" ca
key web-ocsp p256;     cert web-ocsp "TLSV Web OCSP TEST-ONLY" web-ca "$NOW" "$FIVE_YEARS" ocsp_signer -sha256
key web-ca-1024 rsa1024
cert web-ca-1024 "TLSV Weak CA TEST-ONLY" web-root "$NOW" "$FIVE_YEARS" ca
web_ee() { # name kind cn section [extra...]
    local name=$1 kind=$2 cn=$3 section=$4
    shift 4
    key "$name" "$kind"
    cert "$name" "$cn" web-ca "$NOW" "$NINETY_DAYS" "$section" -sha256 "$@"
}
web_ee web-p256 p256 other.web.test web
web_ee web-p384 P-384 other.web.test web
web_ee web-rsa3072 rsa3072 other.web.test web
web_ee web-rsa2048 rsa2048 other.web.test web
web_ee web-p521 p521 other.web.test web
web_ee web-wildcard p256 "*.web.test" web_wildcard
web_ee web-partial p256 "f*.web.test" web_partial
web_ee web-cn-only p256 www.web.test web_cn_only
web_ee web-ip p256 192.0.2.1 web_ip
web_ee web-client-eku p256 www.web.test web_client_eku
key web-sha1 p256;     cert web-sha1 www.web.test web-ca "$NOW" "$NINETY_DAYS" web -sha1
key web-long p256;     cert web-long www.web.test web-ca "$NOW" "$FOUR_HUNDRED_DAYS" web -sha256
key web-expired p256;  cert web-expired www.web.test web-ca "$PAST_FROM" "$PAST_TO" web -sha256
web_ee web-revoked p256 www.web.test web
web_ee web-crl-only p256 www.web.test web_crl_only
web_ee web-crl-revoked p256 www.web.test web_crl_only
web_ee web-no-status p256 www.web.test web_no_status
key web-under-weak-ca p256
cert web-under-weak-ca www.web.test web-ca-1024 "$NOW" "$NINETY_DAYS" web -sha256

# --- OCSP ----------------------------------------------------------------------------------

. "$here/../../../rust/ti-pki/tests/pki/ocsp.sh"
# ocsp_response name cert issuer signer status certhash-of next-update embed
for ee in ti-good ti-cn-only ti-wildcard ti-zd ti-tls-c ti-client-eku ti-sha1 ti-p521; do
    ocsp_response "$ee-good" "$ee" ti-ca ti-ocsp good "$ee" - embed
done
ocsp_response ti-revoked-revoked ti-revoked ti-ca ti-ocsp revoked ti-revoked - embed
ocsp_response ti-good-unknown ti-good ti-ca ti-ocsp unknown ti-good - embed
ocsp_response ti-good-wrong-hash ti-good ti-ca ti-ocsp good ti-cn-only - embed
# A stapled response from an hour before the reference time: beyond the 10-minute grace period.
NOW=20251231230000Z ocsp_response ti-good-stale ti-good ti-ca ti-ocsp good ti-good - embed

for ee in web-p256 web-p384 web-rsa3072 web-rsa2048 web-p521 web-wildcard web-partial web-cn-only \
    web-ip web-client-eku web-sha1 web-long web-expired; do
    ocsp_response "$ee-good" "$ee" web-ca web-ocsp good - "$NINETY_DAYS" embed
done
ocsp_response web-revoked-revoked web-revoked web-ca web-ocsp revoked - "$NINETY_DAYS" embed
ocsp_response web-p256-unknown web-p256 web-ca web-ocsp unknown - "$NINETY_DAYS" embed

# --- CRL -----------------------------------------------------------------------------------

# The CRL number is fixed per CRL, not counted by `openssl ca`, so a CRL written alone gets the same
# number as in a full run.
mkdir -p "$work/ca"
cat > "$work/ca.cnf" <<CNF
[ca]
default_ca = web
[web]
database = $work/ca/index.txt
crlnumber = $work/ca/crlnumber
default_md = sha256
crl_extensions = crl_ext
[crl_ext]
authorityKeyIdentifier = keyid:always
CNF
crl() { # name number; the revoked entries are in $work/ca/index.txt
    wanted "$out/crl/$1.der" || return 0
    echo "$2" > "$work/ca/crlnumber"
    openssl ca -config "$work/ca.cnf" -gencrl -cert "$out/web-ca.pem" -keyfile "$keys/web-ca.key" \
        -crl_lastupdate "$NOW" -crl_nextupdate 20260108000000Z -out "$work/crl.pem" 2>/dev/null
    openssl crl -in "$work/crl.pem" -outform DER -out "$out/crl/$1.der"
}
: > "$work/ca/index.txt"
crl web-ca-empty 01
revoked_serial=$(openssl x509 -in "$out/web-crl-revoked.pem" -noout -serial | cut -d= -f2)
printf 'R\t%s\t%s\t%s\tunknown\t/C=DE/O=TEST-ONLY/CN=www.web.test\n' \
    "${NINETY_DAYS:2}" "251201000000Z" "$revoked_serial" > "$work/ca/index.txt"
crl web-ca-revoked 02
