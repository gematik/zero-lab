#!/usr/bin/env bash
# Generates the OpenSSL-written PKCS#12 fixtures of tests/decode.rs. The TEST-ONLY keys in keys/
# and the outputs are committed; a run writes only what is missing, FORCE=1 writes everything
# again from the same keys (spec/fixtures.sh, and the test data rule of docs/design/testing.md).
#
#   ./generate_test_data.sh [OUT]     OUT defaults to this directory
#
# The keys are the ones go/pkcs12/testdata held in 43e97a55, where these files were first
# written. A FORCE rebuild writes the three certificates byte for byte again (RSA PKCS#1 v1.5
# signatures are deterministic).
#
# Randomised on every FORCE rebuild, so their digests in tests/decode.rs follow:
#   *.p12 written by `openssl pkcs12 -export`  salts and IVs, which the command cannot fix
#   random.p12                                 deliberately random data
# truncated.p12, the first 50 bytes of modern.p12, holds only lengths and OIDs and stays the same.
#
# go-baseline.json, what go/pkcs12 decodes from every fixture, is written by baseline/ (Go) on
# every run. It describes certificates, keys and attributes, not salts, IVs or random data, so
# it changes only when a fixture is added or its content changes.
#
# legacy/ and truststore/ are not written here (PROVENANCE.md).
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")" && pwd)}"
keys="$out/keys"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
. "$(dirname "$0")/../../../../spec/fixtures.sh"

ISSUED=20260203190756Z
ONE_YEAR=20270203190756Z
TEN_YEARS=20360201190756Z
PASSWORD=test1234
# OWASP's count for PBKDF2-HMAC-SHA-256 (2023), three derivations within the work budget of P12-036.
HIGH_ITERATIONS=600000

# An explicit configuration, so the host's openssl.cnf adds no extension.
cat > "$work/openssl.cnf" <<'CNF'
[req]
distinguished_name = dn
x509_extensions = ca

[dn]

[ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = critical, CA:true

[ee]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

key ca rsa2048
key server rsa2048
key ec p256

# leaf name subject: a certificate for keys/name.key, signed by the CA.
leaf() {
    local file="$out/$1-cert.pem"
    wanted "$file" || return 0
    openssl req -new -config "$work/openssl.cnf" -key "$keys/$1.key" -subj "$2" -out "$work/$1.csr"
    # shellcheck disable=SC2046
    openssl x509 -req -in "$work/$1.csr" -CA "$out/ca-cert.pem" -CAkey "$keys/ca.key" \
        $(sign_options "$keys/ca.key") -extfile "$work/openssl.cnf" -extensions ee \
        -set_serial "$(serial_of "$1")" -not_before "$ISSUED" -not_after "$ONE_YEAR" -out "$file" 2>/dev/null
}

# p12 file key cert password [openssl pkcs12 options...]
p12() {
    local name=$1 key=$2 cert=$3 password=$4 file="$out/$1"
    shift 4
    wanted "$file" || return 0
    echo "  $name"
    if [ -n "$key" ]; then set -- -inkey "$keys/$key.key" "$@"; fi
    P12_PASSWORD=$password openssl pkcs12 -export -in "$out/$cert" -passout env:P12_PASSWORD \
        -out "$file" "$@"
}

if wanted "$out/ca-cert.pem"; then
    openssl req -x509 -config "$work/openssl.cnf" -key "$keys/ca.key" \
        -subj "/C=DE/ST=Berlin/L=Berlin/O=Gematik/OU=Test CA/CN=Test CA" \
        -set_serial "$(serial_of ca)" \
        -not_before "$ISSUED" -not_after "$TEN_YEARS" -out "$out/ca-cert.pem"
fi
leaf server "/C=DE/ST=Berlin/L=Berlin/O=Gematik/OU=Test/CN=test.example.com"
leaf ec "/C=DE/ST=Berlin/L=Berlin/O=Gematik/OU=Test/CN=ec.example.com"
if wanted "$out/chain.pem"; then cat "$out/server-cert.pem" "$out/ca-cert.pem" > "$out/chain.pem"; fi

# Each file as tests/decode.rs describes it: cert-only.p12 has a MAC and an encrypted
# certificate, high-iter.p12 HIGH_ITERATIONS for its MAC and both PBKDF2 derivations (the others
# OpenSSL's default of 2048).
p12 modern.p12 server server-cert.pem "$PASSWORD" -certfile "$out/ca-cert.pem" \
    -name "Modern Test Certificate"
p12 legacy.p12 server server-cert.pem "$PASSWORD" -legacy \
    -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
p12 aes128.p12 server server-cert.pem "$PASSWORD" -keypbe AES-128-CBC -certpbe AES-128-CBC
p12 ec.p12 ec ec-cert.pem "$PASSWORD" -name "EC Test Certificate"
p12 multi-cert.p12 server chain.pem "$PASSWORD" -name "Multi-Cert Test"
p12 cert-only.p12 "" server-cert.pem "$PASSWORD" -nokeys
p12 empty-pass.p12 server server-cert.pem ""
p12 no-mac.p12 server server-cert.pem "$PASSWORD" -certpbe NONE -nomac
p12 high-iter.p12 server server-cert.pem "$PASSWORD" -iter "$HIGH_ITERATIONS"

if wanted "$out/not-pkcs12.p12"; then cp "$out/server-cert.pem" "$out/not-pkcs12.p12"; fi
if wanted "$out/truncated.p12"; then head -c 50 "$out/modern.p12" > "$out/truncated.p12"; fi
if wanted "$out/random.p12"; then
    dd if=/dev/urandom of="$out/random.p12" bs=1024 count=1 2>/dev/null
fi

(fixtures=$(cd "$out" && pwd) && cd "$(dirname "$0")/baseline" && GOWORK=off go run . "$fixtures") \
    > "$work/go-baseline.json"
cmp -s "$work/go-baseline.json" "$out/go-baseline.json" || cp "$work/go-baseline.json" "$out/go-baseline.json"
