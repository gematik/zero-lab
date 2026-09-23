#!/usr/bin/env bash
# Generates the test PKI with OpenSSL: an implementation independent of ti-pki produces
# every certificate the tests validate. Run with `just test-pki` from rust/; the output
# (PEM certificates, no keys) is committed, keys live only in a temporary directory.
#
# The topology mirrors go/gempki/internal/testca, validated at a fixed instant
# (TestPki::NOW, 2026-01-01T00:00:00Z) so the files never go stale:
#
#   rca1 (brainpoolP256r1) ── sub-ca-hba ── ee-arzt (admission: Arzt)
#     │                                  ├─ ee-expired, ee-not-yet-valid, ee-revoked
#     ├─ sub-ca-mixed ── ee-mixed (P-256)
#     ├─ sub-ca-expired ── ee-under-expired
#     └─ cross-rca1-for-rca7 (RCA7's name and key, signed by RCA1)
#   rca7 (P-256) ── sub-ca-komp ── ee-zeta (serverAuth, DNS zeta.ti-dienste.de)
#     ├─ ee-p521 (a P-521 key, never admissible in the TI)
#     └─ cross-rca7-for-rca1 (RCA1's name and key, signed by RCA7: a loop)
#   rogue-root (P-256, trusted nowhere) ── ee-rogue
#   rca-rsa (RSA 3072) ── ee-rsa-pss (RSA 2048, signed with RSASSA-PSS)
#   cross-rca1-not-rca (RCA7's key under a non-GEM.RCA name, signed by RCA1)
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")" && pwd)}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

NOW=20260101000000Z
TEN_YEARS=20360101000000Z
FIVE_YEARS=20310101000000Z
PAST_FROM=20240101000000Z
PAST_TO=20251231000000Z
FUTURE_FROM=20260102000000Z
FUTURE_TO=20270101000000Z

cat > "$work/ext.cnf" <<'CNF'
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ee]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ee_zeta]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:zeta.ti-dienste.de
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ee_arzt]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
1.3.36.8.3.3 = ASN1:SEQUENCE:admission_syntax

[admission_syntax]
contents = SEQUENCE:contents_of_admissions
[contents_of_admissions]
admissions = SEQUENCE:admissions
[admissions]
profession_infos = SEQUENCE:profession_infos
[profession_infos]
info = SEQUENCE:profession_info
[profession_info]
items = SEQUENCE:profession_items
oids = SEQUENCE:profession_oids
registration_number = PRINTABLESTRING:80276001081234567890
[profession_items]
item = UTF8String:Arzt
[profession_oids]
oid = OID:1.2.276.0.76.4.30
CNF

serial=1000
key() { # name kind
    case "$2" in
        bp256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1 \
                   -pkeyopt ec_param_enc:named_curve -out "$work/$1.key" 2>/dev/null ;;
        p256)  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
                   -pkeyopt ec_param_enc:named_curve -out "$work/$1.key" 2>/dev/null ;;
        p521)  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 \
                   -pkeyopt ec_param_enc:named_curve -out "$work/$1.key" 2>/dev/null ;;
        rsa*)  openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${2#rsa}" \
                   -out "$work/$1.key" 2>/dev/null ;;
    esac
}

# cert name key-of-subject cn issuer(name|self) from to section [extra x509 options...]
cert() {
    local name=$1 subject_key=$2 cn=$3 issuer=$4 from=$5 to=$6 section=$7
    shift 7
    serial=$((serial + 1))
    openssl req -new -key "$work/$subject_key.key" -subj "/C=DE/CN=$cn" -out "$work/$name.csr"
    local signer=(-key "$work/$subject_key.key")
    if [ "$issuer" != self ]; then
        signer=(-CA "$out/$issuer.pem" -CAkey "$work/$issuer.key")
    fi
    openssl x509 -req -in "$work/$name.csr" "${signer[@]}" -set_serial "$serial" \
        -not_before "$from" -not_after "$to" -extfile "$work/ext.cnf" -extensions "$section" \
        "$@" -out "$out/$name.pem" 2>/dev/null
}

key rca1 bp256;          cert rca1 rca1 "GEM.RCA1 TEST-ONLY" self "$NOW" "$TEN_YEARS" ca
key sub-ca-hba bp256;    cert sub-ca-hba sub-ca-hba "GEM.SubCA-HBA TEST-ONLY" rca1 "$NOW" "$FIVE_YEARS" ca
key ee-arzt bp256;       cert ee-arzt ee-arzt "Dr. Arzt TEST-ONLY" sub-ca-hba "$NOW" "$FIVE_YEARS" ee_arzt
key ee-expired bp256;    cert ee-expired ee-expired "EE-Expired TEST-ONLY" sub-ca-hba "$PAST_FROM" "$PAST_TO" ee
key ee-not-yet-valid bp256
cert ee-not-yet-valid ee-not-yet-valid "EE-NotYetValid TEST-ONLY" sub-ca-hba "$FUTURE_FROM" "$FUTURE_TO" ee
key ee-revoked bp256;    cert ee-revoked ee-revoked "EE-Revoked TEST-ONLY" sub-ca-hba "$NOW" "$FIVE_YEARS" ee
key sub-ca-mixed bp256;  cert sub-ca-mixed sub-ca-mixed "GEM.SubCA-Mixed TEST-ONLY" rca1 "$NOW" "$FIVE_YEARS" ca
key ee-mixed p256;       cert ee-mixed ee-mixed "mixed-curve-ee TEST-ONLY" sub-ca-mixed "$NOW" "$FIVE_YEARS" ee
key sub-ca-expired bp256
cert sub-ca-expired sub-ca-expired "GEM.SubCA-Expired TEST-ONLY" rca1 "$PAST_FROM" "$PAST_TO" ca
key ee-under-expired bp256
cert ee-under-expired ee-under-expired "EE-UnderExpired TEST-ONLY" sub-ca-expired "$NOW" "$FIVE_YEARS" ee

key rca7 p256;           cert rca7 rca7 "GEM.RCA7 TEST-ONLY" self "$NOW" "$TEN_YEARS" ca
key sub-ca-komp p256;    cert sub-ca-komp sub-ca-komp "GEM.SubCA-Komp TEST-ONLY" rca7 "$NOW" "$FIVE_YEARS" ca
key ee-zeta p256;        cert ee-zeta ee-zeta "zeta.ti-dienste.de TEST-ONLY" sub-ca-komp "$NOW" "$FIVE_YEARS" ee_zeta
key ee-p521 p521;        cert ee-p521 ee-p521 "P-521 TEST-ONLY" rca7 "$NOW" "$FIVE_YEARS" ee

cert cross-rca1-for-rca7 rca7 "GEM.RCA7 TEST-ONLY" rca1 "$NOW" "$TEN_YEARS" ca
cert cross-rca7-for-rca1 rca1 "GEM.RCA1 TEST-ONLY" rca7 "$NOW" "$TEN_YEARS" ca
cert cross-rca1-not-rca rca7 "Not A Root" rca1 "$NOW" "$TEN_YEARS" ca

key rogue-root p256;     cert rogue-root rogue-root "ROGUE-ROOT NOT-VALID" self "$NOW" "$TEN_YEARS" ca
key ee-rogue p256;       cert ee-rogue ee-rogue "rogue-ee NOT-VALID" rogue-root "$NOW" "$FIVE_YEARS" ee

key rca-rsa rsa3072;     cert rca-rsa rca-rsa "GEM.RCA-RSA TEST-ONLY" self "$NOW" "$TEN_YEARS" ca -sha256
key ee-rsa-pss rsa2048
cert ee-rsa-pss ee-rsa-pss "EE-RSA-PSS TEST-ONLY" rca-rsa "$NOW" "$FIVE_YEARS" ee \
    -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256

echo "wrote $(ls "$out"/*.pem | wc -l | tr -d ' ') certificates to $out"
