#!/usr/bin/env bash
# A TEST-ONLY SMC-B-like identity for the `ti identity` tests: a brainpoolP256r1 CA and
# three end entities with the key usages a gematik SMC-B carries (AUT: digitalSignature,
# OSIG: digitalSignature + contentCommitment, ENC: keyEncipherment), each with its key,
# as PEM and as a single-pair PKCS#12 (password 00, like gematik's test cards). The
# tests merge the PKCS#12 files into one when they need several pairs in a file.
#
# And a TEST-ONLY HBA-like identity under a CA of its own: C.HP.AUT (digitalSignature)
# and C.HP.QES (contentCommitment), with a practitioner's admission.
#
# Also data.bin and its ECDSA-SHA256 signature by the AUT key, DER-encoded, for
# `ti pki verify-signature`.
#
# Needs an OpenSSL with brainpool (3.x/4.x). All keys are TEST-ONLY and committed next to the
# fixtures (ca.key and hba-ca.key too); a run writes only what is missing, FORCE=1 writes
# everything again from the same keys (spec/fixtures.sh, and the test data rule of
# docs/design/testing.md). Serial numbers come from the file's name, ECDSA signatures are
# deterministic. The .p12 files are randomised: OpenSSL draws the salts and IVs of the PKCS#12
# encryption and MAC itself, so they differ on every FORCE rebuild, the certificate and key
# inside stay the same. Everything else is reproducible.
set -euo pipefail
cd "$(dirname "$0")"
keys=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
. ../../../../../spec/fixtures.sh

NOW=20260101000000Z
TEN_YEARS=20360101000000Z
FIVE_YEARS=20310101000000Z

ext=$work/ext.cnf
cat > "$ext" <<'CNF'
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[aut]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
1.3.36.8.3.3 = ASN1:SEQUENCE:admission_syntax

[osig]
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
1.3.36.8.3.3 = ASN1:SEQUENCE:admission_syntax

[enc]
keyUsage = critical, keyEncipherment, keyAgreement
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
1.3.36.8.3.3 = ASN1:SEQUENCE:admission_syntax

[hp_aut]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
1.3.36.8.3.3 = ASN1:SEQUENCE:hp_admission_syntax

[hp_qes]
keyUsage = critical, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
1.3.36.8.3.3 = ASN1:SEQUENCE:hp_admission_syntax

[hp_admission_syntax]
contents = SEQUENCE:hp_contents_of_admissions
[hp_contents_of_admissions]
admissions = SEQUENCE:hp_admissions
[hp_admissions]
profession_infos = SEQUENCE:hp_profession_infos
[hp_profession_infos]
info = SEQUENCE:hp_profession_info
[hp_profession_info]
items = SEQUENCE:hp_profession_items
oids = SEQUENCE:hp_profession_oids
registration_number = PRINTABLESTRING:1-HBA-TESTONLY01
[hp_profession_items]
item = UTF8String:Arzt
[hp_profession_oids]
oid = OID:1.2.276.0.76.4.30

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
registration_number = PRINTABLESTRING:1-2-ARZTPRAXIS-TESTONLY01
[profession_items]
item = UTF8String:Betriebsstaette Arzt
[profession_oids]
oid = OID:1.2.276.0.76.4.50
CNF

cert() { # name cn issuer(name|self) section
    local name=$1 cn=$2 issuer=$3 section=$4
    wanted "$name.pem" || return 0
    openssl req -new -key "$name.key" -subj "/C=DE/O=gematik TEST-ONLY/CN=$cn" -out "$work/$name.csr"
    local signer=(-key "$name.key") signkey=$name.key
    local to=$FIVE_YEARS
    if [ "$issuer" = self ]; then
        to=$TEN_YEARS
    else
        signer=(-CA "$issuer.pem" -CAkey "$issuer.key") signkey=$issuer.key
    fi
    # shellcheck disable=SC2046 # sign_options prints whole options, one per line
    openssl x509 -req -in "$work/$name.csr" "${signer[@]}" -set_serial "$(serial_of "$name")" \
        -not_before "$NOW" -not_after "$to" -extfile "$ext" -extensions "$section" \
        $(sign_options "$signkey") -out "$name.pem" 2>/dev/null
}

p12() { # name [ca]
    wanted "$1.p12" || return 0
    openssl pkcs12 -export -inkey "$1.key" -in "$1.pem" -certfile "${2:-ca}.pem" \
        -name "$1" -passout pass:00 -out "$1.p12"
}

for k in ca aut osig enc hba-ca hba-aut hba-qes; do key "$k" bp256; done

cert ca "GEM.SMCB-CA TEST-ONLY" self ca
cert aut "Arztpraxis TEST-ONLY" ca aut
cert osig "Arztpraxis TEST-ONLY" ca osig
cert enc "Arztpraxis TEST-ONLY" ca enc
p12 aut; p12 osig; p12 enc

cert hba-ca "GEM.HBA-CA TEST-ONLY" self ca
cert hba-aut "Dr. Test-Only" hba-ca hp_aut
cert hba-qes "Dr. Test-Only" hba-ca hp_qes
p12 hba-aut hba-ca; p12 hba-qes hba-ca

# The AUT certificate and the CA in one PEM, as `--cert` takes a chain.
if wanted aut-chain.pem; then cat aut.pem ca.pem > aut-chain.pem; fi

if wanted data.bin; then printf 'VAU signed_pub_keys TEST-ONLY\n' > data.bin; fi
if wanted sig.der; then
    # shellcheck disable=SC2046
    openssl dgst -sha256 -sign aut.key $(sign_options aut.key) -out sig.der data.bin
fi
openssl x509 -in aut.pem -pubkey -noout > "$work/aut-pub.pem"
openssl dgst -sha256 -verify "$work/aut-pub.pem" -signature sig.der data.bin >/dev/null

{
    echo "# Provenance"
    echo
    echo "Generated by generate.sh. TEST-ONLY material: committed keys, a self-made CA, no relation to any TI PKI."
    echo "Refresh: \`FORCE=1 ./generate.sh\`; only the .p12 files change bytes (PKCS#12 salts and IVs are random)."
    echo
    echo "| File | SHA-256 |"
    echo "|---|---|"
    for f in ca.key hba-ca.key ca.pem aut.pem aut.key aut-chain.pem aut.p12 osig.pem osig.key osig.p12 enc.pem enc.key enc.p12 \
        hba-ca.pem hba-aut.pem hba-aut.key hba-aut.p12 hba-qes.pem hba-qes.key hba-qes.p12 data.bin sig.der; do
        printf '| `%s` | `%s` |\n' "$f" "$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)"
    done
} > PROVENANCE.md
