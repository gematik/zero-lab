#!/usr/bin/env bash
# Generates TSL signer certificates for the part B checks of spec/tsl-xmldsig
# (TSLSIG-031 – 035) with OpenSSL: a TSL signer CA in the Tab_PKI_212 profile and
# C.TSL.SIG signers under it, each breaking one rule. Run with `just test-pki` from rust/;
# the PEM certificates are committed, keys live only in a temporary directory.
#
#   ca.pem                 GEM.TSL-CA99 TEST-ONLY (brainpoolP256r1, CA, pathLen 0)
#   ca-same-name.pem       the same name with another key: the AKI check
#   signer.pem             C.TSL.SIG as gematik issues it
#   signer-aki-different   issued by ca-same-name
#   signer-ku-extra        nonRepudiation and digitalSignature
#   signer-eku-extra       tslSigning and clientAuth
#   signer-no-policy       oid_policy_gem_or_cp instead of oid_policy_gem_tsl_signer
#   signer-ca              basicConstraints cA=TRUE
#   signer-no-aia          without AuthorityInfoAccess
#   signer-compressed-key  the key point compressed
#   signer-p256            a P-256 key
#   signer-sha384          signed with ecdsa-with-SHA384
#   ocsp-signer            the CA's OCSP responder (id-kp-OCSPSigning, RFC 6960 delegate)
#
# ocsp/ holds answers about `signer` at 2026-01-01 (TSLSIG-040 – 042), assembled like the
# responses of ../generate.sh:
#   good, revoked, unknown        by ocsp-signer; good and revoked with certHash
#   no-cert-hash, wrong-cert-hash certHash absent / over signer-ku-extra
#   issuer-signed                 good, signed by the CA itself, no certificates
#
# Validity: the CAs 2026-01-01 – 2036-01-01, the signers 2026-01-01 – 2031-01-01.
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")" && pwd)}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

NOW=20260101000000Z
TEN_YEARS=20360101000000Z
FIVE_YEARS=20310101000000Z
TSL_SIGNER=1.2.276.0.76.4.176
GEM_OR_CP=1.2.276.0.76.4.163
TSL_SIGNING=0.4.0.2231.3.0
serial=100

key() { # name curve
    openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" \
        -pkeyopt ec_param_enc:named_curve -out "$work/$1.key" 2>/dev/null
}

ca() { # name
    key "$1" brainpoolP256r1
    cat > "$work/$1.cnf" <<CNF
[ext]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
certificatePolicies = $GEM_OR_CP
CNF
    openssl req -new -key "$work/$1.key" \
        -subj "/C=DE/O=gematik GmbH NOT-VALID/OU=TSL-Signer-CA der Telematikinfrastruktur/CN=GEM.TSL-CA99 TEST-ONLY" \
        -out "$work/$1.csr"
    serial=$((serial + 1))
    openssl x509 -req -in "$work/$1.csr" -key "$work/$1.key" -sha256 -set_serial "$serial" \
        -not_before "$NOW" -not_after "$TEN_YEARS" -extfile "$work/$1.cnf" -extensions ext \
        -out "$out/$1.pem" 2>/dev/null
}

# signer name issuer "key usage" "ext key usage" policy "extra lines" [curve] [digest]
signer() {
    local name=$1 issuer=$2 ku=$3 eku=$4 policy=$5 extra=$6 curve=${7:-brainpoolP256r1}
    local digest=${8:-sha256} ext="$work/$1.cnf"
    {
        echo "[ext]"
        echo "keyUsage = critical, $ku"
        echo "extendedKeyUsage = $eku"
        echo "certificatePolicies = $policy"
        echo "subjectKeyIdentifier = hash"
        echo "authorityKeyIdentifier = keyid:always"
        [ -n "$extra" ] && printf '%b\n' "$extra"
    } > "$ext"
    key "$name" "$curve"
    if [ "$name" = signer-compressed-key ]; then
        openssl ec -in "$work/$name.key" -conv_form compressed -out "$work/$name.key" 2>/dev/null
    fi
    openssl req -new -key "$work/$name.key" \
        -subj "/C=DE/O=gematik GmbH NOT-VALID/CN=TSL Signing Unit 99 $name TEST-ONLY" \
        -out "$work/$name.csr"
    serial=$((serial + 1))
    openssl x509 -req -in "$work/$name.csr" -CA "$out/$issuer.pem" -CAkey "$work/$issuer.key" \
        -"$digest" -set_serial "$serial" -not_before "$NOW" -not_after "$FIVE_YEARS" \
        -extfile "$ext" -extensions ext -out "$out/$name.pem" 2>/dev/null
}

ca ca
ca ca-same-name

nr=nonRepudiation
aia='authorityInfoAccess = OCSP;URI:http://ocsp-testref.tsl.ti-dienste.de/ocsp'
eebc='basicConstraints = critical, CA:false'
ok="$eebc\n$aia"

signer signer                ca           $nr                       $TSL_SIGNING              $TSL_SIGNER "$ok"
signer signer-aki-different  ca-same-name $nr                       $TSL_SIGNING              $TSL_SIGNER "$ok"
signer signer-ku-extra       ca           "$nr, digitalSignature"   $TSL_SIGNING              $TSL_SIGNER "$ok"
signer signer-eku-extra      ca           $nr                       "$TSL_SIGNING, clientAuth" $TSL_SIGNER "$ok"
signer signer-no-policy      ca           $nr                       $TSL_SIGNING              $GEM_OR_CP  "$ok"
signer signer-ca             ca           $nr                       $TSL_SIGNING              $TSL_SIGNER "basicConstraints = critical, CA:true\n$aia"
signer signer-no-aia         ca           $nr                       $TSL_SIGNING              $TSL_SIGNER "$eebc"
signer signer-compressed-key ca           $nr                       $TSL_SIGNING              $TSL_SIGNER "$ok"
signer signer-p256           ca           $nr                       $TSL_SIGNING              $TSL_SIGNER "$ok" P-256
signer signer-sha384         ca           $nr                       $TSL_SIGNING              $TSL_SIGNER "$ok" brainpoolP256r1 sha384

key ocsp-signer brainpoolP256r1
cat > "$work/ocsp-signer.cnf" <<CNF
[ext]
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CNF
openssl req -new -key "$work/ocsp-signer.key" \
    -subj "/C=DE/O=gematik GmbH NOT-VALID/CN=TSL-CA99 OCSP-Signer TEST-ONLY" -out "$work/ocsp-signer.csr"
serial=$((serial + 1))
openssl x509 -req -in "$work/ocsp-signer.csr" -CA "$out/ca.pem" -CAkey "$work/ca.key" -sha256 \
    -set_serial "$serial" -not_before "$NOW" -not_after "$FIVE_YEARS" \
    -extfile "$work/ocsp-signer.cnf" -extensions ext -out "$out/ocsp-signer.pem" 2>/dev/null

. "$(dirname "$0")/../ocsp.sh"
mkdir -p "$out/ocsp"
ocsp_response good signer ca ocsp-signer good signer - embed
ocsp_response revoked signer ca ocsp-signer revoked signer - embed
ocsp_response unknown signer ca ocsp-signer unknown - - embed
ocsp_response no-cert-hash signer ca ocsp-signer good - - embed
ocsp_response wrong-cert-hash signer ca ocsp-signer good signer-ku-extra - embed
ocsp_response issuer-signed signer ca ca good signer - -
