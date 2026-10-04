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
#   rca1 ── sub-ca-pathlen0 (pathLen 0) ── sub-sub-ca ── ee-deep: a path-length violation
#   ee-arzt ── ee-under-ee: an end entity used as an issuer
#   sub-ca-hba ── ee-critical-unknown (a critical extension nobody knows),
#                 ee-critical-eku (extendedKeyUsage critical, as some TI certificates have)
#   rca1 ── sub-ca-name-constraints (critical nameConstraints) ── ee-under-name-constraints
#   sub-ca-hba ── ocsp-signer-hba (id-kp-OCSPSigning), ocsp-signer-no-eku,
#                 ocsp-signer-expired; sub-ca-komp ── ocsp-signer-komp (a foreign CA's)
#
# ocsp/ holds OCSP responses produced at NOW, assembled by ocsp.sh from DER pieces and
# signed with `openssl dgst` (the `openssl ocsp` responder cannot back-date or add the
# certHash extension gemSpec_PKI requires):
#   good, revoked, unknown        ee-arzt / ee-revoked by ocsp-signer-hba, with certHash
#   no-cert-hash, wrong-cert-hash certHash absent / over ee-expired
#   unknown-no-cert-hash          unknown for ee-arzt without certHash (A_30046 (2))
#   egk-no-cert-hash              good for types/type-ch-aut without certHash, by
#                                 ocsp-signer-komp (stapled eGK answers, A_30046 (7))
#   issuer-signed                 sub-ca-hba at its root, signed by rca1, no certificates
#   no-eku, foreign-responder, expired-responder
#                                 ee-arzt, signed by the responder of that name
#
# types/ holds end entities under sub-ca-komp for certificate-type detection and the
# gemSpec_PKI type baselines, transcribed here from the profile tables independently
# of cert_type.rs:
#   type-<type>.pem      the type's baseline: key usage, extended key usage, the
#                        umbrella and type policies, the first role of its role table
#   role-<type>-<role>   the baseline with another role from the spec table
#   fallback-<case>.pem  admission and key usage only, no policies
#   none-<case>.pem      nothing a type can be read from
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

[ocsp_signer]
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ocsp_no_eku]
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ee_critical_unknown]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
1.3.6.1.4.1.99999.1 = critical, ASN1:NULL

[ee_critical_eku]
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ca_name_constraints]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:ti-dienste.de
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ca_pathlen0]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
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

key sub-ca-pathlen0 bp256
cert sub-ca-pathlen0 sub-ca-pathlen0 "GEM.SubCA-PathLen0 TEST-ONLY" rca1 "$NOW" "$FIVE_YEARS" ca_pathlen0
key sub-sub-ca bp256;    cert sub-sub-ca sub-sub-ca "GEM.SubSubCA TEST-ONLY" sub-ca-pathlen0 "$NOW" "$FIVE_YEARS" ca
key ee-deep bp256;       cert ee-deep ee-deep "EE-Deep TEST-ONLY" sub-sub-ca "$NOW" "$FIVE_YEARS" ee
key ee-under-ee bp256;   cert ee-under-ee ee-under-ee "EE-Under-EE TEST-ONLY" ee-arzt "$NOW" "$FIVE_YEARS" ee
key ee-critical-unknown bp256
cert ee-critical-unknown ee-critical-unknown "EE-Critical-Unknown TEST-ONLY" sub-ca-hba "$NOW" "$FIVE_YEARS" ee_critical_unknown
key ee-critical-eku bp256
cert ee-critical-eku ee-critical-eku "EE-Critical-EKU TEST-ONLY" sub-ca-hba "$NOW" "$FIVE_YEARS" ee_critical_eku
key sub-ca-name-constraints bp256
cert sub-ca-name-constraints sub-ca-name-constraints "GEM.SubCA-NameConstraints TEST-ONLY" rca1 "$NOW" "$FIVE_YEARS" ca_name_constraints
key ee-under-name-constraints bp256
cert ee-under-name-constraints ee-under-name-constraints "EE-Under-NameConstraints TEST-ONLY" sub-ca-name-constraints "$NOW" "$FIVE_YEARS" ee

# --- OCSP -------------------------------------------------------------------------------

key ocsp-signer-hba p256
cert ocsp-signer-hba ocsp-signer-hba "SubCA-HBA OCSP-Signer TEST-ONLY" sub-ca-hba "$NOW" "$FIVE_YEARS" ocsp_signer
key ocsp-signer-no-eku p256
cert ocsp-signer-no-eku ocsp-signer-no-eku "SubCA-HBA No-EKU-Signer TEST-ONLY" sub-ca-hba "$NOW" "$FIVE_YEARS" ocsp_no_eku
key ocsp-signer-expired p256
cert ocsp-signer-expired ocsp-signer-expired "SubCA-HBA Expired-Signer TEST-ONLY" sub-ca-hba "$PAST_FROM" "$PAST_TO" ocsp_signer
key ocsp-signer-komp p256
cert ocsp-signer-komp ocsp-signer-komp "SubCA-Komp OCSP-Signer TEST-ONLY" sub-ca-komp "$NOW" "$FIVE_YEARS" ocsp_signer

. "$(dirname "$0")/ocsp.sh"

mkdir -p "$out/ocsp"
ocsp_response good ee-arzt sub-ca-hba ocsp-signer-hba good ee-arzt 20260102000000Z embed
ocsp_response revoked ee-revoked sub-ca-hba ocsp-signer-hba revoked ee-revoked 20260102000000Z embed
ocsp_response unknown ee-arzt sub-ca-hba ocsp-signer-hba unknown ee-arzt - embed
ocsp_response no-cert-hash ee-arzt sub-ca-hba ocsp-signer-hba good - - embed
ocsp_response wrong-cert-hash ee-arzt sub-ca-hba ocsp-signer-hba good ee-expired - embed
ocsp_response issuer-signed sub-ca-hba rca1 rca1 good sub-ca-hba - -
ocsp_response no-eku ee-arzt sub-ca-hba ocsp-signer-no-eku good ee-arzt - embed
ocsp_response foreign-responder ee-arzt sub-ca-hba ocsp-signer-komp good ee-arzt - embed
ocsp_response expired-responder ee-arzt sub-ca-hba ocsp-signer-expired good ee-arzt - embed
ocsp_response unknown-no-cert-hash ee-arzt sub-ca-hba ocsp-signer-hba unknown - - embed

# --- Certificate types ------------------------------------------------------------------

mkdir -p "$out/types"
ARC=1.2.276.0.76.4
GEM_OR_CP=$ARC.163
HBA_CP=$ARC.145

# typed name "key usage" "ext key usage" "policies" "admission role OID"
typed() {
    local name=$1 ku=$2 eku=$3 policies=$4 role=$5 ext="$work/types-$1.cnf"
    {
        echo "[ext]"
        [ -n "$ku" ] && echo "keyUsage = critical, $ku"
        [ -n "$eku" ] && echo "extendedKeyUsage = $eku"
        [ -n "$policies" ] && echo "certificatePolicies = $policies"
        echo "subjectKeyIdentifier = hash"
        echo "authorityKeyIdentifier = keyid:always"
        if [ -n "$role" ]; then
            echo "1.3.36.8.3.3 = ASN1:SEQUENCE:admission_syntax"
            echo "[admission_syntax]"
            echo "contents = SEQUENCE:contents_of_admissions"
            echo "[contents_of_admissions]"
            echo "admissions = SEQUENCE:admissions"
            echo "[admissions]"
            echo "profession_infos = SEQUENCE:profession_infos"
            echo "[profession_infos]"
            echo "info = SEQUENCE:profession_info"
            echo "[profession_info]"
            echo "items = SEQUENCE:profession_items"
            echo "oids = SEQUENCE:profession_oids"
            echo "[profession_items]"
            echo "item = UTF8String:TEST-ROLE"
            echo "[profession_oids]"
            echo "oid = OID:$role"
        fi
    } > "$ext"
    key "types-$name" p256
    openssl req -new -key "$work/types-$name.key" -subj "/C=DE/CN=$name TEST-ONLY" -out "$work/types-$name.csr"
    serial=$((serial + 1))
    openssl x509 -req -in "$work/types-$name.csr" -CA "$out/sub-ca-komp.pem" -CAkey "$work/sub-ca-komp.key" \
        -set_serial "$serial" -not_before "$NOW" -not_after "$FIVE_YEARS" \
        -extfile "$ext" -extensions ext -out "$out/types/$name.pem" 2>/dev/null
}

# Tab_PKI_405 baselines (gemSpec_PKI Tab_PKI_232-300, ECDSA branch).
EGK=$ARC.49; ARZT=$ARC.30; ARZTPRAXIS=$ARC.50; HSK=$ARC.302
cc=nonRepudiation; ds=digitalSignature; ka=keyAgreement
typed type-ch-qes   $cc "" "$GEM_OR_CP, $ARC.66" $EGK
typed type-ch-sig   $cc "" "$GEM_OR_CP, $ARC.67" $EGK
typed type-ch-enc   $ka "" "$GEM_OR_CP, $ARC.68" $EGK
typed type-ch-encv  $ka "" "$GEM_OR_CP, $ARC.69" $EGK
typed type-ch-aut   $ds "" "$GEM_OR_CP, $ARC.70" $EGK
typed type-ch-autn  $ds clientAuth "$GEM_OR_CP, $ARC.71" $EGK
typed type-hp-qes   $cc "" "$HBA_CP, $ARC.72" $ARZT
typed type-hp-aut   "$ds, $ka" "clientAuth, emailProtection" "$HBA_CP, $ARC.75" $ARZT
typed type-hp-enc   $ka "" "$HBA_CP, $ARC.74" $ARZT
typed type-hci-aut  $ds clientAuth "$GEM_OR_CP, $ARC.77" $ARZTPRAXIS
typed type-hci-enc  $ka "" "$GEM_OR_CP, $ARC.76" $ARZTPRAXIS
typed type-hci-osig $cc "" "$GEM_OR_CP, $ARC.78" $ARZTPRAXIS
typed type-fd-aut   $ds "" "$GEM_OR_CP, $ARC.155" ""
typed type-fd-sig   $ds "" "$GEM_OR_CP, $ARC.203" ""
typed type-fd-enc   $ka "" "$GEM_OR_CP, $ARC.202" ""
typed type-fd-osig  $cc "" "$GEM_OR_CP, $ARC.283" ""
typed type-fd-tls-s $ds serverAuth "$GEM_OR_CP, $ARC.169" ""
typed type-fd-tls-c $ds clientAuth "$GEM_OR_CP, $ARC.168" ""
typed type-zd-tls-s $ds serverAuth "$GEM_OR_CP, $ARC.157" ""
typed type-zd-sig   $cc "" "$GEM_OR_CP, $ARC.287" ""
typed type-hsk-sig  $cc "clientAuth, serverAuth" "$GEM_OR_CP, $ARC.300" $HSK
typed type-hsk-enc  $ka "clientAuth, serverAuth" "$GEM_OR_CP, $ARC.301" $HSK
typed type-gem-ver  "" "" "$GEM_OR_CP, $ARC.321" ""

# Roles beyond the first of their table: every Tab_PKI_402/403 entry counts.
typed role-hci-aut-kostentraeger $ds clientAuth "$GEM_OR_CP, $ARC.77" $ARC.59
typed role-hci-aut-kim-anbieter  $ds clientAuth "$GEM_OR_CP, $ARC.77" $ARC.286
typed role-hp-qes-hebamme        $cc "" "$HBA_CP, $ARC.72" $ARC.235
typed role-hp-qes-notfallsanitaeter $cc "" "$HBA_CP, $ARC.72" $ARC.178
# Technical roles that select a profile among several accepting the same type.
typed role-fd-aut-zeta-guard $ds "" "$GEM_OR_CP, $ARC.155" $ARC.328
typed role-fd-aut-epa-vau    $ds "" "$GEM_OR_CP, $ARC.155" $ARC.209
typed role-fd-sig-idpd       $ds "" "$GEM_OR_CP, $ARC.203" $ARC.260

# Admission fallback: no policies, the type follows from role family and key usage.
typed fallback-hci-aut-krankenhaus  $ds "" "" $ARC.53
typed fallback-hci-enc-apotheke     keyEncipherment "" "" $ARC.54
typed fallback-hci-osig-praxis      $cc "" "" $ARZTPRAXIS
typed fallback-hp-qes-arzt          $cc "" "" $ARZT
typed fallback-hp-aut-apotheker     $ds "" "" $ARC.32
typed fallback-hp-enc-zahnarzt      keyEncipherment "" "" $ARC.31
typed fallback-ch-qes               $cc "" "" $EGK
typed fallback-ch-aut-undecidable   $ds "" "" $EGK
typed fallback-ch-enc-undecidable   keyEncipherment "" "" $EGK

typed none-umbrella-only $ds "" "$GEM_OR_CP" ""
typed none-unrelated-admission $ds "" "" 1.2.3.4.5

# An eGK certificate's answer needs the type above.
ocsp_response egk-no-cert-hash types/type-ch-aut sub-ca-komp ocsp-signer-komp good - 20260102000000Z embed

echo "wrote $(find "$out" -name '*.pem' | wc -l | tr -d ' ') certificates and $(find "$out/ocsp" -name '*.der' | wc -l | tr -d ' ') OCSP responses to $out"
