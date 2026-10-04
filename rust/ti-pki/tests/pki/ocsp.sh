# OCSP responses assembled from DER pieces and signed with `openssl dgst`, sourced by the
# generators here: the `openssl ocsp` responder can neither back-date a response nor add
# the certHash extension gemSpec_PKI requires. Expects `$out` (certificates as
# `$out/<name>.pem`, responses written to `$out/ocsp/`), `$work` (keys as
# `$work/<name>.key`) and `$NOW` (producedAt and thisUpdate).

hex() { xxd -p "$@" | tr -d '\n'; }
tlv() { # tag-hex content-hex, DER definite length
    local n=$((${#2} / 2))
    if ((n < 128)); then printf '%s%02x%s' "$1" "$n" "$2"
    elif ((n < 256)); then printf '%s81%02x%s' "$1" "$n" "$2"
    else printf '%s82%04x%s' "$1" "$n" "$2"; fi
}
der() { openssl x509 -in "$out/$1.pem" -outform DER | hex; }
# The element number $3 at depth $2 of the DER file $1, as hex.
element() {
    openssl asn1parse -inform DER -in "$1" |
        sed -nE 's/^ *([0-9]+):d=([0-9]+) +hl= *([0-9]+) +l= *([0-9]+).*/\1 \2 \3 \4/p' |
        awk -v d="$2" -v i="$3" '$2 == d && n++ == i { print $1, $3 + $4; exit }' |
        { read -r off len; dd if="$1" bs=1 skip="$off" count="$len" 2>/dev/null | hex; }
}
gentime() { tlv 18 "$(printf '%s' "$1" | hex)"; }
SHA256_ALG=$(tlv 30 "$(tlv 06 608648016503040201)")
ECDSA_SHA256=$(tlv 30 "$(tlv 06 2a8648ce3d040302)")

# ocsp_response name cert issuer signer good|revoked|unknown certhash-of|- next-update|- embed|-
ocsp_response() {
    local name=$1 subject=$2 issuer=$3 signer=$4 status=$5 hash_of=$6 next=$7 embed=$8
    openssl x509 -in "$out/$subject.pem" -outform DER -out "$work/subject.der"
    openssl x509 -in "$out/$signer.pem" -outform DER -out "$work/signer.der"
    openssl ocsp -sha256 -issuer "$out/$issuer.pem" -cert "$out/$subject.pem" -no_nonce \
        -reqout "$work/req.der" >/dev/null
    local cert_id cert_status single extensions="" tbs
    cert_id=$(element "$work/req.der" 4 0)
    case $status in
        good) cert_status=8000 ;;
        unknown) cert_status=8200 ;;
        revoked) cert_status=$(tlv a1 "$(gentime 20251201000000Z)$(tlv a0 0a0101)") ;;
    esac
    if [ "$hash_of" != - ]; then
        local digest
        digest=$(openssl x509 -in "$out/$hash_of.pem" -outform DER | openssl dgst -sha256 -binary | hex)
        extensions=$(tlv a1 "$(tlv 30 "$(tlv 30 "$(tlv 06 2b2408030d)$(tlv 04 "$(tlv 30 "$SHA256_ALG$(tlv 04 "$digest")")")")")")
    fi
    single="$cert_id$cert_status$(gentime "$NOW")"
    [ "$next" != - ] && single+=$(tlv a0 "$(gentime "$next")")
    single=$(tlv 30 "$single$extensions")
    tbs=$(tlv 30 "$(tlv a1 "$(element "$work/signer.der" 2 5)")$(gentime "$NOW")$(tlv 30 "$single")")
    printf '%s' "$tbs" | xxd -r -p > "$work/tbs.der"
    openssl dgst -sha256 -sign "$work/$signer.key" -out "$work/sig.der" "$work/tbs.der"
    local basic="$tbs$ECDSA_SHA256$(tlv 03 "00$(hex "$work/sig.der")")"
    [ "$embed" != - ] && basic+=$(tlv a0 "$(tlv 30 "$(der "$signer")")")
    local bytes
    bytes=$(tlv 30 "$(tlv 06 2b0601050507300101)$(tlv 04 "$(tlv 30 "$basic")")")
    tlv 30 "0a0100$(tlv a0 "$bytes")" | xxd -r -p > "$out/ocsp/$name.der"
}

