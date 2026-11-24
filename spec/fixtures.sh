# What every fixture generator of the repository shares (rust/ti-pki/tests/pki and the rest).
# They follow the test data rule of docs/design/testing.md: every output is reproducible from
# committed inputs, and a run writes only what is missing, so adding a certificate changes that
# certificate and nothing else.
#
# - Keys are TEST-ONLY and committed in `$keys`; a key is made only when its file is missing,
#   and never again, also not under FORCE.
# - A certificate or response is written only when its file is missing; FORCE=1 writes all of
#   them again from the same keys.
# - A serial number is derived from the output's name, not counted, so the order of the lines
#   in a generator does not decide it and an added certificate takes no other's number.
# - ECDSA signatures are deterministic (RFC 6979, OpenSSL's nonce-type 1): a rebuild gives the
#   same bytes. What a scheme randomises (RSA-PSS salts, PKCS#12 salts and IVs) differs on every
#   FORCE rebuild; each generator names those outputs.
#
# Source it as `. path/to/spec/fixtures.sh`. Expects `$keys` (the key directory) and `$work` (a
# temporary directory).

FORCE=${FORCE:-}

# Whether $1 is to be written: it is missing, or FORCE asks for everything.
wanted() { [ -n "$FORCE" ] || [ ! -e "$1" ]; }

# serial_of name: a positive 64-bit serial number from the name.
serial_of() { printf '0x1%s' "$(printf '%s' "$1" | openssl dgst -sha256 -r | cut -c1-15)"; }

# key name kind: kind is a curve (brainpoolP256r1, P-256, P-521, or bp256, p256, p521) or rsaBITS.
key() {
    local file="$keys/$1.key" curve
    [ -e "$file" ] && return
    mkdir -p "$keys"
    case "$2" in
        bp256) curve=brainpoolP256r1 ;;
        p256) curve=P-256 ;;
        p521) curve=P-521 ;;
        rsa*)
            openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${2#rsa}" -out "$file" 2>/dev/null
            return ;;
        *) curve=$2 ;;
    esac
    openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$curve" \
        -pkeyopt ec_param_enc:named_curve -out "$file" 2>/dev/null
}

# sign_options key-file: the options that make a signature with this key deterministic.
sign_options() {
    if openssl pkey -in "$1" -noout -text 2>/dev/null | grep -q '^ASN1 OID'; then
        printf '%s\n' -sigopt nonce-type:1
    fi
}
