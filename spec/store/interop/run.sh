#!/usr/bin/env bash
# spec/store interoperability matrix: the Go and the Rust implementation share one
# profile's store on disk. For the SQLite and the files backend: records written by one
# language are read and queried by the other, both ways; then rounds of concurrent takes
# of one record from processes of both languages, of which exactly one may succeed
# (STORE-012). Writes matrix.md next to this script; exits 1 if a cell fails.
#
#   spec/store/interop/run.sh            # ROUNDS=20 TAKERS=8 by default
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
rounds=${ROUNDS:-20}
takers=${TAKERS:-8}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "==> building the drivers"
(cd "$root/go" && go build -o "$work/go-interop" ./sqlitestore/cmd/store-interop)
(cd "$root/rust" && cargo build -q -p ti-cli --bin ti --example store-interop)
ti="$root/rust/target/debug/ti"
declare -A driver=([go]="$work/go-interop" [rust]="$root/rust/target/debug/examples/store-interop")

rows=()
failed=0
cell() { # backend, direction, case, verdict
    rows+=("| $1 | $2 | $3 | $4 |")
    [ "$4" = pass ] || failed=1
    printf '%-7s %-12s %-44s %s\n' "$1" "$2" "$3" "$4"
}
check() { # backend, direction, case, want, got
    if [ "$4" = "$5" ]; then cell "$1" "$2" "$3" pass; else cell "$1" "$2" "$3" "FAIL: got '$5', want '$4'"; fi
}

for backend in sqlite files; do
    d="$work/$backend"
    export TI_STATE_DIR="$d/state" TI_CACHE_DIR="$d/cache" XDG_CONFIG_HOME="$d/config"
    export TI_STORE_KEK_PATH="$d/store.kek" TI_STORE_BACKEND="$backend"
    unset TI_PROFILE TI_STORE_TRACE
    "$ti" profile create >/dev/null

    for writer in go rust; do
        reader=rust; [ "$writer" = rust ] && reader=go
        w="${driver[$writer]}" r="${driver[$reader]}" dir="$writer → $reader"
        "$w" put oauth.access "token-$writer" "access-$writer" "issuer=https://idp-$writer" subject=s1
        "$w" put oauth.access "token2-$writer" "access2-$writer" "issuer=https://idp-$writer" subject=s2
        "$w" put popp "X110000001/$writer" "popp-$writer" kvnr=X110000001 "iccsn=8027-$writer"
        "$w" put tsl.state "tsl-$writer" "{\"id\":\"ID-$writer\",\"sequence_number\":7}"
        "$w" put well-known "https://idp-$writer" "discovery-$writer" "issuer=https://idp-$writer"
        check "$backend" "$dir" "sealed get (oauth.access)" "access-$writer" "$("$r" get oauth.access "token-$writer")"
        check "$backend" "$dir" "sealed query by tag (issuer)" 2 "$("$r" query oauth.access "issuer=https://idp-$writer")"
        check "$backend" "$dir" "sealed query by two tags (issuer, subject)" 1 "$("$r" query oauth.access "issuer=https://idp-$writer" subject=s2)"
        check "$backend" "$dir" "sealed get (popp)" "popp-$writer" "$("$r" get popp "X110000001/$writer")"
        check "$backend" "$dir" "sealed record without expiry (tsl.state)" "{\"id\":\"ID-$writer\",\"sequence_number\":7}" "$("$r" get tsl.state "tsl-$writer")"
        check "$backend" "$dir" "plain get (well-known, cache)" "discovery-$writer" "$("$r" get well-known "https://idp-$writer")"
        check "$backend" "$dir" "take by the other, then gone" "access2-$writer:3" \
            "$("$r" take oauth.access "token2-$writer"):$("$w" get oauth.access "token2-$writer" >/dev/null 2>&1; echo $?)"
    done

    # concurrent takes: takers of both languages wait for one start signal
    wins_go=0 wins_rust=0 bad_rounds=0
    for round in $(seq 1 "$rounds"); do
        id="race-$round"
        writer=go; [ $((round % 2)) = 0 ] && writer=rust
        "${driver[$writer]}" put popp "$id" "won-$round" kvnr=X1
        gate="$work/gate-$backend-$round"
        pids=()
        for lang in go rust; do
            for i in $(seq 1 "$takers"); do
                out="$work/take-$backend-$round-$lang-$i"
                # losing takes exit 3: the code is recorded, not fatal to the script
                (while [ ! -e "$gate" ]; do :; done
                 code=0
                 "${driver[$lang]}" take popp "$id" >"$out.payload" 2>/dev/null || code=$?
                 echo "$code" >"$out.code") &
                pids+=($!)
            done
        done
        sleep 0.3
        touch "$gate"
        wait "${pids[@]}"
        winners=0
        for f in "$work"/take-"$backend"-"$round"-*.code; do
            code=$(cat "$f")
            if [ "$code" = 0 ]; then
                winners=$((winners + 1))
                [ "$(cat "${f%.code}.payload")" = "won-$round" ] || bad_rounds=$((bad_rounds + 1))
                case "$f" in *-go-*) wins_go=$((wins_go + 1));; *) wins_rust=$((wins_rust + 1));; esac
            elif [ "$code" != 3 ]; then
                bad_rounds=$((bad_rounds + 1))
            fi
        done
        [ "$winners" = 1 ] || bad_rounds=$((bad_rounds + 1))
    done
    check "$backend" "both" \
        "take race: $rounds rounds × $((2 * takers)) takers, one winner each" 0 "$bad_rounds"
    cell "$backend" "both" "take race winners: go $wins_go, rust $wins_rust" "$([ $((wins_go + wins_rust)) = "$rounds" ] && echo pass || echo FAIL)"
done

{
    echo "# spec/store interoperability matrix"
    echo
    echo "Written by \`spec/store/interop/run.sh\`: the Go implementation (\`go/store\`, \`go/sqlitestore\`)"
    echo "and the Rust one (\`ti_store::store\` with \`ti\`'s backends) on one profile's files, through"
    echo "\`go/sqlitestore/cmd/store-interop\` and \`ti-cli/examples/store-interop.rs\`."
    echo
    echo "- Run: $(date -u +%Y-%m-%dT%H:%MZ) on $(uname -sm)"
    echo "- $(go version | cut -d' ' -f3-4), $(rustc --version | cut -d' ' -f1-2)"
    echo "- Take race: $rounds rounds of $takers Go and $takers Rust processes released together"
    echo
    echo "| Backend | Direction | Case | Result |"
    echo "|---|---|---|---|"
    printf '%s\n' "${rows[@]}"
} >"$here/matrix.md"
echo "==> $here/matrix.md"
exit "$failed"
