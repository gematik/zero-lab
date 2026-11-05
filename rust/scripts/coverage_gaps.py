"""Line coverage per crate, and the requirements whose code the tests never run, from an LCOV
report of `cargo llvm-cov`.

    python3 -I scripts/coverage_gaps.py <lcov.info> <crate>...

A requirement is cited in a comment in the form the traceability tables parse
(`// RFC 7516 §5.2: …`, `// P12-036: …`, `// gemSpec_PKI A_28419: …`). The code it governs
is taken to start at the first instrumented line a few lines below a plain `//` comment;
when the tests never run that line, the requirement is listed as a gap. This is a
heuristic: a covered first line does not prove that every branch of the rule is tested,
which is what the requirement-named tests are for.
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The kinds of reference docs/design/testing.md lists: our spec rules (P12-036,
# TSLSIG-066), gematik afos and use cases, RFC and other standards' sections.
# Only plain `//` comments: doc comments cite what an item or module is about, not the code
# that follows. Algorithm names (SHA-256, AES-128) share the shape of a rule ID.
REFERENCE = re.compile(
    r"^\s*//(?![/!])\s*.*?\b("
    r"(?!(?:SHA|AES|HMAC|PBES|PBKDF|ECDH|RSA|ES|PS|RS|HS)-)[A-Z][A-Z0-9]{1,9}-\d{3}"
    r"|A_\d{4,5}(?:-\d+)?"
    r"|TUC_[A-Z]+_\d+"
    r"|GS-A_\d+"
    r"|RFC ?\d{3,5}(?:\s*(?:§|[Ss]ection)\s*[\dA-Z][\w.]*\w)?"
    r"|NIST SP [\d-]+[A-Z]?(?:\s*§[\d.]+)?"
    r")"
)


# The code a citation governs starts within a few lines of it; further away, the next
# instrumented line belongs to something else.
GOVERNED_WITHIN = 4


def read_lcov(path):
    hits = defaultdict(dict)
    current = None
    for line in Path(path).read_text().splitlines():
        if line.startswith("SF:"):
            current = Path(line[3:]).resolve()
        elif line.startswith("DA:") and current is not None:
            number, count = line[3:].split(",")[:2]
            hits[current][int(number)] = int(count)
    return hits


def gaps(hits, crate):
    found = []
    for source in sorted((ROOT / crate / "src").rglob("*.rs")):
        lines = source.read_text().splitlines()
        counts = hits.get(source.resolve(), {})
        for index, text in enumerate(lines, start=1):
            match = REFERENCE.search(text)
            if not match:
                continue
            following = [n for n in sorted(counts) if index < n <= index + GOVERNED_WITHIN]
            if following and counts[following[0]] == 0:
                found.append((source.relative_to(ROOT), index, match.group(1)))
    return found


def line_coverage(hits, crate):
    src = (ROOT / crate / "src").resolve()
    counts = [c for path, lines in hits.items() if src in path.parents for c in lines.values()]
    return sum(1 for c in counts if c), len(counts)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    hits = read_lcov(sys.argv[1])
    for crate in sys.argv[2:]:
        found = gaps(hits, crate)
        run, instrumented = line_coverage(hits, crate)
        share = f"{run / instrumented:.1%}" if instrumented else "n/a"
        print(f"{crate}: {share} of {instrumented} lines run; {len(found)} cited requirement(s) whose code no test runs")
        for path, line, reference in found:
            print(f"  {path}:{line}  {reference}")


if __name__ == "__main__":
    main()
