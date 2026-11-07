"""Mutation scores per crate, recorded before a release and checked by `just release`.

    python3 -I scripts/mutation.py record <crate> <outcomes.json>   store the crate's score
    python3 -I scripts/mutation.py gate <crate>...                  check the crates about to be released

The score is (caught + timeout) / (caught + missed + timeout): a mutant that makes the tests
fail or hang has been noticed, one that passes them has not, and unviable mutants (those
that do not build) do not count. A score holds only for the tree it was measured on: the gate refuses
a crate whose directory changed since the recorded commit, so a release cannot carry a
score of older code.
"""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

SCORES = Path(__file__).resolve().parent.parent / "mutation-scores.toml"


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


def load():
    with SCORES.open("rb") as f:
        return tomllib.load(f)


def crate_version(crate):
    with (SCORES.parent / crate / "Cargo.toml").open("rb") as f:
        return tomllib.load(f)["package"]["version"]


def write(doc):
    # The file is written whole, in a fixed order, so a record changes only its own block.
    out = [SCORES.read_text().split("[thresholds]")[0].rstrip() + "\n", "\n[thresholds]\n"]
    for crate, threshold in sorted(doc["thresholds"].items()):
        out.append(f'"{crate}" = {threshold}\n')
    for crate, s in sorted(doc.get("scores", {}).items()):
        out.append(f'\n[scores."{crate}"]\n')
        out.append(f'version = "{s["version"]}"\n')
        out.append(f'commit = "{s["commit"]}"\n')
        out.append(f'date = "{s["date"]}"\n')
        for key in ("caught", "missed", "timeout", "unviable"):
            out.append(f"{key} = {s[key]}\n")
        out.append(f'score = {s["score"]}\n')
    SCORES.write_text("".join(out))


def score(caught, missed, timeout):
    """(caught + timeout) / (caught + missed + timeout), or None without viable mutants."""
    counted = caught + missed + timeout
    if counted == 0:
        return None
    return round((caught + timeout) / counted, 4)


def record(crate, outcomes_path):
    outcomes = json.loads(Path(outcomes_path).read_text())
    value = score(outcomes["caught"], outcomes["missed"], outcomes["timeout"])
    if value is None:
        sys.exit(f"mutation: {crate} has no viable mutants")
    if git("status", "--porcelain", "--", crate):
        sys.exit(f"mutation: {crate} has uncommitted changes; a score must belong to a commit")
    doc = load()
    doc.setdefault("scores", {})[crate] = {
        "version": crate_version(crate),
        "commit": git("rev-parse", "HEAD"),
        "date": outcomes["end_time"][:10],
        "caught": outcomes["caught"],
        "missed": outcomes["missed"],
        "timeout": outcomes["timeout"],
        "unviable": outcomes["unviable"],
        "score": value,
    }
    write(doc)
    s = doc["scores"][crate]
    killed = s["caught"] + s["timeout"]
    print(f"{crate}: {value:.1%} ({killed} of {killed + s['missed']} killed, {s['unviable']} unviable)")


def gate(crates):
    doc = load()
    thresholds, scores = doc["thresholds"], doc.get("scores", {})
    failed = []
    for crate in crates:
        s = scores.get(crate)
        if s is None:
            failed.append(f"{crate}: no mutation score; run `just mutants-record {crate}`")
            continue
        changed = git("diff", "--name-only", s["commit"], "HEAD", "--", crate)
        if changed:
            failed.append(f"{crate}: changed since its score ({s['commit'][:8]}); run `just mutants-record {crate}`")
            continue
        # The counts decide, not the stored score, so a score written by an older formula
        # cannot pass or fail the gate.
        value = score(s["caught"], s["missed"], s["timeout"])
        threshold = thresholds.get(crate)
        if threshold is not None and (value is None or value < threshold):
            failed.append(f"{crate}: mutation score {value or 0:.1%} is below its threshold {threshold:.0%}")
            continue
        print(f"{crate}: mutation score {value:.1%}" + (f" (threshold {threshold:.0%})" if threshold else ""))
    if failed:
        sys.exit("mutation gate:\n  " + "\n  ".join(failed))


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "record":
        record(sys.argv[2], sys.argv[3])
    elif len(sys.argv) >= 3 and sys.argv[1] == "gate":
        gate(sys.argv[2:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
