"""Mutation scores per crate, recorded before a release and checked by `just release`.

    python3 -I scripts/mutation.py record <crate> <outcomes.json>   store the crate's score
    python3 -I scripts/mutation.py gate <crate>...                  check the crates about to be released

The score is (caught + timeout) / (caught + missed + timeout): a mutant that makes the tests
fail or hang has been noticed, one that passes them has not, and unviable mutants (those
that do not build) do not count. A score holds only for the tree it was measured on: the gate refuses
a crate whose code changed since the recorded commit, so a release cannot carry a score of
older code. Code is everything under the crate that a test compiles or runs; the README, the
licence, documents no `include_str!` compiles into the crate, verification stamps and fuzz
targets are not, and neither is the version line of its `[package]`.

    python3 -I scripts/mutation.py affecting <crate> <rev>          the code changed since <rev>
"""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

SCORES = Path(__file__).resolve().parent.parent / "mutation-scores.toml"


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


# Under a crate, what no test compiles or runs: a change there cannot change its score.
INERT_FILES = ("README.md", "LICENSE")
INERT_DIRS = ("docs/", "verification/", "fuzz/")


def without_package_version(text):
    """A Cargo.toml without the version line of its [package] table, which a release bumps."""
    out, section = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped
        elif section == "[package]" and stripped.startswith("version") and stripped.split("=")[0].strip() == "version":
            continue
        out.append(line)
    return "\n".join(out)


def compiled_documents(crate):
    """The crate's documents its sources compile in with include_str!, relative to the crate."""
    root = (SCORES.parent / crate).resolve()
    found = set()
    for source in root.glob("src/**/*.rs"):
        for part in source.read_text().split("include_str!(\"")[1:]:
            target = (source.parent / part.split("\"", 1)[0]).resolve()
            if root in target.parents:
                found.add(target.relative_to(root).as_posix())
    return found


def is_code(crate, path, rev):
    """Whether `path` (relative to the crate) can change the crate's score since `rev`."""
    if path == "Cargo.toml":
        # `./` resolves the path from the current directory, rust/, not the repository root.
        def at(commit):
            return git("show", f"{commit}:./{crate}/Cargo.toml")
        try:
            return without_package_version(at(rev)) != without_package_version(at("HEAD"))
        except subprocess.CalledProcessError:
            return True
    return counts(path, compiled_documents(crate))


def counts(path, compiled):
    """Whether a path other than Cargo.toml can change a score, given the compiled documents."""
    if path in INERT_FILES or path.startswith(INERT_DIRS):
        return path in compiled
    return True


def affecting(crate, rev):
    """The crate's files changed since `rev` that can change its score, relative to the crate."""
    changed = git("diff", "--name-only", "--relative", rev, "HEAD", "--", crate)
    prefix = crate + "/"
    paths = [line.removeprefix(prefix) for line in changed.splitlines() if line]
    return [path for path in paths if is_code(crate, path, rev)]


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
        changed = affecting(crate, s["commit"])
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
    elif len(sys.argv) == 4 and sys.argv[1] == "affecting":
        print("\n".join(affecting(sys.argv[2], sys.argv[3])))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
