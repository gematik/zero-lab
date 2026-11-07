"""What a branch changed in the Rust workspace, for `just check-changed`.

    python3 -I scripts/changed.py <base>

Prints shell assignments: CRATES, the workspace packages whose files changed since the
merge base with <base> (committed, staged, unstaged or untracked) and every package that
depends on one of them, directly or not; and flags for the checks that depend on few
inputs: MANIFESTS (a manifest, the lock file or the supply-chain policy), SCRIPTS (these
scripts).
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Inputs of deny, vet, unsafe-free, core-deps, machete and the jwz backend check.
MANIFEST_FILES = ("Cargo.toml", "Cargo.lock", "deny.toml", "docs/unsafe-exceptions.md")
MANIFEST_DIRS = ("supply-chain/",)


def run(*args, cwd=ROOT):
    return subprocess.run(args, check=True, capture_output=True, text=True, cwd=cwd).stdout


def changed_paths(base):
    """Paths under rust/, relative to it, that differ from the merge base, untracked included."""
    merge_base = run("git", "merge-base", base, "HEAD").strip()
    # Both commands, run in rust/, list only paths below it and relative to it.
    names = run("git", "diff", "--name-only", "--relative", merge_base).splitlines()
    names += run("git", "ls-files", "--others", "--exclude-standard").splitlines()
    return sorted(set(names))


def packages():
    """The workspace members: name, directory relative to rust/, and in-workspace dependencies."""
    meta = json.loads(run("cargo", "metadata", "--format-version", "1", "--no-deps"))
    members = set(meta["workspace_members"])
    result = []
    for package in meta["packages"]:
        if package["id"] not in members:
            continue
        directory = Path(package["manifest_path"]).parent.relative_to(ROOT).as_posix()
        dependencies = {d["name"] for d in package["dependencies"] if d.get("path")}
        result.append({"name": package["name"], "dir": directory, "deps": dependencies})
    return result


def owner(path, packages):
    """The package whose directory holds `path` most closely, or None."""
    best = None
    for package in packages:
        prefix = package["dir"] + "/"
        if path.startswith(prefix) and (best is None or len(package["dir"]) > len(best["dir"])):
            best = package
    return best and best["name"]


def affected(paths, packages):
    """The packages that own a changed path, and all that depend on them."""
    hit = {name for name in (owner(p, packages) for p in paths) if name}
    names = {p["name"] for p in packages}
    while True:
        more = {p["name"] for p in packages if p["deps"] & hit and p["name"] not in hit}
        if not more:
            return sorted(hit & names)
        hit |= more


def touches_manifests(paths):
    return any(
        p.endswith("Cargo.toml") or p in MANIFEST_FILES or p.startswith(MANIFEST_DIRS) for p in paths
    )


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    paths = changed_paths(sys.argv[1])
    crates = affected(paths, packages())
    print(f'CRATES="{" ".join(crates)}"')
    print(f"MANIFESTS={'1' if touches_manifests(paths) else ''}")
    print(f"SCRIPTS={'1' if any(p.startswith('scripts/') for p in paths) else ''}")


if __name__ == "__main__":
    main()
