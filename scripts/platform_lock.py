#!/usr/bin/env python3
"""Write or check platform.lock.json from a local checkout of the platform.

    python scripts/platform_lock.py <platform checkout> [--commit <sha>] [--baseline baseline/N] [--write]

The lock records what this repository needs from the pinned platform commit: the
requirement and test IDs that exist there and the SHA-256 of S6, the paper the
error registry names. scripts/validate.py checks this repository against the lock,
so it runs offline. CI fetches the public platform at the locked baseline tag and
runs this script to prove the lock equals the platform's registry at that commit.

The baseline tag must exist in the checkout and point at the commit. Without
--commit the lock's own commit and baseline are checked. Without --write the
script compares the lock with the checkout and exits 1 on any difference.
Standard library only.
"""
import argparse, json, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = ROOT / "platform.lock.json"
PLATFORM = "true-line/agent-bot-platform"


def show(checkout, commit, path):
    return subprocess.run(["git", "show", f"{commit}:{path}"], cwd=checkout, capture_output=True,
                          text=True, check=True).stdout


def ids(text):
    return re.findall(r"^- id: (\S+)$", text, re.M)


def source_sha(text, sid):
    block = re.search(rf"^- id: {re.escape(sid)}$(.*?)(?=^- id: |\Z)", text, re.M | re.S)
    sha = block and re.search(r"^  sha256: ([0-9a-f]{64})$", block.group(1), re.M)
    if not sha:
        sys.exit(f"no top-level sha256 for {sid} in registry/sources.yaml")
    return sha.group(1)


def rev(checkout, ref):
    r = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd=checkout,
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def build(checkout, commit, baseline):
    sha = rev(checkout, commit)
    if sha is None:
        sys.exit(f"{commit} is not a commit in {checkout}")
    if baseline is None:
        tags = subprocess.run(["git", "tag", "--points-at", sha, "baseline/*"], cwd=checkout,
                              capture_output=True, text=True, check=True).stdout.split()
        if len(tags) != 1:
            sys.exit(f"pass --baseline: {sha[:7]} carries {len(tags)} baseline tags")
        baseline = tags[0]
    if rev(checkout, f"refs/tags/{baseline}") != sha:
        sys.exit(f"tag {baseline} is missing from {checkout} or does not point at {sha[:7]}")
    commit = sha
    return {
        "platform": PLATFORM,
        "baseline": baseline,
        "commit": commit,
        "requirements": ids(show(checkout, commit, "registry/requirements.yaml")),
        "tests": ids(show(checkout, commit, "registry/tests.yaml")),
        "sources": {"S6": source_sha(show(checkout, commit, "registry/sources.yaml"), "S6")},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("checkout", type=pathlib.Path)
    ap.add_argument("--commit", help="default: the lock's commit and baseline")
    ap.add_argument("--baseline")
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()
    if a.commit is None:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        a.commit, a.baseline = lock["commit"], a.baseline or lock["baseline"]
    want = build(a.checkout, a.commit, a.baseline)
    text = json.dumps(want, indent=2) + "\n"
    if a.write:
        LOCK.write_text(text, encoding="utf-8")
        print(f"wrote {LOCK.name} for {want['baseline']} ({want['commit'][:7]})")
        return 0
    if LOCK.read_text(encoding="utf-8") != text:
        print(f"{LOCK.name} differs from {want['commit'][:7]}; rerun with --write", file=sys.stderr)
        return 1
    print(f"{LOCK.name} matches {want['baseline']} ({want['commit'][:7]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
