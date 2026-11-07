#!/usr/bin/env python3
"""Validate soul-contracts. Exit 1 on any failure.

Checks, in order:
  schemas         every schema is valid draft 2020-12, its $id matches its path,
                  and it has at least one positive and one negative fixture
  fixtures        each fixture meets its stated expectation (schema / parse /
                  semantic rule), pins its canonical digest or its base
                  positive, and names only registered error codes
  canonicalization  JCS vectors reproduce byte for byte
  registry        structure, contiguous numbering, add-only ratchet against
                  the merge base with $BASE_REF (default origin/main)
  platform        fetched fresh at main (fails, never skips, if unreachable):
                  R1-R12 and T01-T30 are defined; the error registry names
                  S6's hash; AGENTS.md has the read-at-main block; every
                  platform link uses main and resolves; contract artifacts
                  cite only requirement and test IDs defined there
  vendor tokens   R10: no vendor name in any contract artifact
"""
import hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile
from datetime import datetime

from jsonschema import Draft202012Validator, FormatChecker

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from jcs import canonicalize, parse_strict  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE_ID = "https://true-line.ai/soul-contracts/"
fails = 0


def report(ok, label, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + label + (f"  {detail}" if detail and not ok else ""))
    fails += not ok
    return ok


def digest(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def load(p):
    return json.loads(p.read_text(encoding="utf-8"))


# --- registry (loaded first: fixtures cite it) ------------------------------
REG_PATH = "errors/registry.json"
registry = load(ROOT / REG_PATH)
codes = {c["code"] for c in registry["codes"]}

# --- schemas -----------------------------------------------------------------
schemas = {}
for p in sorted((ROOT / "schemas").rglob("*.schema.json")):
    rel = p.relative_to(ROOT / "schemas").as_posix()
    s = load(p)
    try:
        Draft202012Validator.check_schema(s)
        ok = s.get("$schema") == "https://json-schema.org/draft/2020-12/schema" and s.get("$id") == BASE_ID + rel
        report(ok, f"schema {rel}", f"$id must be {BASE_ID + rel}")
    except Exception as e:  # noqa: BLE001
        report(False, f"schema {rel}", str(e).splitlines()[0])
    schemas[rel] = Draft202012Validator(s, format_checker=FormatChecker())

# --- semantic rules ----------------------------------------------------------
def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def rule_expiry_before_now(inp, ctx):
    stamp = inp.get("expiry") or inp.get("expires_at")
    return stamp is not None and "now" in ctx and ts(stamp) < ts(ctx["now"])


def rule_capability_not_negotiated(inp, ctx):
    neg = ctx.get("negotiated_capabilities")
    return isinstance(neg, list) and any(c not in neg for c in inp.get("required_capabilities", []))


RULES = {"expiry-before-now": rule_expiry_before_now, "capability-not-negotiated": rule_capability_not_negotiated}

# --- fixtures ----------------------------------------------------------------
covered = {rel: {"positive": 0, "negative": 0} for rel in schemas}
for fx in sorted((ROOT / "fixtures").glob("*/*.json")):
    rel = fx.relative_to(ROOT).as_posix()
    if fx.parent.name == "canonicalization":
        continue
    d = load(fx)
    kind = fx.parent.name
    sch = d.get("schema")
    if sch not in schemas:
        report(False, rel, f"unknown schema {sch}")
        continue
    stem = pathlib.PurePosixPath(sch).name.removesuffix(".schema.json")
    if not fx.name.startswith(stem + "."):
        report(False, rel, f"file name must start with {stem}.")
    covered[sch][kind] += 1
    exp = d["expect"]
    problems = []
    if exp.get("error") and exp["error"] not in codes:
        problems.append(f"error {exp['error']} is not in {REG_PATH}")
    if kind == "negative":
        base = d.get("base", {})
        bp = ROOT / "fixtures" / base.get("fixture", "-")
        if not bp.is_file():
            problems.append("base.fixture missing")
        elif digest(bp.read_bytes()) != base.get("sha256"):
            problems.append(f"base.sha256 stale: {base.get('fixture')} is now {digest(bp.read_bytes())}")
    if "input_raw" in d:
        if exp.get("parse") != "invalid":
            problems.append("input_raw requires expect.parse = invalid")
        try:
            json.loads(d["input_raw"])
        except ValueError:
            problems.append("input_raw must be lenient-parseable JSON (the refusal is strictness)")
        try:
            parse_strict(d["input_raw"])
            problems.append("strict parse accepted input_raw")
        except ValueError:
            pass
        report(not problems, f"{rel} expect=parse-invalid", "; ".join(problems))
        continue
    errs = list(schemas[sch].iter_errors(d["input"]))
    got = "invalid" if errs else "valid"
    if exp["schema"] != got:
        problems.append(f"schema expected {exp['schema']}, got {got}" + (f": {errs[0].message}" if errs else ""))
    if kind == "positive":
        if exp["schema"] != "valid" or exp.get("error"):
            problems.append("positive fixtures are valid and name no error")
        if d.get("canonical_sha256") != digest(canonicalize(d["input"])):
            problems.append(f"canonical_sha256 must be {digest(canonicalize(d['input']))}")
    elif exp["schema"] == "valid":
        if not exp.get("error"):
            problems.append("a schema-valid negative must name the error HQ or the broker returns")
        if "rule" in exp:
            fn = RULES.get(exp["rule"])
            if fn is None:
                problems.append(f"unknown rule {exp['rule']}")
            elif not fn(d["input"], d.get("context", {})):
                problems.append(f"rule {exp['rule']} does not refuse this input under its context")
    report(not problems, f"{rel} expect={exp.get('schema')}" + (f" error={exp['error']}" if exp.get("error") else ""), "; ".join(problems))

for sch, c in covered.items():
    report(c["positive"] >= 1 and c["negative"] >= 1, f"coverage {sch}", f"{c['positive']} positive, {c['negative']} negative")

# --- canonicalization --------------------------------------------------------
for p in sorted((ROOT / "fixtures/canonicalization").glob("*.json")):
    for v in load(p)["vectors"]:
        b = canonicalize(v["input"])
        report(b == v["canonical"].encode("utf-8") and digest(b) == v["canonical_sha256"], f"jcs {v['id']}", b.decode("utf-8"))
canon = ROOT / "fixtures/positive/hello.first-start.canonical.txt"
src = load(ROOT / "fixtures/positive/hello.first-start.json")["input"]
report(canon.read_bytes() == canonicalize(src), "jcs hello.first-start.canonical.txt matches its fixture")
report((ROOT / "fixtures/positive/hello.first-start.digest.txt").read_text().strip() == digest(canon.read_bytes()), "jcs hello.first-start digest")

# --- registry ----------------------------------------------------------------
probs = []
if registry.get("schema_version") != 1 or not re.fullmatch(r"[0-9a-f]{64}", registry.get("source", {}).get("sha256", "")):
    probs.append("schema_version 1 and a source.sha256 pin are required")
seen = set()
for i, c in enumerate(registry["codes"], 1):
    if c.get("n") != i: probs.append(f"{c.get('code')}: n must be {i}")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", c.get("code", "")): probs.append(f"{c.get('code')}: snake_case")
    if c["code"] in seen: probs.append(f"{c['code']}: duplicate")
    seen.add(c["code"])
    if not isinstance(c.get("retryable"), bool): probs.append(f"{c['code']}: retryable must be boolean")
    if not c.get("raised_by") or any(r not in registry["raised_by_values"] for r in c["raised_by"]): probs.append(f"{c['code']}: raised_by")
    if not (1 <= len(c.get("description", "")) <= 200): probs.append(f"{c['code']}: description 1-200 chars")
    if not re.fullmatch(r"\d+\.\d+", c.get("registered", "")): probs.append(f"{c['code']}: registered names the draft")
report(not probs, "registry structure", "; ".join(probs))

base_ref = os.environ.get("BASE_REF", "origin/main")
try:
    mb = subprocess.run(["git", "merge-base", base_ref, "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    old = json.loads(subprocess.run(["git", "show", f"{mb}:{REG_PATH}"], cwd=ROOT, capture_output=True, text=True, check=True).stdout)
except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
    print(f"skip registry ratchet (no {base_ref} or no registry at the merge base)")
else:
    now = {c["code"]: c for c in registry["codes"]}
    probs = [f"{c['code']} removed" for c in old["codes"] if c["code"] not in now]
    probs += [f"{c['code']} renumbered" for c in old["codes"] if "n" in c and c["code"] in now and now[c["code"]]["n"] != c["n"]]
    report(not probs, f"registry add-only against {base_ref} ({mb[:7]})", "; ".join(probs))

# --- error-response schema follows the registry --------------------------
er = load(ROOT / "schemas/common/v1/error-response.schema.json")
report(er["properties"]["error"]["enum"] == [c["code"] for c in registry["codes"]],
       "error-response code enum equals errors/registry.json, in order")
retryable = {c["code"] for c in registry["codes"] if c["retryable"]}
for fx in sorted((ROOT / "fixtures/positive").glob("error-response.*.json")):
    inp = load(fx)["input"]
    report("retry_after_seconds" not in inp or inp["error"] in retryable,
           f"{fx.relative_to(ROOT)} retry hint only on a retryable code")

# --- platform ------------------------------------------------------------------
# Requirements, tests, the glossary and the papers live in true-line/agent-bot-platform.
# Agents read it at main (platform PDR-0001, amended), so this fetches main fresh on
# every run. It fails rather than skips when the platform is unreachable: a check
# against stale context is worse than no check.
PLATFORM = "https://github.com/true-line/agent-bot-platform.git"
BLOCK = """<!-- platform:agent-bot-platform:start -->
Platform: true-line/agent-bot-platform, read at main.
This repository's charter, seams and requirements are in the platform's
registry/repos.yaml entry for soul-contracts. Read the platform's AGENTS.md
at the start of every task, and before changing a seam or anything a
requirement covers.
<!-- platform:agent-bot-platform:end -->"""
plat = pathlib.Path(tempfile.mkdtemp(prefix="platform-main-"))
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}


def pgit(*args):
    return subprocess.run(["git", "-C", str(plat), "-c", "credential.helper=", *args], capture_output=True, text=True, env=GIT_ENV)


fetched = pgit("init", "-q").returncode == 0 and pgit("fetch", "-q", "--depth", "1", "--no-tags", PLATFORM, "main").returncode == 0
report(fetched, "platform main fetched", f"cannot fetch main from {PLATFORM}; platform checks fail rather than skip")
if fetched:
    head = pgit("rev-parse", "--short", "FETCH_HEAD").stdout.strip()

    def at_main(path):
        r = pgit("show", f"FETCH_HEAD:{path}")
        return r.stdout if r.returncode == 0 else ""

    known = set(re.findall(r"^- id: (\S+)$", at_main("registry/requirements.yaml") + at_main("registry/tests.yaml"), re.M))
    need = {f"R{n}" for n in range(1, 13)} | {f"T{n:02d}" for n in range(1, 31)}
    report(not need - known, f"platform main ({head}) defines R1-R12 and T01-T30", "missing " + ", ".join(sorted(need - known)))

    s6 = re.search(r"^- id: S6$(.*?)(?=^- id: |\Z)", at_main("registry/sources.yaml"), re.M | re.S)
    s6 = s6 and re.search(r"^  sha256: ([0-9a-f]{64})$", s6.group(1), re.M)
    want = s6.group(1) if s6 else None
    report(registry["source"]["sha256"] == want, f"{REG_PATH} source.sha256 is S6 on platform main", f"platform has {want}")

    report(BLOCK in (ROOT / "AGENTS.md").read_text(encoding="utf-8"), "AGENTS.md carries the read-at-main platform block")

    links = [(p.relative_to(ROOT).as_posix(), ref, path) for p in sorted(ROOT.rglob("*.md")) if ".git" not in p.parts and p.name != "CHANGELOG.md"
             for ref, path in re.findall(r"github\.com/true-line/agent-bot-platform/(?:blob|tree)/([^/\s)#]+)/([^\s)#]*)", p.read_text(encoding="utf-8"))]
    bad = [f"{f}: {ref}/{path}" + ("" if ref == "main" else " (pinned)") for f, ref, path in links
           if ref != "main" or pgit("cat-file", "-e", f"FETCH_HEAD:{path.rstrip('/')}").returncode != 0]
    report(not bad, f"{len(links)} platform links use main and resolve there", "; ".join(bad))

    ID = re.compile(r"(?<![\w/+=.-])(R\d{1,2}|T\d\d|QA-[A-Z0-9]{3,4}-\d\d)(?![\w-])")

    def cited(o, key=None):
        if isinstance(o, dict):
            for k, val in o.items():
                yield from cited(val, k)
        elif isinstance(o, list):
            for val in o:
                yield from cited(val, key)
        elif isinstance(o, str) and key in ("description", "note"):
            yield from ID.findall(o)

    unknown = set()
    for p in [*(ROOT / "schemas").rglob("*.json"), *(ROOT / "fixtures").rglob("*.json"), ROOT / REG_PATH]:
        unknown |= {f"{p.relative_to(ROOT)}: {i}" for i in cited(load(p)) if i not in known}
    unknown |= {f"schemas/README.md: {i}" for i in ID.findall((ROOT / "schemas/README.md").read_text(encoding="utf-8")) if i not in known}
    report(not unknown, "contract artifacts cite only IDs defined on platform main", "; ".join(sorted(unknown)))
shutil.rmtree(plat, ignore_errors=True)

# --- vendor tokens (R10) -----------------------------------------------------
DENY = ["claude", "codex", "anthropic", "openai", "gpt-", "gemini", "google", "opencode", "copilot",
        "cursor", "bedrock", "mistral", "llama", "qwen", "glm", "deepseek", "grok", "meta.ai", "huggingface"]
artifacts = [*(ROOT / "schemas").rglob("*.json"), ROOT / "schemas/README.md", *(ROOT / "fixtures").rglob("*.*"), ROOT / REG_PATH]
hits = [f"{p.relative_to(ROOT)}: {t}" for p in artifacts for t in DENY if t in p.read_text(encoding="utf-8").lower()]
report(not hits, "R10 no vendor token in schemas, fixtures, registry", "; ".join(hits))

print(f"\n{'FAILED' if fails else 'passed'}: {fails} failure(s)")
sys.exit(1 if fails else 0)
