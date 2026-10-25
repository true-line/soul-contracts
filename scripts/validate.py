#!/usr/bin/env python3
"""Validate every fixture against its schema and its stated expectation. Exit 1 on any mismatch."""
import json, sys, pathlib, hashlib
from jsonschema import Draft202012Validator, FormatChecker
root = pathlib.Path(__file__).resolve().parents[1]
fails = 0
for fx in sorted((root / "fixtures").rglob("*.json")):
    d = json.loads(fx.read_text())
    schema = json.loads((root / "schemas" / d["schema"]).read_text())
    errs = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(d["input"]))
    want = d["expect"]["schema"]; got = "invalid" if errs else "valid"
    ok = want == got
    print(f"{'ok  ' if ok else 'FAIL'} {fx.relative_to(root)} expect={want} got={got}" + (f" error={d['expect'].get('error')}" if d['expect'].get('error') else ""))
    if not ok:
        fails += 1
        for e in errs[:3]: print("      ", e.message)
canon = root / "fixtures/positive/hello.first-start.canonical.txt"
if canon.exists():
    want = (root / "fixtures/positive/hello.first-start.digest.txt").read_text().strip()
    got = "sha256:" + hashlib.sha256(canon.read_bytes()).hexdigest()
    print(("ok  " if want == got else "FAIL") + " canonical digest")
    fails += want != got
sys.exit(1 if fails else 0)
