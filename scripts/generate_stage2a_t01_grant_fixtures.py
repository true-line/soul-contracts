#!/usr/bin/env python3
"""Rebuild source-only T01 byte vectors; fixture keys grant no authority."""

import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from jcs import canonicalize

ROOT = Path(__file__).resolve().parents[1]
KEY = Ed25519PrivateKey.from_private_bytes(b"\x15" * 32)
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
PURPOSE = "agent-bot/stage2a-protected-grant-refusal/v1"


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def write(name, value):
    path = ROOT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    return sha(path.read_bytes())


def fixture(stem, schema, value, negative=None):
    path = f"fixtures/positive/{stem}.synthetic.json"
    base = {"schema": schema, "input": value, "expect": {"schema": "valid"},
            "canonical_sha256": sha(canonicalize(value))}
    base_sha = write(path, base)
    bad = copy.deepcopy(value)
    negative(bad)
    write(f"fixtures/negative/{stem}.synthetic-invalid.json", {
        "schema": schema, "input": bad, "expect": {"schema": "invalid"},
        "base": {"fixture": f"positive/{stem}.synthetic.json", "sha256": base_sha},
    })


def main():
    request = {
        "contract": "hq/v1", "kind": "stage2a-protected-grant-invoke", "schema_version": 1,
        "installation_id": "fixture-t01-install", "start_id": "st_" + "a" * 24,
        "launch_id": "ln_" + "b" * 24, "runtime_id": "fixture-member-b-runtime",
        "grant_handle": "gh_" + "c" * 32, "operation": "provider.invoke",
        "resource_selector": {"provider": "fixture-provider", "model": "fixture-model"},
        "prompt_sha256": sha(b"fixture prompt"),
        "request_nonce_base64url": b64(bytes(range(16))),
    }
    request_raw = canonicalize(request)
    assertion = {
        "contract": "hq/v1", "kind": "stage2a-protected-grant-refusal-assertion",
        "schema_version": 1, "host_id": "fixture-physical-mac",
        "installation_id": request["installation_id"], "start_id": request["start_id"],
        "launch_id": request["launch_id"], "hq_epoch": "d" * 64,
        "runtime_id": request["runtime_id"], "member_id": "fixture-member-b",
        "installation_epoch": 3, "lease_generation": 2,
        "request_sha256": sha(request_raw),
        "grant_handle_sha256": sha(request["grant_handle"].encode("ascii")),
        "operation": request["operation"], "resource_selector": request["resource_selector"],
        "prompt_sha256": request["prompt_sha256"],
        "request_nonce_base64url": request["request_nonce_base64url"],
        "code": "caller_mismatch", "decision_stage": "before_effect",
        "effect_invoked": False, "seq": 91, "recorded_at": "2026-11-23T10:15:00Z",
    }
    assertion_raw = canonicalize(assertion)
    payload = {
        "contract": "machine/v1", "kind": "stage2a-protected-grant-refusal",
        "schema_version": 1, "host_id": assertion["host_id"],
        "installation_id": assertion["installation_id"], "start_id": assertion["start_id"],
        "launch_id": assertion["launch_id"], "reservation_sha256": sha(b"fixture reservation"),
        "hq_epoch": assertion["hq_epoch"], "paired_hq_public_key_base64url": b64(b"\x16" * 32),
        "hq_assertion_sha256": sha(assertion_raw), "hq_assertion_base64url": b64(assertion_raw),
        "observed_hq_request_sha256": sha(b"fixture authenticated paired delivery"),
        "evidence_class": "authenticated-hq-assertion-only", "issued_at": "2026-11-23T10:15:01Z",
    }
    payload_raw = canonicalize(payload)
    envelope = {
        "schema_version": 1, "purpose": PURPOSE,
        "issuer_public_key_base64url": b64(PUBLIC),
        "payload_sha256": sha(payload_raw), "payload_base64url": b64(payload_raw),
        "signature_base64url": b64(KEY.sign(PURPOSE.encode() + b"\0" + payload_raw)),
    }
    fixture("stage2a-protected-grant-invoke", "hq/v1/stage2a-protected-grant-invoke.schema.json",
            request, lambda v: v.pop("grant_handle"))
    fixture("stage2a-protected-grant-refusal-assertion",
            "hq/v1/stage2a-protected-grant-refusal-assertion.schema.json",
            assertion, lambda v: v.__setitem__("effect_invoked", True))
    fixture("stage2a-protected-grant-refusal-payload",
            "machine/v1/stage2a-protected-grant-refusal-payload.schema.json",
            payload, lambda v: v.__setitem__("evidence_class", "physical-pass"))
    fixture("stage2a-protected-grant-signed-refusal",
            "machine/v1/stage2a-protected-grant-signed-refusal.schema.json",
            envelope, lambda v: v.__setitem__("purpose", "agent-bot/stage2a-protected-grant-refusal/v0"))
    write("fixtures/qualification/t01/t01-grant-wire-synthetic.json", {
        "request_jcs": request_raw.decode(), "assertion_jcs": assertion_raw.decode(),
        "a_payload_jcs": payload_raw.decode(), "a_envelope_jcs": canonicalize(envelope).decode(),
        "fixture_a_public_key_base64url": b64(PUBLIC),
    })


if __name__ == "__main__":
    main()
