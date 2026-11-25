#!/usr/bin/env python3
"""Derive a vendor-neutral signed c5 path/order twin from the pinned public source."""

import base64
import hashlib
import json
import pathlib
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize, parse_strict

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_SHA = "9ed32dfb54df653d2ec1d1a11f979275f90e0705736edaa8d8bfacc2e12de8d2"
KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x44]) * 32)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main(source_path):
    source_raw = pathlib.Path(source_path).read_bytes()
    if hashlib.sha256(source_raw).hexdigest() != SOURCE_SHA:
        raise ValueError("c5 public source SHA mismatch")
    source = parse_strict(source_raw)
    public = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    twin = {key: value for key, value in source.items()
            if key not in ("positive_envelope_base64url", "positive_payload_jcs",
                           "stale_c4_envelope_base64url", "target_first_envelope_base64url",
                           "public_key_base64url", "source")}
    twin["source_c5_sha256"] = "sha256:" + SOURCE_SHA
    twin["source"] = "vendor-neutral synthetic derivative; source bytes remain outside Contracts"
    twin["public_key_base64url"] = b64(public)

    positive = parse_strict(decode(parse_strict(decode(source["positive_envelope_base64url"]))[
        "payload_base64url"]))
    slug = re.sub(r"[^A-Za-z0-9]", "-", positive["cwd"]["emitted"])
    memory = positive["home"]["lexical"] + "/.fixture/projects/" + slug + "/memory/"

    for name in ("positive", "stale_c4", "target_first"):
        envelope = parse_strict(decode(source[name + "_envelope_base64url"]))
        payload = parse_strict(decode(envelope["payload_base64url"]))
        payload["memory"] = {"lexical": memory, "emitted": "/private" + memory}
        payload_raw = canonicalize(payload)
        envelope["issuer_public_key_base64url"] = b64(public)
        envelope["payload_base64url"] = b64(payload_raw)
        envelope["payload_sha256"] = "sha256:" + hashlib.sha256(payload_raw).hexdigest()
        envelope["signature_base64url"] = b64(KEY.sign(envelope["purpose"].encode() + b"\0" + payload_raw))
        twin[name + "_envelope_base64url"] = b64(canonicalize(envelope))
        if name == "positive":
            twin["positive_payload_jcs"] = payload_raw.decode("utf-8")

    destination = ROOT / "fixtures/stage2a-local-test/v2/c5-neutral-path-order.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(twin, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    envelope = parse_strict(decode(twin["positive_envelope_base64url"]))
    payload = parse_strict(decode(envelope["payload_base64url"]))
    for stem, schema, record in (
            ("stage2a-child-path-binding-payload.c5-neutral",
             "machine/local-test-v2/stage2a-child-path-binding-payload.schema.json", payload),
            ("stage2a-child-path-binding-signed.c5-neutral",
             "machine/local-test-v2/stage2a-child-path-binding-signed.schema.json", envelope)):
        positive = ROOT / "fixtures/positive" / (stem + ".json")
        positive.write_text(json.dumps({"schema": schema, "expect": {"schema": "valid"},
            "input": record, "canonical_sha256": "sha256:" + hashlib.sha256(canonicalize(record)).hexdigest()},
            indent=2, sort_keys=True) + "\n", encoding="utf-8")
        negative_record = {**record, "unexpected_field": True}
        negative = ROOT / "fixtures/negative" / (stem + "-extra.json")
        negative.write_text(json.dumps({"schema": schema, "expect": {"schema": "invalid"},
            "input": negative_record,
            "canonical_sha256": "sha256:" + hashlib.sha256(canonicalize(negative_record)).hexdigest(),
            "base": {"fixture": "positive/" + positive.name,
                     "sha256": "sha256:" + hashlib.sha256(positive.read_bytes()).hexdigest()}},
            indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_stage2a_local_test_c5_fixtures.py /absolute/c5-public-vector.json")
    main(sys.argv[1])
