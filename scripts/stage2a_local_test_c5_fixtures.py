"""Verify the source-only c5 signed per-start path and ancillary order twin."""

import base64
import hashlib
import re
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jcs import canonicalize, parse_strict

PAYLOAD = "machine/local-test-v2/stage2a-child-path-binding-payload.schema.json"
ENVELOPE = "machine/local-test-v2/stage2a-child-path-binding-signed.schema.json"
SOURCE_SHA = "sha256:9ed32dfb54df653d2ec1d1a11f979275f90e0705736edaa8d8bfacc2e12de8d2"
PURPOSE = "agent-bot/stage2a-child-path-binding-local-test/v1"


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == value,
            "canonical unpadded base64url")
    return raw


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def signed_payload(vector, name, schemas):
    raw = decode(vector[name + "_envelope_base64url"])
    envelope = parse_strict(raw)
    require(canonicalize(envelope) == raw and schemas[ENVELOPE].is_valid(envelope) and
            envelope["purpose"] == PURPOSE, "exact c5 signed envelope shape and purpose")
    public = decode(vector["public_key_base64url"])
    require(decode(envelope["issuer_public_key_base64url"]) == public,
            "c5 neutral test signature uses pinned issuer")
    payload_raw = decode(envelope["payload_base64url"])
    payload = parse_strict(payload_raw)
    require(canonicalize(payload) == payload_raw and schemas[PAYLOAD].is_valid(payload) and
            envelope["payload_sha256"] == digest(payload_raw),
            "exact c5 payload JCS, schema and digest")
    Ed25519PublicKey.from_public_bytes(public).verify(
        decode(envelope["signature_base64url"]), PURPOSE.encode() + b"\0" + payload_raw)
    return payload, payload_raw


def check_semantics(vector, payload):
    preimage = (b"agent-bot-soul-endpoint-start/v1\0" + vector["installation_id"].encode() +
                b"\0" + vector["start_id"].encode())
    slot = hashlib.sha256(preimage).digest()[:10].hex()
    require(vector["slot_preimage_hex"] == preimage.hex() and
            vector["slot_preimage_utf8"] == preimage.decode() and
            vector["start_slot"] == payload["start_slot"] == slot,
            "NUL-separated per-start slot preimage and first ten SHA-256 bytes")
    require(payload["installation_id"] == vector["installation_id"] and
            payload["start_id"] == vector["start_id"] and
            payload["runner_account"] == vector["runner_account"] and
            payload["runner_home_lexical"] == vector["runner_home_lexical"] and
            when(payload["issued_at"]) < when(payload["expires_at"]),
            "c5 signed start, runner and live time window")
    home_root = "/var/agent-bot-soul-runner-" + vector["runner_account"]
    base = home_root + "/state/child-" + slot
    cwd, home = base + "/work", base + "/home"
    slug = re.sub(r"[^A-Za-z0-9]", "-", "/private" + cwd)
    memory = home + "/.fixture/projects/" + slug + "/memory/"
    require(vector["runner_home_lexical"] == home_root and
            all(payload[key] == {"lexical": lexical, "emitted": "/private" + lexical}
                for key, lexical in (("cwd", cwd), ("home", home), ("memory", memory))),
            "per-start lexical and emitted child paths and neutral memory slug")
    require(payload["ancillary_order"] == ["first", "second"] and
            payload["target_after"] == ["first"],
            "target follows first ancillary request with fixed A/B order")


def permits_sequence(payload, sequence):
    if sorted(sequence) != ["first", "second", "target"]:
        return False
    ancillary = [item for item in sequence if item != "target"]
    before_target = sequence[:sequence.index("target")]
    return ancillary == payload["ancillary_order"] and all(
        item in before_target for item in payload["target_after"])


def check_stage2a_local_test_c5_fixtures(root, schemas, report):
    vector = parse_strict((root / "fixtures/stage2a-local-test/v2/c5-neutral-path-order.json").read_bytes())
    try:
        require(vector["source_c5_sha256"] == SOURCE_SHA,
                "exact reviewed external c5 source SHA pin")
        positive, raw = signed_payload(vector, "positive", schemas)
        require(raw == vector["positive_payload_jcs"].encode(),
                "checked-in neutral positive payload exact JCS")
        check_semantics(vector, positive)
        require(vector["accepted_sequences"] == ["A,B,T", "A,T,B"] and
                permits_sequence(positive, ["first", "second", "target"]) and
                permits_sequence(positive, ["first", "target", "second"]) and
                not permits_sequence(positive, ["target", "first", "second"]),
                "both first-before-target ancillary placements are accepted")
        for name, reason in (("stale_c4", "per-start lexical and emitted child paths and neutral memory slug"),
                             ("target_first", "target follows first ancillary request with fixed A/B order")):
            negative, _ = signed_payload(vector, name, schemas)
            try:
                check_semantics(vector, negative)
            except ValueError as error:
                require(str(error) == reason, name + " signed refusal at intended c5 join")
            else:
                raise ValueError(name + " signed c5 negative accepted")
        report(True, "c5 neutral signed per-start path, slug, A/B order and negative refusals")
    except Exception as error:
        report(False, "c5 neutral signed per-start path, slug, A/B order and negative refusals", str(error))
