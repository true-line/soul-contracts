"""Source-only T21 candidate vectors; no physical qualification credit."""

import base64
import hashlib
import json
import pathlib
import sys
from copy import deepcopy
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from jcs import canonicalize, parse_strict
from stage2a_cooperative_reservation_fixtures import topology_matches


ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT
SCHEMAS = {}
for source in (BASE, ROOT):
    for path in (source / "schemas").rglob("*.schema.json"):
        schema = json.loads(path.read_text())
        SCHEMAS[schema["$id"]] = schema

def validator(name):
    uri = "https://true-line.ai/soul-contracts/machine/v3/" + name
    schema = SCHEMAS[uri]
    registry = Registry().with_resources(
        (schema_id, Resource.from_contents(contents))
        for schema_id, contents in SCHEMAS.items()
    )
    return Draft202012Validator(schema, registry=registry)

candidate = validator("soul-cooperative-qualification-candidate-reservation-payload.schema.json")
signed = validator("soul-cooperative-qualification-candidate-signed-reservation.schema.json")
ordinary = validator("soul-cooperative-reservation-payload.schema.json")
ordinary_signed = validator("soul-cooperative-signed-reservation.schema.json")

def canonical(raw):
    raw = raw.removesuffix(b"\n")
    value = parse_strict(raw)
    assert canonicalize(value) == raw
    return value

def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def cross_fields(payload, installed_review):
    assignment = payload["assignment"]
    binding = payload["measurement_binding"]
    issued = datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
    return (
        payload["qualification_only"] is True
        and issued < expires <= issued + timedelta(seconds=30)
        and assignment["expires_at"] == payload["expires_at"]
        and payload["host_id"] == binding["host_id"]
        and all(assignment[field] == binding[field] for field in
                ("installation_id", "soul_id", "start_id", "launch_id", "plan_id", "hq_epoch"))
        and assignment["plan_digest"] == binding["installed_plan_digest"]
        and assignment["package_sha256"] == binding["package_sha256"]
        and assignment["soul_artifact_sha256"] == binding["soul_artifact_sha256"]
        and topology_matches(payload)
        and payload["reviewed_start_id"] == assignment["start_id"]
        and payload["provider_config_sha256"] == payload["qualification_provider"]["config_sha256"]
        and payload["q_plan_id"] == installed_review["q_plan_id"]
        and payload["q_plan_digest"] == installed_review["q_plan_digest"]
        and payload["test_plan_sha256"] == installed_review["test_plan_sha256"]
        and payload["provider_config_sha256"] == installed_review["provider_config_sha256"]
        and payload["reviewed_start_id"] == installed_review["reviewed_start_id"]
        and binding["adapter_candidate"]["status"] == "uncertified-qualification-candidate"
        and "release_attestation_sha256" not in binding["adapter_candidate"]
        and "adapter_release" not in binding
    )

fixture_path = ROOT / "fixtures/reservation/v3/soul-cooperative-qualification-candidate-signed-reservation.synthetic.json"
fixture = canonical(fixture_path.read_bytes())
payload_raw = fixture["reservation_payload_jcs"].encode()
envelope_raw = fixture["reservation_envelope_jcs"].encode()
payload = canonical(payload_raw)
envelope = canonical(envelope_raw)
installed_review = fixture["synthetic_installed_review"]
assert candidate.is_valid(payload) and cross_fields(payload, installed_review)
assert not ordinary.is_valid(payload)
assert signed.is_valid(envelope) and not ordinary_signed.is_valid(envelope)
assert base64.urlsafe_b64decode(envelope["payload_base64url"] + "===") == payload_raw
assert envelope["payload_sha256"] == digest(payload_raw)
public_key = base64.urlsafe_b64decode(envelope["issuer_public_key_base64url"] + "===")
signature = base64.urlsafe_b64decode(envelope["signature_base64url"] + "===")
assert base64.urlsafe_b64encode(public_key).rstrip(b"=").decode() == envelope["issuer_public_key_base64url"]
assert base64.urlsafe_b64encode(signature).rstrip(b"=").decode() == envelope["signature_base64url"]
Ed25519PublicKey.from_public_bytes(public_key).verify(
    signature, envelope["purpose"].encode() + b"\0" + payload_raw
)
for altered_key, altered_value in (
    ("purpose", "agent-bot/soul-cooperative-reservation/v3"),
    ("payload_sha256", digest(b"different payload")),
    ("payload_base64url", base64.urlsafe_b64encode(b"different payload").rstrip(b"=").decode()),
):
    altered = deepcopy(envelope)
    altered[altered_key] = altered_value
    assert not (
        signed.is_valid(altered)
        and altered["payload_sha256"] == digest(payload_raw)
        and base64.urlsafe_b64decode(altered["payload_base64url"] + "===") == payload_raw
    ), altered_key
altered = deepcopy(envelope)
altered["signature_base64url"] = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
try:
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        base64.urlsafe_b64decode(altered["signature_base64url"] + "==="),
        altered["purpose"].encode() + b"\0" + payload_raw,
    )
except InvalidSignature:
    pass
else:
    raise AssertionError("altered signature accepted")

negatives_path = ROOT / "fixtures/reservation/v3/soul-cooperative-qualification-candidate-negative-vectors.synthetic.json"
negatives = canonical(negatives_path.read_bytes())
for case in negatives:
    raw = case["payload_jcs"].encode()
    bad = canonical(raw)
    negative_envelope = canonical(case["reservation_envelope_jcs"].encode())
    assert signed.is_valid(negative_envelope), case["name"]
    assert negative_envelope["payload_sha256"] == digest(raw), case["name"]
    assert base64.urlsafe_b64decode(negative_envelope["payload_base64url"] + "===") == raw, case["name"]
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        base64.urlsafe_b64decode(negative_envelope["signature_base64url"] + "==="),
        negative_envelope["purpose"].encode() + b"\0" + raw,
    )
    assert not (candidate.is_valid(bad) and cross_fields(bad, installed_review)), case["name"]

ordinary_fixture = parse_strict((BASE / "fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json").read_bytes())
ordinary_payload = canonical(ordinary_fixture["reservation_payload_jcs"].encode())
assert ordinary.is_valid(ordinary_payload)
assert not candidate.is_valid(ordinary_payload)
assert len(negatives) == 24
print("candidate signed positive, 24 signed negative payload vectors, 4 envelope substitutions, and ordinary cross-purpose refusal passed")
