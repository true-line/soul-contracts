"""Source-only T21 candidate vectors; no physical qualification credit."""

import base64
import binascii
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
from stage2a_cooperative_reservation_fixtures import LAUNCH_PURPOSE, topology_matches
from stage2a_hr_v3_fixtures import H_PURPOSE


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

def decoded_config(value):
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        return None
    return raw

def cross_fields(payload, installed_review, source):
    assignment = payload["assignment"]
    binding = payload["measurement_binding"]
    inventory = binding["r_inventory"]
    launch = source["launch_records"]
    provider_bytes = decoded_config(payload["qualification_provider"]["config_base64url"])
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
        and assignment["package_root"] == binding["snapshots"]["definition"]["root_path"]
        and assignment["launch_inputs_root"] == binding["snapshots"]["launch_inputs"]["root_path"]
        and assignment["runtime_root"] == inventory["snapshot"]["path"]
        and assignment["node_path"] == assignment["runtime_root"].rstrip("/") + "/bin/node"
        and assignment["entry_path"] == assignment["runtime_root"].rstrip("/") + "/bin/agent-bot-souls.mjs"
        and assignment["state_root"] == f"/private/var/agent-bot-soul-runner-{assignment['runner_account']}/state"
        and inventory["installation_id"] == assignment["installation_id"]
        and inventory["owner_plan_digest"] == "sha256:" + assignment["plan_digest"]
        and inventory["reader_uid"] == assignment["runner_uid"]
        and inventory["reader_gid"] == assignment["runner_gid"]
        and inventory == source["r_inventory_reference"]
        and payload["installed_plan_receipt_sha256"] == installed_review["installed_plan_receipt_sha256"]
        and binding["h_service_descriptor_digest"] == source["h_descriptor_digest"]
        and binding["launch_input_measurement"] == source["launch_input_digest"]
        and payload["admission_challenge_sha256"] == source["admission_challenge_digest"]
        and launch["adapter_transport"] == payload["adapter_transport"]
        and launch["selected_command"] == assignment["node_path"]
        and launch["environment"]["HOME"] == assignment["state_root"]
        and launch["effective_config"]["qualification_provider_config_sha256"] == payload["provider_config_sha256"]
        and launch["host_projection"]["installation"]["id"] == assignment["installation_id"]
        and topology_matches(payload)
        and payload["reviewed_start_id"] == assignment["start_id"]
        and payload["provider_config_sha256"] == payload["qualification_provider"]["config_sha256"]
        and provider_bytes is not None
        and digest(provider_bytes) == payload["provider_config_sha256"]
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
assert fixture["r_inventory_fixture"] == "fixtures/reservation/v3/soul-cooperative-r-inventory.synthetic.json"
assert fixture["launch_input_fixture"] == "fixtures/reservation/v3/soul-cooperative-launch-inputs.synthetic.json"
r_vector = parse_strict((ROOT / fixture["r_inventory_fixture"]).read_bytes())
launch_vector = parse_strict((ROOT / fixture["launch_input_fixture"]).read_bytes())
launch_raw = launch_vector["records_jcs"].encode()
h_raw = fixture["h_payload_jcs"].encode()
launch_records = canonical(launch_raw)
canonical(h_raw)
source = {
    "r_inventory_reference": r_vector["reference"],
    "launch_records": launch_records,
    "launch_input_digest": digest(LAUNCH_PURPOSE + b"\0" + launch_raw),
    "h_descriptor_digest": digest(H_PURPOSE + b"\0" + h_raw),
    "admission_challenge_digest": digest(base64.urlsafe_b64decode(fixture["admission_challenge_base64url"] + "===")),
}
assert launch_vector["sha256"] == source["launch_input_digest"]
assert fixture["h_descriptor_digest"] == source["h_descriptor_digest"]
payload_raw = fixture["reservation_payload_jcs"].encode()
envelope_raw = fixture["reservation_envelope_jcs"].encode()
payload = canonical(payload_raw)
envelope = canonical(envelope_raw)
installed_review = fixture["synthetic_installed_review"]
assert candidate.is_valid(payload) and cross_fields(payload, installed_review, source)
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
    if case["name"] == "altered provider config bytes":
        assert candidate.is_valid(bad)
        assert bad["provider_config_sha256"] == payload["provider_config_sha256"]
        assert decoded_config(bad["qualification_provider"]["config_base64url"]) != decoded_config(
            payload["qualification_provider"]["config_base64url"])
    if case["name"] == "runner substitution against R inventory":
        assert candidate.is_valid(bad) and topology_matches(bad)
        assert bad["measurement_binding"]["r_inventory"]["reader_uid"] != bad["assignment"]["runner_uid"]
    assert not (candidate.is_valid(bad) and cross_fields(bad, installed_review, source)), case["name"]

ordinary_fixture = parse_strict((BASE / "fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json").read_bytes())
ordinary_payload = canonical(ordinary_fixture["reservation_payload_jcs"].encode())
assert ordinary.is_valid(ordinary_payload)
assert not candidate.is_valid(ordinary_payload)
assert len(negatives) == 32
print("candidate signed positive, 32 signed negative payload vectors, 4 envelope substitutions, and ordinary cross-purpose refusal passed")
