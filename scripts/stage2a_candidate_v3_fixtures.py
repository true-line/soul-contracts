"""A synthetic first-qualification reservation, deliberately not a launch grant."""

import copy
import json
from datetime import datetime, timedelta

from jcs import canonicalize, parse_strict
from stage2a_hr_v3_fixtures import decode, digest, require, signed_payload

PURPOSE = b"agent-bot/stage2a-qualification-candidate-reservation/v3"
BASE = "machine/v3/stage2a-qualification-candidate-"


def candidate_envelope(raw):
    parsed = parse_strict(raw)
    require(canonicalize(parsed) == raw, "candidate envelope must be exact JCS bytes")
    return parsed


def check_byte_refusals(path, canonical_envelope, normal_receipt):
    refusals = parse_strict(path.read_bytes())
    cases = (
        ("duplicate_envelope_key", candidate_envelope, canonical_envelope),
        ("noncanonical_envelope", candidate_envelope, canonical_envelope),
        ("duplicate_attempt_key", parse_strict, normal_receipt),
    )
    require(set(refusals) == {name for name, _, _ in cases}, "byte refusal vector fields")
    for name, parse, normal in cases:
        raw = refusals[name].encode()
        require(raw != normal and json.loads(raw) == json.loads(normal),
                "byte refusal must preserve lenient JSON values: " + name)
        try:
            parse(raw)
        except ValueError:
            continue
        raise ValueError("candidate byte verifier accepted " + name)


def check_stage2a_candidate_v3_fixtures(root, schemas, report):
    directory = root / "fixtures/reservation/v3"
    path = directory / "machine-qualification-candidate-synthetic.json"
    try:
        vector = parse_strict(path.read_bytes())
        ordinary = parse_strict((directory / "machine-hr-synthetic.json").read_bytes())
        envelope_schema = schemas[BASE + "signed-reservation.schema.json"]
        payload_schema = schemas[BASE + "reservation-payload.schema.json"]
        envelope_raw = vector["reservation_envelope_jcs"].encode()
        envelope = candidate_envelope(envelope_raw)
        payload, _ = signed_payload(envelope, PURPOSE, envelope_schema, payload_schema,
                                    decode(ordinary["issuer_public_key_base64url"]))
        common = parse_strict(ordinary["reservation_payload_jcs"])
        projected = copy.deepcopy(payload)
        attempt = projected.pop("qualification_attempt")
        binding = projected["measurement_binding"]
        candidate = binding.pop("candidate_adapter")
        ordinary_binding = common["measurement_binding"]
        released = ordinary_binding["adapter_release"]
        require(candidate["candidate_manifest_sha256"] == released["release_manifest_sha256"],
                "reviewed candidate manifest")
        for key in ("component_id", "package_sha256", "executable_path", "executable_sha256",
                    "code_inputs_digest", "code_input_count"):
            require(candidate[key] == released[key], "same selected bytes: " + key)
        binding["adapter_release"] = released
        binding["kind"] = ordinary_binding["kind"]
        projected["kind"] = common["kind"]
        require(projected == common, "exact common H/R projection")
        receipt_raw = vector["spent_attempt_bytes"].encode()
        require(attempt["attempt_receipt_sha256"] == digest(receipt_raw),
                "exact durable attempt bytes")
        receipt = parse_strict(receipt_raw)
        require(receipt["result"] == "started" and receipt["purpose"] == "harness-qualification-run",
                "fixed owner attempt purpose and state")
        require(attempt["approval_plan_id"] == receipt["plan_id"] and
                attempt["approval_plan_digest"] == receipt["plan_digest"] and
                attempt["qualification_request_sha256"] == "sha256:" + receipt["request_sha256"],
                "selected approval and request identity")
        issued = datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
        approval = datetime.fromisoformat(attempt["approval_expires_at"].replace("Z", "+00:00"))
        require(issued < expires <= min(approval, issued + timedelta(seconds=30)), "short live approval")
        require(not schemas["machine/v3/stage2a-reservation-payload.schema.json"].is_valid(payload),
                "ordinary reservation rejects candidate")
        require(not payload_schema.is_valid(common), "candidate reservation rejects ordinary release")
        substitution = copy.deepcopy(payload)
        substitution["measurement_binding"]["adapter_release"] = released
        require(not payload_schema.is_valid(substitution), "candidate refuses release field injection")
        substitution = copy.deepcopy(payload)
        substitution["qualification_attempt"]["network_mode"] = "vendor-direct"
        require(not payload_schema.is_valid(substitution), "candidate refuses direct vendor egress")
        substitution = copy.deepcopy(envelope)
        substitution["purpose"] = "agent-bot/stage2a-reservation/v3"
        require(not envelope_schema.is_valid(substitution), "candidate refuses ordinary signature purpose")
        check_byte_refusals(directory / "machine-qualification-candidate-invalid-bytes.json",
                            envelope_raw, receipt_raw)
        report(True, str(path.relative_to(root)))
    except (KeyError, OSError, ValueError) as exc:
        report(False, str(path.relative_to(root)), str(exc))
