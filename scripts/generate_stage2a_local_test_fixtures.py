#!/usr/bin/env python3
"""Derive a vendor-neutral, signed contract twin from private candidate 4.

Usage: uv run --no-project --with cryptography python scripts/generate_stage2a_local_test_fixtures.py /absolute/path/to/signed-tuple-c4.json
The source's SHA is pinned below; only neutral derived fixtures enter this repo.
"""
import base64
import copy
import hashlib
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from jcs import canonicalize

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_SHA = "bca0837385815cefc86b1158e7aad564f1885721e24670e415d3dae41ddbf167"
BASE_ID = "https://true-line.ai/soul-contracts/"
KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x43]) * 32)
PUBLIC = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def neutral(value):
    if isinstance(value, dict):
        return {neutral(key): neutral(part) for key, part in value.items()}
    if isinstance(value, list):
        return [neutral(part) for part in value]
    if isinstance(value, str):
        for before, after in (
            ("claude-haiku-4-5-20251001", "fixture-model"),
            ("claude-agent-acp", "fixture-adapter-acp"),
            ("claude-code", "fixture-adapter"),
            ("stock-claude", "fixture-adapter"),
            ("ANTHROPIC", "FIXTURE"),
            ("Anthropic", "Fixture"),
            ("anthropic", "fixture"),
            ("Claude", "Fixture"),
            ("claude", "fixture"),
        ):
            value = value.replace(before, after)
    return value


def signed(purpose, payload):
    raw = canonicalize(payload)
    envelope = {
        "schema_version": 1,
        "purpose": purpose,
        "issuer_public_key_base64url": b64(PUBLIC),
        "payload_sha256": sha(raw),
        "payload_base64url": b64(raw),
        "signature_base64url": b64(KEY.sign(purpose.encode() + b"\0" + raw)),
    }
    envelope_raw = canonicalize(envelope)
    return {"purpose": purpose, "payload": payload, "envelope": envelope,
            "envelope_base64url": b64(envelope_raw), "envelope_sha256": sha(envelope_raw)}


def replace_selector(member, reservation_sha):
    preimage = ("agent-bot/stage2a-member-selector/v1\0" + reservation_sha + "\0"
                + member["member_id"] + "\0" + member["launch_id"]).encode()
    member["member_selector"] = "mb_" + hashlib.sha256(preimage).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def inferred(value, key=""):
    if isinstance(value, dict):
        if key in {"required_fixed", "required_volatile"}:
            return {"type": "object", "propertyNames": {"pattern": "^[a-z0-9][a-z0-9-]*$"},
                    "additionalProperties": {"type": "string"}}
        properties = {name: inferred(part, name) for name, part in value.items()}
        return {"type": "object", "required": sorted(value), "properties": properties,
                "additionalProperties": False}
    if isinstance(value, list):
        return {"type": "array", "minItems": len(value), "maxItems": len(value),
                "prefixItems": [inferred(part, key) for part in value], "items": False}
    if isinstance(value, bool):
        return {"const": value}
    if isinstance(value, int):
        if key in {"schema_version", "http_status", "invocation", "max_ancillary", "ancillary_http_status"}:
            return {"const": value}
        return {"type": "integer", "minimum": 0, "maximum": 9007199254740991}
    if value is None:
        return {"type": "null"}
    if key in {"contract", "kind", "schema", "version", "purpose", "mode",
               "profile_in_force", "body_profile", "digest_kind", "role", "state",
               "runtime_state", "acp_authority", "provider_ingress", "relay_peer_rule",
               "relay_peer_state", "stop_reason"}:
        return {"const": value}
    if key.endswith("_base64url"):
        return {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"}
    if key.endswith("_sha256") or key in {"reservation_digest", "response_sha256"}:
        pattern = "^sha256:[0-9a-f]{64}$" if value.startswith("sha256:") else "^[0-9a-f]{64}$"
        return {"type": "string", "pattern": pattern}
    if key in {"start_id", "launch_id", "selected_launch_id", "outer_launch_id"}:
        return {"type": "string", "pattern": "^(st|ln)_[0-9a-f]{24}$"}
    if key == "member_selector" or key == "selected_member_selector":
        return {"type": "string", "pattern": "^mb_[0-9a-f]{64}$"}
    if key.endswith("_at") or key == "expires_at":
        return {"type": "string", "format": "date-time"}
    if key in {"hq_epoch", "plan_digest", "attach", "bridge_ready_nonce",
               "prewrite_receipt", "ingress_origin_mac", "completion_origin_mac"}:
        return {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {"type": "string", "minLength": 0 if value == "" else 1}


def main(source_path):
    raw = pathlib.Path(source_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise SystemExit("private candidate-4 source SHA differs")
    source = json.loads(raw)
    r = neutral(copy.deepcopy(source["reservation"]["payload"]))
    reservation = signed(source["reservation"]["purpose"], r)
    a = neutral(copy.deepcopy(source["member_assignment"]["payload"]))
    a["reservation_sha256"] = reservation["envelope_sha256"]
    a["b_authority"] = {"purpose": reservation["purpose"],
                        "envelope_sha256": reservation["envelope_sha256"]}
    for member in a["members"]:
        replace_selector(member, reservation["envelope_sha256"])
    fields = ("member_id", "role", "adapter_id", "adapter_version", "command_path",
              "command_sha256", "adjacent_cli_path", "adjacent_cli_sha256")
    a["owner_plan_member_set_sha256"] = sha(canonicalize([
        {field: row[field] for field in fields} for row in a["members"]]))
    assignment = signed(source["member_assignment"]["purpose"], a)
    b = neutral(copy.deepcopy(source["b_policy"]["payload"]))
    b["reservation_sha256"] = reservation["envelope_sha256"]
    b["member_set_assignment_envelope_sha256"] = assignment["envelope_sha256"]
    b["owner_plan_member_set_sha256"] = a["owner_plan_member_set_sha256"]
    b["b_authority"] = a["b_authority"]
    for i, row in enumerate(b["members"]):
        row["member_selector"] = a["members"][i]["member_selector"]
    lt = b["local_test"]
    lt["selected_member_selector"] = a["members"][0]["member_selector"]
    lt["header_shape_sha256"] = sha(canonicalize(lt["header_shape"]))
    lt["ancillary_profile_sha256"] = sha(canonicalize(lt["ancillary_profile"]))
    lt["fixture_config_sha256"] = sha(canonicalize({"schema": "stage2a-observed-body-local-test-fixture/v1",
                                                  "model": lt["model"], "response_text": "fixture response"}))
    b["members"][0]["qualification"]["header_shape_sha256"] = lt["header_shape_sha256"]
    b["members"][0]["qualification"]["model"] = lt["model"]
    b["members"][0]["qualification"]["response_text_sha256"] = sha(b"fixture response")
    policy = signed(source["b_policy"]["purpose"], b)
    fd3 = neutral(copy.deepcopy(source["b_fd3"]))
    fd3["assignment_envelope_base64url"] = assignment["envelope_base64url"]
    fd3["authority_envelope_base64url"] = policy["envelope_base64url"]
    fd3["local_test"] = lt
    fd3["selectors"]["reservation_digest"] = reservation["envelope_sha256"]
    fd3["selectors"]["assignment_envelope_sha256"] = assignment["envelope_sha256"]
    fd3["selectors"]["authority_envelope_sha256"] = policy["envelope_sha256"]
    fd3["selectors"]["member_selectors_sha256"] = sha(canonicalize([
        row["member_selector"] for row in a["members"]]))
    core = neutral(copy.deepcopy(source["ingress"]["payload"]["core"]))
    core["selectors"] = fd3["selectors"]
    authorization_payload = neutral(copy.deepcopy(source["authorization"]["payload"]))
    authorization_payload["selectors"] = fd3["selectors"]
    authorization_payload["ingress_core_sha256"] = sha(canonicalize(core))
    authorization = signed(source["authorization"]["purpose"], authorization_payload)
    provider = neutral(copy.deepcopy(source["provider_response"]))
    provider["response_sha256"] = sha(provider["response_text"].encode())
    request = {"mode": provider["mode"], "model": provider["model"],
               "observed_body_sha256": provider["observed_body_sha256"]}
    reply = {"id": "ingress", "ok": True, "result": {
        "authorization_envelope_base64url": authorization["envelope_base64url"],
        "authorization_envelope_sha256": authorization["envelope_sha256"],
        "ingress_core_sha256": sha(canonicalize(core)), "provider": provider,
        "provider_request_body_sha256": sha(canonicalize(request)),
        "provider_response_body_sha256": sha(canonicalize(provider))}}
    ack = neutral(copy.deepcopy(source["completion_ack"]))
    ack["result"]["selectors"] = fd3["selectors"]
    ack["result"]["authorization_envelope_sha256"] = authorization["envelope_sha256"]
    neutral_tuple = {"schema": "stage2a-local-test-neutral-tuple/v1",
                     "source_c4_sha256": "sha256:" + SOURCE_SHA,
                     "machine_public_key_base64url": b64(PUBLIC),
                     "reservation": reservation, "assignment": assignment,
                     "policy": policy, "b_fd3": fd3,
                     "ingress_core": core, "authorization": authorization,
                     "ingress_reply": reply, "completion_ack": ack}
    write_json(ROOT / "fixtures/stage2a-local-test/v1/neutral-tuple.json", neutral_tuple)
    # This proposed gate is separate from frozen C4. A signs only after it
    # durably accepts prewrite; B verifies the signed bytes before any write.
    response_wire = ('HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n'
                     'event: message\ndata: {"text":"fixture response"}\n\n')
    prewrite_core = neutral(copy.deepcopy(source["prewrite"]))
    prewrite_core["selectors"] = fd3["selectors"]
    prewrite_core["authorization_envelope_sha256"] = authorization["envelope_sha256"]
    prewrite_core["ingress_core_sha256"] = sha(canonicalize(core))
    prewrite_core["response_wire_bytes"] = len(response_wire.encode())
    prewrite_core["response_wire_sha256"] = sha(response_wire.encode())
    proof_payload = {"schema": "agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1",
                     "kind": "observed-body-local-test-prewrite-acceptance", "schema_version": 1,
                     "selectors": fd3["selectors"], "hq_epoch": b["hq_epoch"],
                     "authorization_envelope_sha256": authorization["envelope_sha256"],
                     "prewrite_core_sha256": sha(canonicalize(prewrite_core)),
                     "prewrite_receipt": neutral(source["completion_core"]["prewrite_receipt"]),
                     "issued_at": "2026-11-24T12:00:12Z", "expires_at": "2026-11-24T12:00:16Z"}
    proof = signed("agent-bot/stage2a-observed-body-local-test-prewrite-acceptance/v1", proof_payload)
    prewrite_reply = {"prewrite_receipt": proof_payload["prewrite_receipt"],
                      "prewrite_proof_envelope_base64url": proof["envelope_base64url"],
                      "prewrite_proof_envelope_sha256": proof["envelope_sha256"]}
    write_json(ROOT / "fixtures/stage2a-local-test/v1/prewrite-proof.json",
               {"schema": "stage2a-local-test-prewrite-proof-fixture/v1",
                "source_c4_sha256": "sha256:" + SOURCE_SHA,
                "response_wire_utf8": response_wire,
                "prewrite_core": prewrite_core,
                "proof": proof, "prewrite_reply": prewrite_reply})
    records = {
        "machine/local-test-v1/stage2a-reservation-payload.schema.json": r,
        "machine/local-test-v1/stage2a-signed-reservation.schema.json": reservation["envelope"],
        "machine/local-test-v1/stage2a-member-set-assignment-payload.schema.json": a,
        "machine/local-test-v1/stage2a-member-set-signed-assignment.schema.json": assignment["envelope"],
        "machine/local-test-v1/stage2a-b-member-authority-payload.schema.json": b,
        "machine/local-test-v1/stage2a-b-member-signed-authority.schema.json": policy["envelope"],
        "machine/local-test-v1/stage2a-b-fd3.schema.json": fd3,
        "machine/local-test-v1/stage2a-ingress-authorization-payload.schema.json": authorization_payload,
        "machine/local-test-v1/stage2a-ingress-signed-authorization.schema.json": authorization["envelope"],
        "machine/local-test-v1/stage2a-prewrite-core.schema.json": prewrite_core,
        "machine/local-test-v1/stage2a-prewrite-proof-payload.schema.json": proof_payload,
        "machine/local-test-v1/stage2a-prewrite-signed-proof.schema.json": proof["envelope"],
        "hq/v1/stage2a-local-test-ingress-reply.schema.json": reply,
        "hq/v1/stage2a-local-test-completion-ack.schema.json": ack,
        "hq/v1/stage2a-local-test-prewrite-reply.schema.json": prewrite_reply,
    }
    for path, record in records.items():
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
                  "$id": BASE_ID + path, "title": "Stage 2a observed-body local-test " +
                  pathlib.Path(path).name.removesuffix(".schema.json").replace("-", " "),
                  "description": "Source-enabling exact record shape; signed authority, cross-record joins, current lifetime and kernel observations require independent verification.",
                  **inferred(record)}
        if path.endswith("stage2a-reservation-payload.schema.json"):
            schema["properties"]["assignment"]["properties"]["machine_uid"].update({"minimum": 400, "maximum": 4294967295})
            schema["properties"]["assignment"]["properties"]["runner_uid"].update({"minimum": 300, "maximum": 399})
            schema["properties"]["start_scope"]["properties"]["mode"] = {"const": "provider-pending-local-test/v1"}
        if path.endswith("stage2a-b-member-authority-payload.schema.json"):
            schema["properties"]["outer_launch_id"] = {"type": "string", "pattern": "^ln_[0-9a-f]{24}$"}
        write_json(ROOT / "schemas" / path, schema)
        stem = pathlib.Path(path).name.removesuffix(".schema.json")
        pos_path = ROOT / "fixtures/positive" / f"{stem}.local-test-neutral.json"
        pos = {"schema": path, "input": record, "expect": {"schema": "valid"},
               "canonical_sha256": sha(canonicalize(record))}
        write_json(pos_path, pos)
        wrong = copy.deepcopy(record)
        wrong["unexpected_field"] = True
        neg_path = ROOT / "fixtures/negative" / f"{stem}.local-test-neutral-extra.json"
        write_json(neg_path, {"schema": path, "input": wrong,
                              "base": {"fixture": "positive/" + pos_path.name,
                                       "sha256": sha(pos_path.read_bytes())},
                              "expect": {"schema": "invalid"}})
    print("generated", len(records), "schemas and neutral signed fixtures")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("pass private candidate-4 JSON path")
    main(sys.argv[1])
