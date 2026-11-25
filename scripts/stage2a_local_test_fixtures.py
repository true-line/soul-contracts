"""Verify the neutral signed local-test tuple and semantic refusal vectors."""

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from jcs import canonicalize, parse_strict

FAMILY = "machine/local-test-v1/"
SIGNED = {
    "reservation": ("stage2a-signed-reservation", "stage2a-reservation-payload"),
    "assignment": ("stage2a-member-set-signed-assignment", "stage2a-member-set-assignment-payload"),
    "policy": ("stage2a-b-member-signed-authority", "stage2a-b-member-authority-payload"),
    "authorization": ("stage2a-ingress-signed-authorization", "stage2a-ingress-authorization-payload"),
    "proof": ("stage2a-prewrite-signed-proof", "stage2a-prewrite-proof-payload"),
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == value, "noncanonical base64url")
    return raw


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_signed(record, kind, schemas, public):
    env_name, payload_name = SIGNED[kind]
    envelope_raw = decode(record["envelope_base64url"])
    envelope = parse_strict(envelope_raw)
    require(canonicalize(envelope) == envelope_raw == canonicalize(record["envelope"]), kind + " envelope JCS")
    require(sha(envelope_raw) == record["envelope_sha256"], kind + " envelope digest")
    require(schemas[FAMILY + env_name + ".schema.json"].is_valid(envelope), kind + " envelope shape")
    require(envelope["purpose"] == record["purpose"] and envelope["schema_version"] == 1,
            kind + " purpose and version")
    require(decode(envelope["issuer_public_key_base64url"]) == public, kind + " pinned issuer")
    payload_raw = decode(envelope["payload_base64url"])
    payload = parse_strict(payload_raw)
    require(canonicalize(payload) == payload_raw == canonicalize(record["payload"]), kind + " payload JCS")
    require(sha(payload_raw) == envelope["payload_sha256"], kind + " payload digest")
    require(schemas[FAMILY + payload_name + ".schema.json"].is_valid(payload), kind + " payload shape")
    Ed25519PublicKey.from_public_bytes(public).verify(
        decode(envelope["signature_base64url"]), envelope["purpose"].encode() + b"\0" + payload_raw)


def check_tuple(vector, schemas):
    public = decode(vector["machine_public_key_base64url"])
    require(vector["source_c4_sha256"] ==
            "sha256:bca0837385815cefc86b1158e7aad564f1885721e24670e415d3dae41ddbf167",
            "exact private source pin")
    for kind in ("reservation", "assignment", "policy", "authorization"):
        check_signed(vector[kind], kind, schemas, public)

    reservation = vector["reservation"]
    assignment = vector["assignment"]
    policy = vector["policy"]
    auth = vector["authorization"]
    r, a, b, ap = (vector[name]["payload"] for name in ("reservation", "assignment", "policy", "authorization"))
    r_ref = r["measurement_binding"]["r_inventory"]
    require(r_ref["kind"] == "stage2a-inventory-ref" and
            r_ref["sidecar"]["mode"] == "0440" and
            r_ref["snapshot"]["mode"] == "0555", "sealed v3 R reference shape")
    outer = r["assignment"]
    fd3 = vector["b_fd3"]
    selectors = fd3["selectors"]
    local = b["local_test"]
    core = vector["ingress_core"]
    reply = vector["ingress_reply"]
    result = reply["result"]
    provider = result["provider"]
    ack = vector["completion_ack"]["result"]

    require(len(a["members"]) == len(b["members"]) == 2 and
            [row["role"] for row in a["members"]] == ["lead", "specialist"], "two ordered members")
    require(b["members"][1]["qualification"] == {"mode": "disabled"}, "sibling disabled")
    require(b["outer_launch_id"] == selectors["launch_id"] == outer["launch_id"] and
            b["outer_launch_id"] != a["members"][0]["launch_id"], "distinct exact outer launch")
    require(a["reservation_sha256"] == b["reservation_sha256"] == selectors["reservation_digest"] ==
            reservation["envelope_sha256"], "reservation join")
    require(a["b_authority"] == b["b_authority"] ==
            {"purpose": reservation["purpose"], "envelope_sha256": reservation["envelope_sha256"]},
            "primary B authority")
    require(b["member_set_assignment_envelope_sha256"] == selectors["assignment_envelope_sha256"] ==
            assignment["envelope_sha256"] and selectors["authority_envelope_sha256"] ==
            policy["envelope_sha256"], "assignment and policy joins")
    require(b["owner_plan_member_set_sha256"] == a["owner_plan_member_set_sha256"] and
            [row["member_selector"] for row in a["members"]] ==
            [row["member_selector"] for row in b["members"]], "member set join")
    require(selectors["member_selectors_sha256"] == sha(canonicalize(
            [row["member_selector"] for row in a["members"]])), "selector digest")
    for field in ("installation_id", "plan_id", "plan_digest", "start_id"):
        require(selectors[field] == a[field] == b[field], field + " selector join")
    require(local["selected_member_id"] == a["members"][0]["member_id"] and
            local["selected_launch_id"] == a["members"][0]["launch_id"] and
            local["selected_member_selector"] == a["members"][0]["member_selector"],
            "selected lead")
    require(b["members"][0]["qualification"]["response_text_sha256"] ==
            provider["response_sha256"] == sha(provider["response_text"].encode()),
            "A policy binds UTF-8 Provider text")
    require(b["members"][0]["qualification"]["model"] == local["model"] == provider["model"] and
            b["members"][0]["qualification"]["mode"] == provider["mode"], "Provider mode and model")
    require(local["header_shape_sha256"] == sha(canonicalize(local["header_shape"])) and
            local["ancillary_profile_sha256"] == sha(canonicalize(local["ancillary_profile"])),
            "header and ancillary pins")
    require(fd3["local_test"] == local and
            decode(fd3["assignment_envelope_base64url"]) == decode(assignment["envelope_base64url"]) and
            decode(fd3["authority_envelope_base64url"]) == decode(policy["envelope_base64url"]),
            "FD3 carries exact signed records")
    require(len(canonicalize(fd3)) <= 32768 and
            schemas[FAMILY + "stage2a-b-fd3.schema.json"].is_valid(fd3), "bounded FD3 shape")
    require(core["selectors"] == ap["selectors"] == ack["selectors"] == selectors and
            ap["ingress_core_sha256"] == result["ingress_core_sha256"] == sha(canonicalize(core)),
            "signed ingress core and selectors")
    require(result["authorization_envelope_sha256"] == ack["authorization_envelope_sha256"] ==
            auth["envelope_sha256"] and decode(result["authorization_envelope_base64url"]) ==
            decode(auth["envelope_base64url"]), "HQ reply exact A authorization")
    request = {"mode": provider["mode"], "model": provider["model"],
               "observed_body_sha256": provider["observed_body_sha256"]}
    require(result["provider_request_body_sha256"] == sha(canonicalize(request)) and
            result["provider_response_body_sha256"] == sha(canonicalize(provider)) and
            provider["observed_body_sha256"] == core["observed_body_sha256"] ==
            ack["observed_body_sha256"], "Provider request, response and body joins")
    require(reply["id"] == "ingress" and reply["ok"] is True and
            vector["completion_ack"]["id"] == "complete" and
            vector["completion_ack"]["ok"] is True and ack["accepted"] is True,
            "exact positive reply and completion ack")
    require(schemas["hq/v1/stage2a-local-test-ingress-reply.schema.json"].is_valid(reply) and
            schemas["hq/v1/stage2a-local-test-completion-ack.schema.json"].is_valid(vector["completion_ack"]),
            "HQ reply and ack shapes")
    require(when(core["target_received_at"]) <= when(ap["issued_at"]) < when(ap["expires_at"]) <=
            when(r["expires_at"]) and when(ap["expires_at"]) - when(ap["issued_at"]) <=
            timedelta(seconds=30), "live bounded authorization")


def check_prewrite(vector, fixture, schemas, used_receipts=()):
    public = decode(vector["machine_public_key_base64url"])
    proof = fixture["proof"]
    check_signed(proof, "proof", schemas, public)
    reply = fixture["prewrite_reply"]
    payload = proof["payload"]
    prewrite = fixture["prewrite_core"]
    wire = fixture["response_wire_utf8"].encode()
    auth = vector["authorization"]
    policy = vector["policy"]
    require(schemas[FAMILY + "stage2a-prewrite-core.schema.json"].is_valid(prewrite),
            "prewrite core closed shape")
    require(schemas["hq/v1/stage2a-local-test-prewrite-reply.schema.json"].is_valid(reply) and
            reply == {"prewrite_receipt": payload["prewrite_receipt"],
                      "prewrite_proof_envelope_base64url": proof["envelope_base64url"],
                      "prewrite_proof_envelope_sha256": proof["envelope_sha256"]},
            "HQ forwards exact A proof and receipt")
    require(payload["prewrite_receipt"] not in used_receipts,
            "A-signed prewrite receipt is consumed once before first byte")
    require(prewrite["response_wire_bytes"] == len(wire) and
            prewrite["response_wire_sha256"] == sha(wire) and
            prewrite["http_status"] == 200, "exact prepared response wire")
    require(payload["prewrite_core_sha256"] == sha(canonicalize(prewrite)) and
            payload["selectors"] == prewrite["selectors"] == vector["b_fd3"]["selectors"],
            "A proof binds exact B prewrite core and selectors")
    require(payload["hq_epoch"] == policy["payload"]["hq_epoch"] == vector["b_fd3"]["hq_epoch"] and
            payload["authorization_envelope_sha256"] == prewrite["authorization_envelope_sha256"] ==
            auth["envelope_sha256"], "A proof binds epoch and authorization")
    require(prewrite["ingress_core_sha256"] == sha(canonicalize(vector["ingress_core"])) and
            prewrite["observed_body_sha256"] == vector["ingress_core"]["observed_body_sha256"],
            "A proof binds request body and ingress")
    ingress = vector["ingress_core"]
    require(prewrite["peer_sha256"] == sha(canonicalize(prewrite["peer"])) and
            ingress["peer_sha256"] == sha(canonicalize(ingress["peer"])),
            "prewrite and ingress peer digests are recomputed")
    require(prewrite["peer"] == ingress["peer"] and
            all(prewrite[field] == ingress[field] for field in
                ("peer_sha256", "bind_receipt_sha256", "observed_headers_sha256",
                 "owner_prompt_sha256", "static_projection_sha256")),
            "prewrite core repeats signed ingress peer and request evidence")
    require(when(auth["payload"]["issued_at"]) <= when(payload["issued_at"]) <
            when(payload["expires_at"]) <=
            min(when(auth["payload"]["expires_at"]), when(policy["payload"]["expires_at"]),
                when(vector["reservation"]["payload"]["expires_at"])) and
            when(payload["expires_at"]) - when(payload["issued_at"]) <= timedelta(seconds=30),
            "A proof expires no later than authorization and policy")
    # A production verifier also compares the current clock immediately
    # before first byte; the fixture's fixed time models an in-window proof.
    require(when(payload["issued_at"]) <= when("2026-11-24T12:00:13Z") <
            when(payload["expires_at"]), "proof live at synthetic first byte")


def resign_proof(record):
    """Create a valid A signature around a semantically inconsistent mutant."""
    key = Ed25519PrivateKey.from_private_bytes(bytes([0x43]) * 32)
    payload_raw = canonicalize(record["payload"])
    envelope = record["envelope"]
    envelope["payload_base64url"] = base64.urlsafe_b64encode(payload_raw).rstrip(b"=").decode()
    envelope["payload_sha256"] = sha(payload_raw)
    envelope["signature_base64url"] = base64.urlsafe_b64encode(
        key.sign(record["purpose"].encode() + b"\0" + payload_raw)).rstrip(b"=").decode()
    envelope_raw = canonicalize(envelope)
    record["envelope_base64url"] = base64.urlsafe_b64encode(envelope_raw).rstrip(b"=").decode()
    record["envelope_sha256"] = sha(envelope_raw)


def resign_prewrite_core(fixture):
    fixture["proof"]["payload"]["prewrite_core_sha256"] = sha(canonicalize(fixture["prewrite_core"]))
    resign_proof(fixture["proof"])
    fixture["prewrite_reply"]["prewrite_proof_envelope_base64url"] = fixture["proof"]["envelope_base64url"]
    fixture["prewrite_reply"]["prewrite_proof_envelope_sha256"] = fixture["proof"]["envelope_sha256"]


def check_stage2a_local_test_fixtures(root, schemas, report):
    vector = json.loads((root / "fixtures/stage2a-local-test/v1/neutral-tuple.json").read_text())
    try:
        check_tuple(vector, schemas)
        report(True, "neutral local-test signed tuple, joins, reply and ack")
    except Exception as exc:  # noqa: BLE001
        report(False, "neutral local-test signed tuple, joins, reply and ack", str(exc))
        return

    mutations = {
        "wrong outer launch": ("policy", "payload", "outer_launch_id"),
        "wrong selected lead": ("policy", "payload", "local_test", "selected_member_id"),
        "wrong reservation digest": ("b_fd3", "selectors", "reservation_digest"),
        "wrong assignment digest": ("b_fd3", "selectors", "assignment_envelope_sha256"),
        "wrong policy digest": ("b_fd3", "selectors", "authority_envelope_sha256"),
        "wrong signed purpose": ("authorization", "envelope", "purpose"),
        "wrong ingress core": ("ingress_core", "attempt_id"),
        "wrong provider text": ("ingress_reply", "result", "provider", "response_text"),
        "wrong provider response digest": ("ingress_reply", "result", "provider_response_body_sha256"),
        "wrong authorization digest": ("ingress_reply", "result", "authorization_envelope_sha256"),
        "wrong completion selector": ("completion_ack", "result", "selectors", "launch_id"),
        "wrong completion authorization": ("completion_ack", "result", "authorization_envelope_sha256"),
    }
    for label, path in mutations.items():
        changed = copy.deepcopy(vector)
        node = changed
        for key in path[:-1]:
            node = node[key]
        old = node[path[-1]]
        node[path[-1]] = "invalid" if isinstance(old, str) else not old
        try:
            check_tuple(changed, schemas)
            report(False, "neutral local-test refusal: " + label, "accepted mutant")
        except Exception:  # noqa: BLE001
            report(True, "neutral local-test refusal: " + label)

    prewrite = json.loads((root / "fixtures/stage2a-local-test/v1/prewrite-proof.json").read_text())
    try:
        check_prewrite(vector, prewrite, schemas)
        report(True, "proposed Machine-signed prewrite proof before first byte")
    except Exception as exc:  # noqa: BLE001
        report(False, "proposed Machine-signed prewrite proof before first byte", str(exc))
        return
    proof_mutations = {
        "wrong core digest": ("prewrite_core_sha256", "sha256:" + "0" * 64),
        "wrong authorization": ("authorization_envelope_sha256", "sha256:" + "0" * 64),
        "wrong epoch": ("hq_epoch", "0" * 64),
        "wrong selector": ("selectors", {**prewrite["proof"]["payload"]["selectors"],
                                          "launch_id": "ln_" + "0" * 24}),
        "proof predates authorization": ("issued_at", "2026-11-24T12:00:10Z"),
        "expired before first byte": ("expires_at", "2026-11-24T12:00:13Z"),
        "expiry beyond authorization": ("expires_at", "2026-11-24T12:00:17Z"),
    }
    for label, (field, value) in proof_mutations.items():
        changed = copy.deepcopy(prewrite)
        changed["proof"]["payload"][field] = value
        resign_proof(changed["proof"])
        changed["prewrite_reply"] = {
            "prewrite_receipt": changed["proof"]["payload"]["prewrite_receipt"],
            "prewrite_proof_envelope_base64url": changed["proof"]["envelope_base64url"],
            "prewrite_proof_envelope_sha256": changed["proof"]["envelope_sha256"]}
        try:
            check_prewrite(vector, changed, schemas)
            report(False, "prewrite zero-write refusal: " + label, "accepted signed mutant")
        except Exception:  # noqa: BLE001
            report(True, "prewrite zero-write refusal: " + label)
    for label, field in (("peer", "peer"), ("peer digest", "peer_sha256"),
                         ("bind receipt", "bind_receipt_sha256"),
                         ("headers", "observed_headers_sha256"),
                         ("prompt", "owner_prompt_sha256"),
                         ("static projection", "static_projection_sha256")):
        changed = copy.deepcopy(prewrite)
        if field == "peer":
            changed["prewrite_core"]["peer"]["pid"] += 1
            changed["prewrite_core"]["peer_sha256"] = sha(canonicalize(changed["prewrite_core"]["peer"]))
        else:
            changed["prewrite_core"][field] = "sha256:" + "0" * 64
        resign_prewrite_core(changed)
        reason = ("prewrite and ingress peer digests are recomputed" if field == "peer_sha256" else
                  "prewrite core repeats signed ingress peer and request evidence")
        try:
            check_prewrite(vector, changed, schemas)
        except ValueError as exc:
            report(str(exc) == reason, "prewrite signed ingress mismatch refusal: " + label,
                   "refused for a different reason: " + str(exc))
        else:
            report(False, "prewrite signed ingress mismatch refusal: " + label,
                   "accepted re-signed prewrite mutant")
    receipt = prewrite["proof"]["payload"]["prewrite_receipt"]
    for label, changed in (("identical proof replay", copy.deepcopy(prewrite)),
                           ("re-signed proof receipt replay", copy.deepcopy(prewrite))):
        if label.startswith("re-signed"):
            changed["proof"]["payload"]["issued_at"] = "2026-11-24T12:00:12.500Z"
            resign_proof(changed["proof"])
            changed["prewrite_reply"]["prewrite_proof_envelope_base64url"] = changed["proof"]["envelope_base64url"]
            changed["prewrite_reply"]["prewrite_proof_envelope_sha256"] = changed["proof"]["envelope_sha256"]
        try:
            check_prewrite(vector, changed, schemas, {receipt})
        except ValueError as exc:
            report(str(exc) == "A-signed prewrite receipt is consumed once before first byte",
                   "prewrite one-use refusal: " + label, "refused for a different reason: " + str(exc))
        else:
            report(False, "prewrite one-use refusal: " + label, "accepted spent receipt")
    for label, path in (("forged A signature", ("proof", "envelope", "signature_base64url")),
                        ("altered response wire", ("response_wire_utf8",)),
                        ("altered observed body", ("prewrite_core", "observed_body_sha256")),
                        ("altered wire digest", ("prewrite_core", "response_wire_sha256")),
                        ("forged HQ receipt", ("prewrite_reply", "prewrite_receipt"))):
        changed = copy.deepcopy(prewrite)
        node = changed
        for key in path[:-1]:
            node = node[key]
        if label == "forged A signature":
            node[path[-1]] = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
            envelope_raw = canonicalize(changed["proof"]["envelope"])
            changed["proof"]["envelope_base64url"] = base64.urlsafe_b64encode(
                envelope_raw).rstrip(b"=").decode()
            changed["proof"]["envelope_sha256"] = sha(envelope_raw)
            changed["prewrite_reply"]["prewrite_proof_envelope_base64url"] = changed["proof"]["envelope_base64url"]
            changed["prewrite_reply"]["prewrite_proof_envelope_sha256"] = changed["proof"]["envelope_sha256"]
        else:
            node[path[-1]] = "sha256:" + "0" * 64 if label.startswith("altered ") and len(path) > 1 else "invalid"
        try:
            check_prewrite(vector, changed, schemas)
            report(False, "prewrite zero-write refusal: " + label, "accepted mutant")
        except Exception:  # noqa: BLE001
            report(True, "prewrite zero-write refusal: " + label)
