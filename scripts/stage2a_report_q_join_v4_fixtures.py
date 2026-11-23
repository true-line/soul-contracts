"""Source-only exact-byte Q and completion joins for the draft report successor."""

import base64
import copy
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes

from jcs import canonicalize, parse_strict
from stage2a_q_presign_fixtures import verify as verify_q

KEY = Ed25519PrivateKey.from_private_bytes(b"\x13" * 32)
COMPLETION_PURPOSE = "agent-bot/stage2a-execution-completion/v2"


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def require(ok, label):
    if not ok:
        raise ValueError(label)


def authenticated_payload(envelope_jcs, purpose, version, key):
    raw = envelope_jcs.encode()
    require(canonicalize(parse_strict(raw)) == raw, "canonical envelope")
    envelope = parse_strict(raw)
    require(envelope["schema_version"] == version and envelope["purpose"] == purpose,
            "purpose and version")
    require(decode(envelope["issuer_public_key_base64url"]) == key, "same enrolled Machine key")
    payload_raw = decode(envelope["payload_base64url"])
    require(canonicalize(parse_strict(payload_raw)) == payload_raw and
            envelope["payload_sha256"] == sha(payload_raw), "canonical signed payload")
    Ed25519PublicKey.from_public_bytes(key).verify(
        decode(envelope["signature_base64url"]), purpose.encode() + b"\0" + payload_raw)
    return parse_strict(payload_raw)


def joined(run, schemas):
    report = run["report"]
    completion = run["completion"]
    profile = report["profile_in_force"]
    require(schemas["adapter/v4/qualification-host-report.schema.json"].is_valid(report), "report shape")
    require(schemas["machine/v2/stage2a-execution-completion-payload.schema.json"].is_valid(completion),
            "completion shape")
    key = decode(run["issuer_public_key_base64url"])
    q = {"issuer_public_key_base64url": run["issuer_public_key_base64url"],
         "wire_jcs": run["q_wire_jcs"], "index_envelope_jcs": run["q_index_envelope_jcs"],
         "eof_envelope_jcs": run["q_eof_envelope_jcs"]}
    verify_q(q, schemas)
    idx = authenticated_payload(run["q_index_envelope_jcs"],
                                "agent-bot/stage2a-q-frame-index/v1", 1, key)
    authenticated_payload(run["q_eof_envelope_jcs"],
                          "agent-bot/stage2a-q-finished-eof/v1", 1, key)
    reservation_purpose = ("agent-bot/soul-cooperative-reservation/v3"
                           if profile == "managed-cooperative" else "agent-bot/stage2a-reservation/v3")
    reservation = authenticated_payload(run["reservation_envelope_jcs"], reservation_purpose, 3, key)
    reservation_schema = ("machine/v3/soul-cooperative-reservation-payload.schema.json"
                          if profile == "managed-cooperative" else
                          "machine/v3/stage2a-reservation-payload.schema.json")
    require(schemas[reservation_schema].is_valid(reservation), "released reservation schema")
    refs = report["run_evidence"]
    evidence = [refs["reservation"], refs["execution_completion"], *refs["q_session"].values()]
    evidence.extend(refs[name] for name in ("finalization", "bridge_assignment", "cooperative_order_receipt")
                    if name in refs)
    require(len({value["uri"] for value in evidence}) == len(evidence) and
            len({value["sha256"] for value in evidence}) == len(evidence),
            "distinct exact-byte evidence references")
    blobs = {"reservation": run["reservation_envelope_jcs"].encode(),
             "framed_wire": run["q_wire_jcs"].encode(),
             "frame_index_envelope": run["q_index_envelope_jcs"].encode(),
             "clean_eof_envelope": run["q_eof_envelope_jcs"].encode(),
             "execution_completion": run["completion_envelope_jcs"].encode()}
    for name in ("framed_wire", "frame_index_envelope", "clean_eof_envelope"):
        require(refs["q_session"][name]["sha256"] == sha(blobs[name]), "exact Q " + name)
    require(refs["reservation"]["sha256"] == sha(blobs["reservation"]) == idx["reservation_sha256"],
            "one signed reservation")
    require(refs["execution_completion"]["sha256"] == sha(blobs["execution_completion"]),
            "exact completion envelope")
    require(idx["profile"] == profile == completion["profile_in_force"] ==
            reservation["measurement_binding"]["profile_in_force"], "profile join")
    binding = report["measurement_binding"]
    require(binding == reservation["measurement_binding"], "signed measurement binding")
    require(refs["challenge_sha256"] == completion["challenge_sha256"] ==
            reservation["admission_challenge_sha256"] == idx["launch_challenge_sha256"],
            "launch challenge")
    for signed, in_report in (("host_id", "host_id"), ("installation_id", "installation_id"),
                              ("soul_id", "soul_id"), ("start_id", "start_id")):
        require(idx[signed] == completion[signed] == binding[in_report], signed + " join")
    require(idx["host_id"] == report["host"]["id"] and idx["cohort_id"] == completion["cohort_id"],
            "host and cohort")
    require(completion["launch_id"] == binding["launch_id"] and
            completion["reservation_sha256"] == refs["reservation"]["sha256"] and
            completion["measurement_binding_sha256"] == sha(canonicalize(binding)),
            "completion identity and binding")
    for field in ("framed_wire", "frame_index_envelope", "clean_eof_envelope"):
        require(completion["q_" + field + "_sha256"] == refs["q_session"][field]["sha256"],
                "completion Q " + field)
    candidate = copy.deepcopy(report)
    del candidate["run_evidence"]["execution_completion"]
    require(completion["report_candidate_sha256"] == sha(canonicalize(candidate)),
            "acyclic pre-sign report candidate")
    require(authenticated_payload(run["completion_envelope_jcs"], COMPLETION_PURPOSE, 2, key) == completion,
            "A-signed completion")
    host = run["host_signature_envelope"]
    require(schemas["adapter/v4/qualification-host-signature.schema.json"].is_valid(host),
            "host signature shape")
    report_raw = canonicalize(report)
    host_purpose = "agent-bot/qualification-host-report/v4"
    require(host["purpose"] == host_purpose and host["host_id"] == report["host"]["id"] and
            decode(host["report_base64url"]) == report_raw and host["report_sha256"] == sha(report_raw),
            "exact host signed report")
    raw_signature = decode(host["signature_base64url"])
    require(len(raw_signature) == 64, "raw ES256 signature")
    der = encode_dss_signature(int.from_bytes(raw_signature[:32], "big"),
                               int.from_bytes(raw_signature[32:], "big"))
    ec.derive_private_key(1, ec.SECP256R1()).public_key().verify(
        der, host_purpose.encode() + b"\0" + report_raw, ec.ECDSA(hashes.SHA256()))
    if profile == "managed-cooperative":
        require(reservation["adapter_transport"] == "brokered-b", "B transport")
        bridge = authenticated_payload(run["bridge_assignment_envelope_jcs"],
                                       "agent-bot/soul-cooperative-bridge-assignment/v3", 3, key)
        require(schemas["machine/v3/soul-cooperative-bridge-assignment-payload.schema.json"].is_valid(bridge),
                "released B assignment schema")
        require(bridge["reservation_sha256"] == refs["reservation"]["sha256"] and
                refs["bridge_assignment"]["sha256"] == sha(run["bridge_assignment_envelope_jcs"].encode()) ==
                completion["bridge_assignment_sha256"], "private B assignment")
        require(refs["cooperative_order_receipt"]["sha256"] ==
                completion["cooperative_order_receipt_sha256"], "order receipt reference")
        require("finalization" not in refs and "finalization_sha256" not in completion,
                "no protected finalization in T21")
    else:
        require(refs["finalization"]["sha256"] == completion["finalization_sha256"] and
                "bridge_assignment" not in refs and "cooperative_order_receipt" not in refs,
                "protected finalization only")


def check_stage2a_report_q_join_v4_fixtures(root, schemas, report):
    vector = json.loads((root / "fixtures/qualification/v4/report-q-join-synthetic.json").read_text())
    for name, run in vector.items():
        try:
            joined(run, schemas)
            report(True, "draft report/Q exact signed join " + name)
        except (ValueError, KeyError, TypeError, InvalidSignature) as exc:
            report(False, "draft report/Q exact signed join " + name, str(exc))
    for label, change in (
        ("changed signed Q index ref", lambda r: r["report"]["run_evidence"]["q_session"]["frame_index_envelope"].update(sha256="sha256:" + "0" * 64)),
        ("cross-profile Q replay", lambda r: r.update(q_wire_jcs=vector["protected"]["q_wire_jcs"],
                                                   q_index_envelope_jcs=vector["protected"]["q_index_envelope_jcs"],
                                                   q_eof_envelope_jcs=vector["protected"]["q_eof_envelope_jcs"])),
        ("protected receipt in T21", lambda r: r["report"]["run_evidence"].update(
            finalization=r["report"]["run_evidence"].pop("cooperative_order_receipt"))),
        ("duplicate Q evidence URI", lambda r: r["report"]["run_evidence"]["q_session"]["clean_eof_envelope"].update(
            uri=r["report"]["run_evidence"]["q_session"]["frame_index_envelope"]["uri"])),
    ):
        bad = copy.deepcopy(vector["cooperative"])
        change(bad)
        try:
            joined(bad, schemas)
            report(False, "draft report/Q refuses " + label)
        except (ValueError, KeyError, TypeError, InvalidSignature):
            report(True, "draft report/Q refuses " + label)
    for label, field in (("changed host signature", "host_signature_envelope"),
                         ("changed A completion signature", "completion_envelope_jcs")):
        bad = copy.deepcopy(vector["protected"])
        if field == "host_signature_envelope":
            bad[field]["signature_base64url"] = "A" * 86
        else:
            envelope = parse_strict(bad[field].encode())
            envelope["signature_base64url"] = "A" * 86
            bad[field] = canonicalize(envelope).decode()
        try:
            joined(bad, schemas)
            report(False, "draft report/Q refuses " + label)
        except (ValueError, KeyError, TypeError, InvalidSignature):
            report(True, "draft report/Q refuses " + label)
