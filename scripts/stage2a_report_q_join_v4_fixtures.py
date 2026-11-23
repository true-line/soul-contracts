"""Source-only exact-byte Q and completion joins for the draft report successor."""

import base64
import copy
import hashlib
import json
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes

from jcs import canonicalize, parse_strict
from generate_stage2a_report_q_join_v4_synthetic import HOST_KEY as FIXTURE_HOST_KEY, sign as fixture_sign
from stage2a_q_presign_fixtures import verify as verify_q

KEY = Ed25519PrivateKey.from_private_bytes(b"\x13" * 32)
COMPLETION_PURPOSE = "agent-bot/stage2a-execution-completion/v2"
COMMITMENT_PURPOSE = "agent-bot/stage2a-report-commitment/v2"


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


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


def reseal_fixture_run(run):
    """Re-sign every downstream fixture edge after a changed source payload."""
    report = run["report"]
    completion = run["completion"]
    refs = report["run_evidence"]
    if report["profile_in_force"] == "managed-cooperative":
        for kind in ("order", "outcome"):
            name = "cooperative_publish_" + kind
            raw = fixture_sign(run[name + "_payload"],
                               "agent-bot/soul-cooperative-publish-" + kind + "/v3", 3)
            run[name + "_envelope_jcs"] = raw.decode()
            refs[name]["sha256"] = sha(raw)
            completion[name + "_sha256"] = sha(raw)
    else:
        raw = fixture_sign(run["protected_finalization_payload"],
                           "agent-bot/stage2a-finalization/v1", 1)
        run["protected_finalization_envelope_jcs"] = raw.decode()
        refs["finalization"]["sha256"] = sha(raw)
        completion["finalization_sha256"] = sha(raw)
    candidate = copy.deepcopy(report)
    del candidate["run_evidence"]["execution_completion"]
    completion["report_candidate_sha256"] = sha(canonicalize(candidate))
    completion_raw = fixture_sign(completion, COMPLETION_PURPOSE, 2)
    run["completion_envelope_jcs"] = completion_raw.decode()
    refs["execution_completion"]["sha256"] = sha(completion_raw)
    report_raw = canonicalize(report)
    purpose = "agent-bot/qualification-host-report/v4"
    der = FIXTURE_HOST_KEY.sign(purpose.encode() + b"\0" + report_raw,
                                ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    host = run["host_signature_envelope"]
    host["report_sha256"] = sha(report_raw)
    host["report_base64url"] = encode(report_raw)
    host["signature_base64url"] = encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    commitment = run["commitment"]
    commitment["execution_completion_sha256"] = sha(completion_raw)
    commitment["report_payload_sha256"] = sha(report_raw)
    commitment["report_envelope_sha256"] = sha(canonicalize(host))
    run["commitment_envelope_jcs"] = fixture_sign(commitment, COMMITMENT_PURPOSE, 2).decode()


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
    evidence.extend(refs[name] for name in ("finalization", "bridge_assignment", "cooperative_publish_order",
                                           "cooperative_publish_outcome", "cooperative_watched_request")
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
    commitment = run["commitment"]
    require(schemas["machine/v2/stage2a-report-commitment-payload.schema.json"].is_valid(commitment),
            "post-sign commitment shape")
    require(authenticated_payload(run["commitment_envelope_jcs"], COMMITMENT_PURPOSE, 2, key) ==
            commitment, "A-signed post-sign commitment")
    require(commitment["profile_in_force"] == profile and
            commitment["host_id"] == host["host_id"] == report["host"]["id"] and
            commitment["signer_id"] == host["signer_id"] and
            commitment["execution_completion_sha256"] == sha(blobs["execution_completion"]) and
            commitment["report_payload_sha256"] == sha(report_raw) and
            commitment["report_envelope_sha256"] == sha(canonicalize(host)),
            "exact post-sign host envelope and pre-sign completion")
    for name in ("installation_id", "soul_id", "start_id", "launch_id", "cohort_id"):
        require(commitment[name] == completion[name], name + " post-sign identity")
    committed_at = datetime.fromisoformat(commitment["committed_at"].replace("Z", "+00:00"))
    recorded_at = datetime.fromisoformat(report["recorded_at"].replace("Z", "+00:00"))
    completed_at = datetime.fromisoformat(completion["completed_at"].replace("Z", "+00:00"))
    require(completed_at <= recorded_at <= committed_at, "pre-sign/report/post-sign order")
    if profile == "managed-cooperative":
        require(reservation["adapter_transport"] == "brokered-b", "B transport")
        bridge = authenticated_payload(run["bridge_assignment_envelope_jcs"],
                                       "agent-bot/soul-cooperative-bridge-assignment/v3", 3, key)
        require(schemas["machine/v3/soul-cooperative-bridge-assignment-payload.schema.json"].is_valid(bridge),
                "released B assignment schema")
        require(bridge["reservation_sha256"] == refs["reservation"]["sha256"] and
                refs["bridge_assignment"]["sha256"] == sha(run["bridge_assignment_envelope_jcs"].encode()) ==
                completion["bridge_assignment_sha256"], "private B assignment")
        order_raw = run["cooperative_publish_order_envelope_jcs"].encode()
        outcome_raw = run["cooperative_publish_outcome_envelope_jcs"].encode()
        order = authenticated_payload(run["cooperative_publish_order_envelope_jcs"],
                                      "agent-bot/soul-cooperative-publish-order/v3", 3, key)
        outcome = authenticated_payload(run["cooperative_publish_outcome_envelope_jcs"],
                                        "agent-bot/soul-cooperative-publish-outcome/v3", 3, key)
        require(schemas["machine/v3/soul-cooperative-publish-order-payload.schema.json"].is_valid(order),
                "signed B order schema")
        require(schemas["machine/v3/soul-cooperative-publish-outcome-payload.schema.json"].is_valid(outcome),
                "signed B outcome schema")
        require(order == run["cooperative_publish_order_payload"] and
                outcome == run["cooperative_publish_outcome_payload"], "signed B payloads")
        require(refs["cooperative_publish_order"]["sha256"] == sha(order_raw) ==
                completion["cooperative_publish_order_sha256"] and
                refs["cooperative_publish_outcome"]["sha256"] == sha(outcome_raw) ==
                completion["cooperative_publish_outcome_sha256"], "both exact B envelopes")
        require(order["reservation_sha256"] == outcome["reservation_sha256"] ==
                refs["reservation"]["sha256"] and
                order["bridge_assignment_sha256"] == outcome["bridge_assignment_sha256"] ==
                refs["bridge_assignment"]["sha256"] and
                outcome["order_sha256"] == sha(order_raw), "B order to outcome chain")
        for identity in ("installation_id", "start_id", "launch_id"):
            require(order[identity] == outcome[identity] == completion[identity], identity + " B publication")
        request_raw = run["cooperative_watched_request_jcs"].encode()
        request_identity = run["cooperative_watched_request_identity"]
        require(canonicalize(parse_strict(request_raw)) == request_raw and
                refs["cooperative_watched_request"]["sha256"] == sha(request_raw) ==
                outcome["request_sha256"], "exact watched request bytes")
        for name in ("device", "inode", "birthtime_ns"):
            require(request_identity[name] == outcome["request_" + name],
                    "observed watched request " + name)
        require(request_identity["mode"] == "0640" and
                request_identity["owner_uid"] == reservation["assignment"]["machine_uid"] and
                request_identity["group_gid"] == reservation["assignment"]["runner_gid"],
                "watched request owner and R group")
        authorized = datetime.fromisoformat(order["authorized_at"].replace("Z", "+00:00"))
        published = datetime.fromisoformat(outcome["published_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(outcome["expires_at"].replace("Z", "+00:00"))
        reserved_expires = datetime.fromisoformat(reservation["expires_at"].replace("Z", "+00:00"))
        require(authorized <= published < expires == reserved_expires and
                outcome["publication_mode"] == "direct",
                "authorized publication before reservation expiry")
        require("finalization" not in refs and "finalization_sha256" not in completion,
                "no protected finalization in T21")
    else:
        finalization_raw = run["protected_finalization_envelope_jcs"].encode()
        finalization = authenticated_payload(run["protected_finalization_envelope_jcs"],
                                             "agent-bot/stage2a-finalization/v1", 1, key)
        require(finalization == run["protected_finalization_payload"] and
                finalization["schema"] == "agent-bot-machine/stage2a-finalization/v1" and
                finalization["reservation_sha256"] == refs["reservation"]["sha256"] and
                finalization["installation_id"] == completion["installation_id"] and
                finalization["start_id"] == completion["start_id"] and
                finalization["launch_id"] == completion["launch_id"], "A-signed protected finalization")
        require(refs["finalization"]["sha256"] == sha(finalization_raw) ==
                completion["finalization_sha256"] and
                "bridge_assignment" not in refs and "cooperative_publish_order" not in refs and
                "cooperative_publish_outcome" not in refs and "cooperative_watched_request" not in refs,
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
            finalization=r["report"]["run_evidence"].pop("cooperative_publish_outcome"))),
        ("missing B publication outcome", lambda r: r["report"]["run_evidence"].pop("cooperative_publish_outcome")),
        ("swapped B order and outcome refs", lambda r: r["report"]["run_evidence"].update(
            cooperative_publish_order=r["report"]["run_evidence"]["cooperative_publish_outcome"],
            cooperative_publish_outcome=r["report"]["run_evidence"]["cooperative_publish_order"])),
        ("changed B outcome signature", lambda r: r.update(
            cooperative_publish_outcome_envelope_jcs=canonicalize({**parse_strict(r["cooperative_publish_outcome_envelope_jcs"].encode()),
                "signature_base64url": "A" * 86}).decode())),
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
                         ("changed A completion signature", "completion_envelope_jcs"),
                         ("changed A post-sign signature", "commitment_envelope_jcs")):
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
    for label, mutation in (
        ("re-signed commitment for other host envelope",
         lambda c: c.update(report_envelope_sha256="sha256:" + "0" * 64)),
        ("re-signed commitment for other completion",
         lambda c: c.update(execution_completion_sha256="sha256:" + "0" * 64)),
        ("re-signed commitment for other host",
         lambda c: c.update(host_id="other-host")),
        ("re-signed commitment before report",
         lambda c: c.update(committed_at="2026-11-22T14:15:25Z")),
    ):
        bad = copy.deepcopy(vector["protected"])
        mutation(bad["commitment"])
        bad["commitment_envelope_jcs"] = fixture_sign(bad["commitment"], COMMITMENT_PURPOSE, 2).decode()
        try:
            joined(bad, schemas)
            report(False, "draft report/Q refuses " + label)
        except (ValueError, KeyError, TypeError, InvalidSignature):
            report(True, "draft report/Q refuses " + label)
    coherent_changes = (
        ("re-signed protected finalization for another reservation", "protected",
         lambda r: r["protected_finalization_payload"].update(reservation_sha256="sha256:" + "0" * 64)),
        ("re-signed B outcome for another order", "cooperative",
         lambda r: r["cooperative_publish_outcome_payload"].update(order_sha256="sha256:" + "0" * 64)),
        ("re-signed B outcome for other watched bytes", "cooperative",
         lambda r: r["cooperative_publish_outcome_payload"].update(request_sha256="sha256:" + "0" * 64)),
        ("re-signed B outcome for other watched inode", "cooperative",
         lambda r: r["cooperative_publish_outcome_payload"].update(request_inode="12346")),
        ("watched request for other owner", "cooperative",
         lambda r: r["cooperative_watched_request_identity"].update(owner_uid=502)),
        ("watched request for other group", "cooperative",
         lambda r: r["cooperative_watched_request_identity"].update(group_gid=332)),
        ("re-signed B outcome before authorization", "cooperative",
         lambda r: r["cooperative_publish_outcome_payload"].update(published_at="2026-11-22T14:15:17Z")),
        ("re-signed B outcome at expiry", "cooperative",
         lambda r: r["cooperative_publish_outcome_payload"].update(
             published_at=r["cooperative_publish_outcome_payload"]["expires_at"])),
        ("re-signed unsupported recovered publication", "cooperative",
         lambda r: r["cooperative_publish_outcome_payload"].update(publication_mode="recovered")),
    )
    for label, profile, change in coherent_changes:
        bad = copy.deepcopy(vector[profile])
        change(bad)
        reseal_fixture_run(bad)
        try:
            joined(bad, schemas)
            report(False, "draft report/Q refuses " + label)
        except (ValueError, KeyError, TypeError, InvalidSignature):
            report(True, "draft report/Q refuses " + label)
    try:
        direct = json.loads((root / "fixtures/qualification/v4/q-direct-cooperative-synthetic.json").read_text())
        direct_key = decode(direct["issuer_public_key_base64url"])
        verify_q({"issuer_public_key_base64url": direct["issuer_public_key_base64url"],
                  "wire_jcs": direct["q_wire_jcs"],
                  "index_envelope_jcs": direct["q_index_envelope_jcs"],
                  "eof_envelope_jcs": direct["q_eof_envelope_jcs"]}, schemas)
        reservation = authenticated_payload(direct["reservation_envelope_jcs"],
                                            "agent-bot/soul-cooperative-reservation/v3", 3, direct_key)
        idx = authenticated_payload(direct["q_index_envelope_jcs"],
                                    "agent-bot/stage2a-q-frame-index/v1", 1, direct_key)
        require(schemas["machine/v3/soul-cooperative-reservation-payload.schema.json"].is_valid(reservation),
                "released direct reservation schema")
        require(reservation["adapter_transport"] == "direct-comms" and
                set(reservation["endpoints"]) == {"admission", "broker"} and
                "bridge_launch_sha256" not in reservation and
                reservation["measurement_binding"]["profile_in_force"] == "managed-cooperative" and
                idx["profile"] == "managed-cooperative" and
                idx["reservation_sha256"] == sha(direct["reservation_envelope_jcs"].encode()) and
                idx["launch_challenge_sha256"] == reservation["admission_challenge_sha256"] and
                idx["host_id"] == reservation["host_id"] and
                idx["installation_id"] == reservation["assignment"]["installation_id"] and
                idx["start_id"] == reservation["assignment"]["start_id"],
                "direct Comms Q branch stays distinct from B")
        report(True, "draft direct Comms T21 signed Q/reservation join")
    except (ValueError, KeyError, TypeError, InvalidSignature) as exc:
        report(False, "draft direct Comms T21 signed Q/reservation join", str(exc))
