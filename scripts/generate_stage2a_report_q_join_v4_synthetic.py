#!/usr/bin/env python3
"""Generate deterministic draft report/Q successor vectors, never host proof."""

import base64
import copy
import hashlib
import json
import pathlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from jcs import canonicalize, parse_strict  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
KEY = Ed25519PrivateKey.from_private_bytes(b"\x13" * 32)
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
HOST_KEY = ec.derive_private_key(1, ec.SECP256R1())
Q_SCHEMA = "soul-conformance/qualification-session/v1"


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign(payload, purpose, version):
    raw = canonicalize(payload)
    return canonicalize({
        "schema_version": version, "purpose": purpose,
        "issuer_public_key_base64url": b64(PUBLIC),
        "payload_sha256": sha(raw), "payload_base64url": b64(raw),
        "signature_base64url": b64(KEY.sign(purpose.encode() + b"\0" + raw)),
    })


def ref(name, raw):
    return {"uri": "fixture:" + name, "sha256": sha(raw)}


def framed(obj):
    raw = canonicalize(obj)
    return struct.pack(">I", len(raw)) + raw


def fixture(name, schema, value, invalid=None, base=None):
    record = {"schema": schema, "input": value,
              "expect": {"schema": "invalid" if invalid else "valid"}}
    path = ROOT / "fixtures" / ("negative" if invalid else "positive") / name
    if invalid:
        record["base"] = {"fixture": "positive/" + base,
                          "sha256": sha((ROOT / "fixtures/positive" / base).read_bytes())}
    else:
        record["canonical_sha256"] = sha(canonicalize(value))
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


def q_chain(profile, reservation_raw, reservation, cohort, session):
    original = json.loads((ROOT / "fixtures/qualification/v3/q-presign-argv-synthetic.json").read_text())
    wire = parse_strict(original["wire_jcs"].encode())
    frames = {name: parse_strict(unb64(wire[name + "_base64url"])[4:])
              for name in ("begin_frame", "ready_frame", "request_frames",
                           "observation_frames", "finish_request_frame", "finished_frame")}
    assignment = reservation["assignment"]
    begin = frames["begin_frame"]
    begin.update(session_id=session, cohort_id=cohort,
                 installation_id=assignment["installation_id"], soul_id=assignment["soul_id"],
                 start_id=assignment["start_id"], host_id=reservation["host_id"],
                 profile=profile, reservation_sha256=sha(reservation_raw),
                 deadline_at="2026-11-22T14:15:35Z")
    for frame in frames.values():
        frame["session_id"] = session
    frames["request_frames"]["gate"] = "T21" if profile == "managed-cooperative" else "T01"
    frames["observation_frames"]["gate"] = frames["request_frames"]["gate"]
    frames["ready_frame"]["captured_at"] = "2026-11-22T14:15:20Z"
    frames["observation_frames"]["captured_at"] = "2026-11-22T14:15:21Z"
    frames["finished_frame"]["captured_at"] = "2026-11-22T14:15:22Z"
    order = ("begin_frame", "ready_frame", "request_frames", "observation_frames",
             "finish_request_frame", "finished_frame")
    raw = {name: framed(frames[name]) for name in order}
    frames["observation_frames"]["request_sha256"] = sha(raw["request_frames"][4:])
    raw["observation_frames"] = framed(frames["observation_frames"])
    frames["finished_frame"]["observations_sha256"] = sha(raw["observation_frames"])
    raw["finished_frame"] = framed(frames["finished_frame"])
    wire = {"schema": Q_SCHEMA, "kind": "framed-wire", "session_id": session,
            **{name + "_base64url": b64(raw[name]) for name in order}}
    wire_raw = canonicalize(wire)
    idx = parse_strict(unb64(parse_strict(original["index_envelope_jcs"].encode())["payload_base64url"]))
    idx.update(cohort_id=cohort, installation_id=assignment["installation_id"],
               soul_id=assignment["soul_id"], start_id=assignment["start_id"],
               host_id=reservation["host_id"], profile=profile,
               reservation_sha256=sha(reservation_raw), session_id=session,
               launch_challenge_sha256=reservation["admission_challenge_sha256"],
               wire_sha256=sha(wire_raw), ordered_frames_sha256=sha(b"".join(raw[n] for n in order)),
               issued_at="2026-11-22T14:15:24Z")
    for name in order:
        idx[name + "_sha256"] = sha(raw[name])
    index_raw = sign(idx, "agent-bot/stage2a-q-frame-index/v1", 1)
    eof = parse_strict(unb64(parse_strict(original["eof_envelope_jcs"].encode())["payload_base64url"]))
    eof.update(session_id=session, index_envelope_sha256=sha(index_raw),
               wire_sha256=sha(wire_raw), finished_frame_sha256=sha(raw["finished_frame"]),
               eof_observed_at="2026-11-22T14:15:23Z", issued_at="2026-11-22T14:15:24Z")
    return wire_raw, index_raw, sign(eof, "agent-bot/stage2a-q-finished-eof/v1", 1), idx


def make_run(profile):
    cooperative = profile == "managed-cooperative"
    if cooperative:
        original = json.loads((ROOT / "fixtures/reservation/v3/soul-cooperative-signed-reservation.brokered-b.synthetic.json").read_text())
        reservation = parse_strict(original["reservation_payload_jcs"].encode())
        reservation.pop("qualification_provider", None)
        reservation_raw = sign(reservation, "agent-bot/soul-cooperative-reservation/v3", 3)
        bridge = parse_strict(unb64(parse_strict(original["bridge_envelope_jcs"].encode())["payload_base64url"]))
        bridge["reservation_sha256"] = sha(reservation_raw)
        bridge_raw = sign(bridge, "agent-bot/soul-cooperative-bridge-assignment/v3", 3)
        template = json.loads((ROOT / "fixtures/positive/qualification-host-report.measurement-v3-cooperative-synthetic.json").read_text())["input"]
    else:
        reservation = json.loads((ROOT / "fixtures/positive/stage2a-reservation-payload.v3-synthetic.json").read_text())["input"]
        reservation_raw = sign(reservation, "agent-bot/stage2a-reservation/v3", 3)
        bridge_raw = None
        template = json.loads((ROOT / "fixtures/positive/qualification-host-report.measurement-v3-synthetic.json").read_text())["input"]
    cohort = "synthetic-cohort-" + ("cooperative" if cooperative else "protected")
    session = ("c" if cooperative else "a") * 32
    wire_raw, index_raw, eof_raw, idx = q_chain(profile, reservation_raw, reservation, cohort, session)
    report = copy.deepcopy(template)
    report["schema_version"] = 4
    report["host"]["id"] = reservation["host_id"]
    report["profile_in_force"] = profile
    report["measurement_binding"] = reservation["measurement_binding"]
    report["recorded_at"] = "2026-11-22T14:15:27Z"
    q = {"framed_wire": ref(profile + "-q-wire", wire_raw),
         "frame_index_envelope": ref(profile + "-q-index", index_raw),
         "clean_eof_envelope": ref(profile + "-q-eof", eof_raw)}
    run = {"reservation": ref(profile + "-reservation", reservation_raw),
           "challenge_sha256": reservation["admission_challenge_sha256"], "q_session": q}
    if cooperative:
        run["bridge_assignment"] = ref("cooperative-b-assignment", bridge_raw)
        run["cooperative_order_receipt"] = ref("cooperative-order-receipt", b"synthetic order receipt: pending wire")
    else:
        run["finalization"] = ref("protected-finalization", b"synthetic protected finalization: pending run")
        assignment = report["bridge"]["assignment"]
        for field in ("installation_id", "soul_id", "start_id", "launch_id", "plan_id"):
            assignment[field] = reservation["assignment"][field]
        assignment["machine_reservation_sha256"] = sha(reservation_raw)
    report["run_evidence"] = run
    binding = report["measurement_binding"]
    candidate_sha = sha(canonicalize(report))
    completion = {
        "schema_version": 2, "kind": "stage2a-execution-completion",
        "profile_in_force": profile, "host_id": reservation["host_id"],
        "installation_id": reservation["assignment"]["installation_id"],
        "soul_id": reservation["assignment"]["soul_id"],
        "start_id": reservation["assignment"]["start_id"],
        "launch_id": reservation["assignment"]["launch_id"], "cohort_id": cohort,
        "report_candidate_sha256": candidate_sha, "reservation_sha256": sha(reservation_raw),
        "challenge_sha256": run["challenge_sha256"],
        "measurement_binding_sha256": sha(canonicalize(binding)),
        "q_framed_wire_sha256": q["framed_wire"]["sha256"],
        "q_frame_index_envelope_sha256": q["frame_index_envelope"]["sha256"],
        "q_clean_eof_envelope_sha256": q["clean_eof_envelope"]["sha256"],
        "completed_at": "2026-11-22T14:15:26Z",
    }
    if cooperative:
        completion["bridge_assignment_sha256"] = run["bridge_assignment"]["sha256"]
        completion["cooperative_order_receipt_sha256"] = run["cooperative_order_receipt"]["sha256"]
    else:
        completion["finalization_sha256"] = run["finalization"]["sha256"]
    completion_raw = sign(completion, "agent-bot/stage2a-execution-completion/v2", 2)
    run["execution_completion"] = ref(profile + "-execution-completion", completion_raw)
    report_raw = canonicalize(report)
    host_purpose = "agent-bot/qualification-host-report/v4"
    der = HOST_KEY.sign(host_purpose.encode() + b"\0" + report_raw,
                        ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    signature_r, signature_s = decode_dss_signature(der)
    host_signature = {"schema_version": 4, "purpose": host_purpose,
                      "host_id": report["host"]["id"], "signer_id": "synthetic-signer",
                      "report_sha256": sha(report_raw), "report_base64url": b64(report_raw),
                      "signature_base64url": b64(signature_r.to_bytes(32, "big") + signature_s.to_bytes(32, "big"))}
    return {"report": report, "completion": completion, "completion_envelope_jcs": completion_raw.decode(),
            "host_signature_envelope": host_signature,
            "reservation_envelope_jcs": reservation_raw.decode(),
            "bridge_assignment_envelope_jcs": bridge_raw.decode() if bridge_raw else None,
            "q_wire_jcs": wire_raw.decode(), "q_index_envelope_jcs": index_raw.decode(),
            "q_eof_envelope_jcs": eof_raw.decode(), "q_index": idx,
            "issuer_public_key_base64url": b64(PUBLIC)}


def main():
    runs = {name: make_run(profile) for name, profile in
            (("protected", "managed-protected"), ("cooperative", "managed-cooperative"))}
    target = ROOT / "fixtures/qualification/v4/report-q-join-synthetic.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(runs, indent=2, sort_keys=True) + "\n")
    report_schema = "adapter/v4/qualification-host-report.schema.json"
    completion_schema = "machine/v2/stage2a-execution-completion-payload.schema.json"
    envelope_schema = "machine/v2/stage2a-signed-execution-completion.schema.json"
    signature_schema = "adapter/v4/qualification-host-signature.schema.json"
    for name, run in runs.items():
        fixture("qualification-host-report.v4-" + name + ".synthetic.json", report_schema, run["report"])
        fixture("stage2a-execution-completion-payload.v2-" + name + ".synthetic.json", completion_schema, run["completion"])
    protected = copy.deepcopy(runs["protected"]["report"])
    del protected["run_evidence"]["q_session"]["clean_eof_envelope"]
    fixture("qualification-host-report.v4-missing-q-eof.json", report_schema, protected, True,
            "qualification-host-report.v4-protected.synthetic.json")
    cooperative = copy.deepcopy(runs["cooperative"]["report"])
    cooperative["run_evidence"]["finalization"] = cooperative["run_evidence"].pop("cooperative_order_receipt")
    fixture("qualification-host-report.v4-cooperative-protected-finalization.json", report_schema,
            cooperative, True, "qualification-host-report.v4-cooperative.synthetic.json")
    bad_completion = copy.deepcopy(runs["protected"]["completion"])
    del bad_completion["q_frame_index_envelope_sha256"]
    fixture("stage2a-execution-completion-payload.v2-missing-q-index.json", completion_schema,
            bad_completion, True, "stage2a-execution-completion-payload.v2-protected.synthetic.json")
    bad_completion = copy.deepcopy(runs["cooperative"]["completion"])
    bad_completion["finalization_sha256"] = bad_completion.pop("cooperative_order_receipt_sha256")
    fixture("stage2a-execution-completion-payload.v2-cooperative-protected-finalization.json", completion_schema,
            bad_completion, True, "stage2a-execution-completion-payload.v2-cooperative.synthetic.json")
    signed_completion = parse_strict(runs["protected"]["completion_envelope_jcs"].encode())
    fixture("stage2a-signed-execution-completion.v2-synthetic.json", envelope_schema, signed_completion)
    wrong_purpose = dict(signed_completion)
    wrong_purpose["purpose"] = "agent-bot/stage2a-execution-completion/v1"
    fixture("stage2a-signed-execution-completion.v2-wrong-purpose.json", envelope_schema,
            wrong_purpose, True, "stage2a-signed-execution-completion.v2-synthetic.json")
    host_shape = runs["protected"]["host_signature_envelope"]
    fixture("qualification-host-signature.v4-synthetic.json", signature_schema, host_shape)
    wrong_host_purpose = dict(host_shape)
    wrong_host_purpose["purpose"] = "agent-bot/qualification-host-report/v3"
    fixture("qualification-host-signature.v4-wrong-purpose.json", signature_schema,
            wrong_host_purpose, True, "qualification-host-signature.v4-synthetic.json")


if __name__ == "__main__":
    main()
