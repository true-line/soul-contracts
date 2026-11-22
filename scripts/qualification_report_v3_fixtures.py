"""Cross-record byte vectors for v3; never a signature or physical verifier."""

import base64
import copy
import hashlib
import json

from jcs import canonicalize


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load(root, name):
    return json.loads((root / "fixtures/positive" / name).read_text())["input"]


def _reference(ref, raw):
    return ref["sha256"] == _digest(raw)


def _report_consistent(report, profile):
    binding = report["measurement_binding"]
    if report["profile_in_force"] != profile or binding["profile_in_force"] != profile:
        return False
    if report["host"]["id"] != binding["host_id"] or report["adapter"]["package_sha256"] != "sha256:" + binding["package_sha256"]:
        return False
    if profile == "managed-protected":
        assignment = report["bridge"]["assignment"]
        if any(assignment[key] != binding[key] for key in ("installation_id", "soul_id", "start_id", "launch_id", "plan_id")):
            return False
        if assignment["plan_digest"] != "sha256:" + binding["installed_plan_digest"]:
            return False
        if assignment["machine_reservation_sha256"] != report["run_evidence"]["reservation"]["sha256"]:
            return False
        if assignment["machine_observation"] != report["soul_start"]["machine_observation"]:
            return False
    return True


def _envelope_matches(report, envelope):
    raw = canonicalize(report)
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return (envelope["schema_version"] == 3 and
            envelope["purpose"] == "agent-bot/qualification-host-report/v3" and
            envelope["host_id"] == report["host"]["id"] and
            envelope["report_sha256"] == _digest(raw) and
            envelope["report_base64url"] == encoded)


def check_report_v3_fixtures(root, schemas, report):
    protected = _load(root, "qualification-host-report.measurement-v3-synthetic.json")
    cooperative = _load(root, "qualification-host-report.measurement-v3-cooperative-synthetic.json")
    protected_sig = _load(root, "qualification-host-signature.measurement-v3-synthetic.json")
    cooperative_sig = _load(root, "qualification-host-signature.measurement-v3-cooperative-synthetic.json")
    evidence = _load(root, "qualification-evidence.measurement-v3-synthetic.json")
    attestation = _load(root, "qualification-attestation.measurement-v3-synthetic.json")
    report(_report_consistent(protected, "managed-protected"), "v3 protected binding agrees with report and bridge")
    report(_report_consistent(cooperative, "managed-cooperative"), "v3 cooperative binding agrees with report")
    for profile, payload, envelope in (("protected", protected, protected_sig), ("cooperative", cooperative, cooperative_sig)):
        report(_envelope_matches(payload, envelope), "v3 " + profile + " envelope exact report bytes")
        release_ref = evidence["conformance"][profile + "_report"]
        report(release_ref == attestation["predicate"]["host_reports"][profile + "_report"], "v3 " + profile + " release/attestation refs agree")
        report(_reference(release_ref["payload"], canonicalize(payload)) and
               _reference(release_ref["signature"], canonicalize(envelope)), "v3 " + profile + " payload/envelope refs bind exact bytes")
        report(release_ref["report_schema_version"] == 3 and
               release_ref["signature_purpose"] == "agent-bot/qualification-host-report/v3" and
               "completed_run" not in payload and "completed_run" not in payload["run_evidence"],
               "v3 " + profile + " completion ref is outside signed report")
    p = protected["measurement_binding"]
    c = cooperative["measurement_binding"]
    report(p["definition_measurement"] == c["definition_measurement"] and
           p["claimed_definition_digest"] == c["claimed_definition_digest"] and
           p["launch_input_measurement"] != c["launch_input_measurement"] and
           p["snapshots"]["definition"] == c["snapshots"]["definition"] and
           p["snapshots"]["launch_inputs"] != c["snapshots"]["launch_inputs"] and
           p["start_id"] != c["start_id"] and p["launch_id"] != c["launch_id"] and
           protected["run_evidence"] != cooperative["run_evidence"],
           "v3 T21 spends a distinct profile-specific start and launch closure")
    report(attestation["subject"][0]["digest"]["sha256"] == _digest(canonicalize(evidence))[7:],
           "v3 Statement subject binds exact qualification bytes")
    for label, edit in (
        ("package", lambda v: v["measurement_binding"].__setitem__("package_sha256", "f" * 64)),
        ("host", lambda v: v["measurement_binding"].__setitem__("host_id", "other-host")),
        ("reservation", lambda v: v["run_evidence"]["reservation"].__setitem__("sha256", "sha256:" + "f" * 64)),
        ("start", lambda v: v["bridge"]["assignment"].__setitem__("start_id", "st_" + "f" * 24)),
    ):
        changed = copy.deepcopy(protected)
        edit(changed)
        report(not _report_consistent(changed, "managed-protected"), "v3 changed " + label + " refuses")
    stale = copy.deepcopy(protected_sig)
    stale["purpose"] = "agent-bot/qualification-host-report/v2"
    report(not _envelope_matches(protected, stale), "v3 v2-purpose substitution refuses")
