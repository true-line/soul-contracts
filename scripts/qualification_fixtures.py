"""Fixture oracles for qualification cross-record checks. No signature or policy verification."""
from copy import deepcopy
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
import re

from jcs import canonicalize, parse_strict

PREFIX = "adapter/v1/"
GATE_PROFILES = {
    "T01": "managed-protected",
    "T02": "managed-protected",
    "T03": "managed-protected",
    "T21": "managed-cooperative",
}
HOST_IDENTITY_FIELDS = ("id", "os", "os_version", "architecture")
PRIMARY_FIELDS = ("host", "profile_in_force", "renders", "cost_bound", "evaluation_cells")


def hex_digest(data):
    return sha256(data).hexdigest()


def digest(data):
    return "sha256:" + hex_digest(data)


def instant(timestamp):
    # RFC 3339 allows more fractional digits than datetime stores.
    fraction = re.search(r"\.([0-9]+)", timestamp)
    without_fraction = timestamp if fraction is None else timestamp[:fraction.start()] + timestamp[fraction.end():]
    whole = datetime.fromisoformat(without_fraction.upper().replace("Z", "+00:00"))
    return whole, Decimal("0." + fraction[1]) if fraction else Decimal(0)


def measured_inputs(record):
    launch = record["launch"]
    inputs = {item["path"]: item["sha256"] for item in launch["code_inputs"]}
    if len(inputs) != len(launch["code_inputs"]):
        return None
    return (
        record["adapter"], record["harness"],
        launch["executable"], launch["executable_sha256"], launch["argv"], inputs,
    )


def binding_error(schemas, qualification_bytes, reference, bundle_bytes,
                  host_report_bytes, measured, now):
    """Compare fixture data supplied on separate inputs, in its original bytes.

    Real callers need authenticated statements, passing designated-host evidence,
    locally measured inputs and current signed trust policy before using these checks.
    """
    def valid(name, value):
        return schemas[PREFIX + name + ".schema.json"].is_valid(value)

    if not valid("qualification-reference", reference):
        return "reference-shape"
    if reference["attestation"]["sha256"] != digest(bundle_bytes):
        return "attestation-bundle"
    try:
        wrapper = parse_strict(bundle_bytes.decode("utf-8"))
    except ValueError:
        return "bundle-shape"
    if not isinstance(wrapper, dict) or wrapper.keys() != {"fixture_statement"}:
        return "bundle-shape"
    statement = wrapper["fixture_statement"]
    if not valid("qualification-attestation", statement):
        return "statement-shape"
    if statement["subject"][0]["digest"]["sha256"] != hex_digest(qualification_bytes):
        return "qualification-bytes"
    try:
        qualification = parse_strict(qualification_bytes.decode("utf-8"))
    except ValueError:
        return "qualification-shape"
    if not valid("qualification-evidence", qualification) or "id" not in qualification["host"]:
        return "qualification-shape"
    if qualification["host"]["os"] != "darwin" or reference["profile"] != qualification["profile_in_force"]:
        return "scope"
    expires_at = instant(statement["predicate"]["expires_at"])
    recorded_at = instant(qualification["recorded_at"])
    if recorded_at > now:
        return "qualification-future"
    if expires_at <= recorded_at:
        return "qualification-expiry-order"
    if expires_at <= now:
        return "qualification-expired"
    run = qualification["conformance"]
    if run["outcome"] != "pass":
        return "qualification-outcome"

    inputs = measured_inputs(qualification)
    installed = measured_inputs(measured)
    if inputs is None or inputs != installed:
        return "installed-inputs"
    host = qualification["host"]
    if (qualification["profile_in_force"] != measured["profile_in_force"]
            or any(host[field] != measured["host"].get(field) for field in (*HOST_IDENTITY_FIELDS, "profile"))):
        return "installed-profile"

    primary_sha = run["report"]["sha256"]
    seen_reports = set()
    gates = set()
    for ref in statement["predicate"]["host_reports"]:
        report_sha = ref["sha256"]
        raw = host_report_bytes.get(report_sha)
        if report_sha in seen_reports or raw is None or digest(raw) != report_sha:
            return "host-report-bytes"
        seen_reports.add(report_sha)
        try:
            host_report = parse_strict(raw.decode("utf-8"))
        except ValueError:
            return "host-report-shape"
        if not valid("qualification-host-report", host_report):
            return "host-report-shape"
        if host_report["suite_revision"] != run["suite_revision"] or measured_inputs(host_report) != inputs:
            return "host-report-inputs"
        if any(host_report["host"][field] != host[field] for field in HOST_IDENTITY_FIELDS):
            return "host-report-identity"
        recorded_at = instant(host_report["recorded_at"])
        if expires_at <= recorded_at:
            return "qualification-expiry-order"
        if recorded_at > now:
            return "host-report-future"
        if host_report["outcome"] != "pass":
            return "host-report-outcome"
        if host_report["profile_in_force"] == "managed-protected" and any(
            check["outcome"] != "pass" for check in host_report["checks"].values()
        ):
            return "protected-checks"
        if report_sha == primary_sha and (
            any(qualification[field] != host_report[field] for field in PRIMARY_FIELDS)
            or any(run[field] != host_report[field] for field in ("run_id", "checks"))
        ):
            return "primary-report"
        for name, evidence in host_report["gates"].items():
            if evidence["outcome"] != "pass" or host_report["profile_in_force"] != GATE_PROFILES[name]:
                return "physical-gates"
            gates.add(name)

    if primary_sha not in seen_reports:
        return "primary-report"
    if gates != GATE_PROFILES.keys():
        return "physical-gates"
    return None


def check_qualification_fixtures(root, schemas, report):
    files = root / "fixtures/qualification/macos"
    qualification_bytes = (files / "qualification.json").read_bytes()
    measured = parse_strict((files / "measured.json").read_text())
    reports = {digest(raw): raw for raw in (p.read_bytes() for p in files.glob("host-*.json"))}
    fixtures = root / "fixtures/positive"
    statement = parse_strict((fixtures / "qualification-attestation.synthetic.json").read_text())["input"]
    reference = parse_strict((fixtures / "qualification-reference.synthetic.json").read_text())["input"]

    # This is synthetic serialization so the reference has real bytes to hash.
    # The fixture inputs contain no signature, certificate, or trusted signer.
    bundle_bytes = canonicalize({"fixture_statement": statement})

    def check(label, expected, *, record=qualification_bytes,
              manifest=reference, bundle=bundle_bytes, host=reports, live=measured,
              now=instant("2026-11-10T00:00:00Z")):
        got = binding_error(schemas, record, manifest, bundle, host, live, now)
        report(got == expected, f"qualification {label}", f"expected {expected}, got {got}")

    def check_repacked(label, expected, release, **inputs):
        bundle = canonicalize({"fixture_statement": release})
        manifest = deepcopy(reference)
        manifest["attestation"]["sha256"] = digest(bundle)
        check(label, expected, manifest=manifest, bundle=bundle, **inputs)

    def replace_host(profile, label, expected, new_report, *, match_primary=False):
        # Recompute untrusted references so the typed comparison sees a
        # well-formed but inconsistent tuple instead of merely a stale hash.
        release = deepcopy(statement)
        host = dict(reports)
        old_sha = next(key for key, value in host.items()
                       if parse_strict(value.decode())["profile_in_force"] == profile)
        del host[old_sha]
        raw = canonicalize(new_report)
        host[digest(raw)] = raw
        for ref in release["predicate"]["host_reports"]:
            if ref["sha256"] == old_sha:
                ref["sha256"] = digest(raw)
        qualification = parse_strict(qualification_bytes.decode())
        if qualification["conformance"]["report"]["sha256"] == old_sha:
            qualification["conformance"]["report"]["sha256"] = digest(raw)
            if match_primary:
                qualification["conformance"]["checks"] = new_report["checks"]
                qualification["cost_bound"] = new_report["cost_bound"]
        record = canonicalize(qualification)
        release["subject"][0]["digest"]["sha256"] = hex_digest(record)
        check_repacked(label, expected, release, record=record, host=host)

    check("matches separately supplied report and installed inputs", None)
    check("rejects reserialized qualification bytes", "qualification-bytes", record=qualification_bytes + b"\n")
    check("rejects different bundle bytes", "attestation-bundle", bundle=bundle_bytes + b"\n")
    release = deepcopy(statement)
    another_record = parse_strict(qualification_bytes.decode())
    another_record["recorded_at"] = "2026-11-02T00:00:00Z"
    release["subject"][0]["digest"]["sha256"] = hex_digest(canonicalize(another_record))
    check_repacked("rejects referenced bundle for another statement subject", "qualification-bytes", release)
    check("rejects missing host report", "host-report-bytes", host={})
    check("rejects cooperative reference for this contract", "reference-shape",
          manifest={**reference, "profile": "managed-cooperative"})
    record_time = parse_strict(qualification_bytes.decode())["recorded_at"]
    check("accepts record observed exactly at verification time", None, now=instant(record_time))
    check("rejects record observed after verification time", "qualification-future",
          now=instant("2026-10-31T23:59:59.9999999Z"))
    check("rejects exactly at expiry", "qualification-expired",
          now=instant(statement["predicate"]["expires_at"]))
    check("accepts before fractional second expiry boundary", None,
          now=instant("2026-11-30t23:59:59.9999999z"))
    release = deepcopy(statement)
    release["predicate"]["expires_at"] = parse_strict(qualification_bytes.decode())["recorded_at"]
    check_repacked("requires expiry after the record date", "qualification-expiry-order", release)
    for field, value in (("profile_in_force", "managed-cooperative"), ("host", {"os": "linux"})):
        record = parse_strict(qualification_bytes.decode())
        if field == "host":
            record["host"].update(value)
        else:
            record[field] = value
        release = deepcopy(statement)
        raw = canonicalize(record)
        release["subject"][0]["digest"]["sha256"] = hex_digest(raw)
        check_repacked(f"rejects record outside Mac protected scope ({field})", "scope", release, record=raw)

    for section, field, value in (
        ("adapter", "package_sha256", "sha256:" + "9" * 64),
        ("harness", "binary_path", "/fixture/other/harness"),
        ("harness", "binary_sha256", "sha256:" + "9" * 64),
        ("launch", "executable", "/fixture/other/adapter"),
        ("launch", "executable_sha256", "sha256:" + "9" * 64),
        ("launch", "argv", list(reversed(measured["launch"]["argv"]))),
        ("launch", "code_inputs", []),
        ("host", "os_version", "15.1"),
        ("host", "id", "fixture-other-mac"),
    ):
        changed = deepcopy(measured)
        changed[section][field] = value
        expected = "installed-profile" if section == "host" else "installed-inputs"
        check(f"rejects changed installed {section}.{field}", expected, live=changed)
    live = deepcopy(measured)
    live["profile_in_force"] = "managed-cooperative"
    check("rejects weaker profile in force", "installed-profile", live=live)

    cooperative = "managed-cooperative"
    host_report = next(parse_strict(raw.decode()) for raw in reports.values()
                       if parse_strict(raw.decode())["profile_in_force"] == cooperative)
    changed = deepcopy(host_report)
    changed["harness"]["binary_path"] = "/fixture/other/harness"
    replace_host(cooperative, "independent run disagrees on selected binary", "host-report-inputs", changed)
    changed = deepcopy(host_report)
    changed["gates"]["T21"]["outcome"] = "fail"
    replace_host(cooperative, "cooperative gate failed", "physical-gates", changed)
    changed = deepcopy(host_report)
    changed["host"]["id"] = "fixture-other-mac"
    replace_host(cooperative, "cooperative report from another host", "host-report-identity", changed)
    changed = deepcopy(host_report)
    changed["host"]["os_version"] = "15.1"
    replace_host(cooperative, "cooperative report ran a different OS build", "host-report-identity", changed)

    protected = "managed-protected"
    host_report = next(parse_strict(raw.decode()) for raw in reports.values()
                       if parse_strict(raw.decode())["profile_in_force"] == protected)
    changed = deepcopy(host_report)
    del changed["gates"]["T01"]
    replace_host(protected, "required protected gate missing", "physical-gates", changed)
    changed = deepcopy(host_report)
    changed["suite_revision"] = "b" * 40
    replace_host(protected, "independent suite revision differs", "host-report-inputs", changed)
    changed = deepcopy(host_report)
    changed["checks"]["session_reuse"]["evidence"][0]["sha256"] = "sha256:" + "a" * 64
    replace_host(protected, "primary results disagree", "primary-report", changed)

    for name, outcome in (
        ("safe_interrupt_resume", "fail"),
        ("session_reuse", "not-run"),
        ("cost_bound", "fail"),
        ("render_coverage", "unenforced"),
    ):
        changed = deepcopy(host_report)
        changed["checks"][name]["outcome"] = outcome
        replace_host(protected, f"rejects matching nonpassing {name}", "protected-checks",
                     changed, match_primary=True)
    changed = deepcopy(host_report)
    changed["cost_bound"] = "none"
    replace_host(protected, "accepts passing check for declared unavailable cost bound", None,
                 changed, match_primary=True)

    changed = deepcopy(host_report)
    changed["recorded_at"] = statement["predicate"]["expires_at"]
    replace_host(protected, "requires expiry after the host report date", "qualification-expiry-order", changed)
    changed = deepcopy(host_report)
    changed["recorded_at"] = "2026-11-10T00:00:00Z"
    replace_host(protected, "accepts host report observed exactly at verification time", None, changed)
    changed["recorded_at"] = "2026-11-10T00:00:00.0000001Z"
    replace_host(protected, "rejects host report observed after verification time", "host-report-future", changed)

    for name, outcome in (("state_redirect", "fail"), ("egress", "unenforced"), ("credentials", None)):
        changed = deepcopy(host_report)
        if outcome is None:
            del changed["checks"][name]
        else:
            changed["checks"][name]["outcome"] = outcome
        expected = "host-report-shape" if outcome is None else "protected-checks"
        replace_host(protected, f"rejects protected pass with {name} {outcome or 'missing'}", expected, changed)
