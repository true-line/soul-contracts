"""Cross-field checks for synthetic bridge report vectors, not host verification."""
import copy
import base64
import hashlib
import json

from jcs import canonicalize, parse_strict


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def release_binding_refusal(schemas, qualification_bytes, statement, payload_bytes, envelope_bytes,
                           build_receipt_bytes, approved_source_tree, measured_souls_package_sha256):
    """Check exact bytes and v2/v1 role binding, never signature authenticity."""
    if not schemas["adapter/v2/qualification-attestation.schema.json"].is_valid(statement):
        return "statement-shape"
    if statement["subject"][0]["digest"]["sha256"] != _digest(qualification_bytes)[7:]:
        return "qualification-bytes"
    try:
        qualification = parse_strict(qualification_bytes.decode())
    except (UnicodeError, ValueError):
        return "qualification-shape"
    if not schemas["adapter/v2/qualification-evidence.schema.json"].is_valid(qualification):
        return "qualification-shape"
    if qualification["profile_in_force"] != "managed-protected":
        return "qualification-profile"
    build = qualification["souls_build"]
    if statement["predicate"]["souls_build"] != build:
        return "statement-build-binding"
    if build["source_tree"] != approved_source_tree:
        return "unapproved-source-tree"
    if build["package_sha256"] != measured_souls_package_sha256:
        return "installed-souls-package"
    if _digest(build_receipt_bytes) != build["receipt"]["sha256"]:
        return "build-receipt-bytes"
    try:
        wrapper = parse_strict(build_receipt_bytes.decode())
        receipt = wrapper["fixture_statement"]
    except (UnicodeError, ValueError, KeyError, TypeError):
        return "build-receipt-shape"
    if wrapper.keys() != {"fixture_statement"} or not schemas["adapter/v2/qualification-build-receipt.schema.json"].is_valid(receipt):
        return "build-receipt-shape"
    if (receipt["subject"][0]["digest"]["sha256"] != build["package_sha256"][7:]
            or receipt["predicate"] != {k: v for k, v in build.items() if k not in ("package_sha256", "receipt")}):
        return "build-receipt-binding"
    refs = statement["predicate"]["host_reports"]
    for role, version in (("protected_report", 2), ("cooperative_report", 1)):
        binding = qualification["conformance"][role]
        if refs[role] != binding:
            return "statement-report-binding"
        raw = payload_bytes.get(role)
        envelope_raw = envelope_bytes.get(role)
        if raw is None or envelope_raw is None or _digest(raw) != binding["payload"]["sha256"] or _digest(envelope_raw) != binding["signature"]["sha256"]:
            return "report-or-envelope-bytes"
        try:
            payload, envelope = json.loads(raw), json.loads(envelope_raw)
        except (UnicodeError, ValueError):
            return "report-or-envelope-shape"
        prefix = f"adapter/v{version}/"
        if not schemas[prefix + "qualification-host-report.schema.json"].is_valid(payload) or not schemas[prefix + "qualification-host-signature.schema.json"].is_valid(envelope):
            return "report-or-envelope-shape"
        if (payload["profile_in_force"] != ("managed-protected" if version == 2 else "managed-cooperative")
                or envelope["purpose"] != binding["signature_purpose"]
                or envelope["host_id"] != payload["host"]["id"]
                or envelope["report_sha256"] != _digest(raw)
                or envelope["report_base64url"] != base64.urlsafe_b64encode(raw).rstrip(b"=").decode()):
            return "report-or-envelope-binding"
        if (payload["adapter"] != qualification["adapter"] or payload["launch"] != qualification["launch"]
                or payload["harness"] != qualification["harness"] or payload["runner"] != qualification["runner"]
                or payload["suite_revision"] != qualification["conformance"]["suite_revision"]):
            return "report-inputs"
        gates = {"T01", "T02", "T03"} if version == 2 else {"T21"}
        if set(payload["gates"]) != gates or payload["outcome"] != "pass" or any(x["outcome"] != "pass" for x in payload["gates"].values()):
            return "physical-gates"
        if version == 2 and (payload["run_id"] != qualification["conformance"]["run_id"]
                             or payload["recorded_at"] != qualification["recorded_at"]
                             or payload["checks"] != qualification["conformance"]["checks"]
                             or any(payload[k] != qualification[k] for k in ("host", "profile_in_force", "renders", "cost_bound", "evaluation_cells", "soul_start"))):
            return "primary-report"
    return None


def bridge_shape_refusal(report, approved_plan_digest=None):
    """Reject contradictory claims before external evidence is considered.

    A None result is never proof of kernel identity, FD custody, HMAC binding,
    signature authenticity, one-use state or physical T03.
    """
    bridge = report["bridge"]
    if bridge["assignment"]["machine_observation"] != report["soul_start"]["machine_observation"]:
        return "machine-observation-binding"
    if approved_plan_digest is not None and bridge["assignment"]["plan_digest"] != "sha256:" + approved_plan_digest:
        return "approved-plan-digest"
    principals = bridge["principals"]
    r, b, c, hq, machine = (principals[key] for key in
                            ("runner_uid", "bridge_uid", "credential_uid", "hq_uid", "machine_uid"))
    if len({r, b, c, hq, machine}) != 5 or min(r, b, c) == 0:
        return "principal-separation"
    bg, rg = principals["bridge_private_gid"], principals["runner_private_gid"]
    if bg == 0 or rg == 0 or bg == rg:
        return "private-group-separation"
    endpoints = bridge["endpoints"]
    expected = {
        "hq_broker": (hq, bg, b),
        "souls_member": (r, bg, b),
        "http_relay": (b, rg, r),
    }
    paths, parent_inodes, socket_inodes = [], [], []
    for name, (owner, group, peer) in expected.items():
        item = endpoints[name]
        if item["parent_uid"] != owner or item["socket_uid"] != owner or \
           item["parent_gid"] != group or item["socket_gid"] != group:
            return name + "-custody"
        if item["observed_peer_uid"] != peer:
            return name + "-peer"
        paths.append(item["socket_path"])
        parent_inodes.append(item["parent_inode"])
        socket_inodes.append(item["socket_inode"])
    if any(len(set(items)) != 3 for items in (paths, parent_inodes, socket_inodes)):
        return "endpoint-alias"
    if bridge["handoff"]["recipient_uid"] != b:
        return "handoff-recipient"
    return None


def check_bridge_report_fixtures(root, schemas, report):
    payload = json.loads((root / "fixtures/positive/qualification-host-report.bridge-v2-synthetic.json").read_text())["input"]
    schema = schemas["adapter/v2/qualification-host-report.schema.json"]
    report(schema.is_valid(payload), "v2 synthetic bridge report shape")
    report(bridge_shape_refusal(payload, "1" * 64) is None, "v2 synthetic bridge cross-field claims and normalized plan digest")
    observation_negative = json.loads((root / "fixtures/qualification/bridge-v2/observation-mismatch.json").read_text())
    changed = copy.deepcopy(payload)
    changed["bridge"]["assignment"]["machine_observation"] = observation_negative["replacement"]
    report(schema.is_valid(changed) and bridge_shape_refusal(changed) == observation_negative["expect"],
           "v2 bridge refuses distinct Machine observations for one start")
    cases = (
        ("same R/B UID", "principal-separation", lambda x: x["bridge"]["principals"].__setitem__("bridge_uid", 501)),
        ("same B/C UID", "principal-separation", lambda x: x["bridge"]["principals"].__setitem__("credential_uid", 502)),
        ("shared private group", "private-group-separation", lambda x: x["bridge"]["principals"].__setitem__("runner_private_gid", 702)),
        ("wrong broker owner", "hq_broker-custody", lambda x: x["bridge"]["endpoints"]["hq_broker"].__setitem__("socket_uid", 503)),
        ("wrong member peer", "souls_member-peer", lambda x: x["bridge"]["endpoints"]["souls_member"].__setitem__("observed_peer_uid", 501)),
        ("wrong relay group", "http_relay-custody", lambda x: x["bridge"]["endpoints"]["http_relay"].__setitem__("parent_gid", 702)),
        ("aliased endpoint", "endpoint-alias", lambda x: x["bridge"]["endpoints"]["http_relay"].__setitem__("socket_path", "/fixture/broker.sock")),
        ("R gets B handoff", "handoff-recipient", lambda x: x["bridge"]["handoff"].__setitem__("recipient_uid", 501)),
    )
    for name, expected, mutate in cases:
        candidate = copy.deepcopy(payload)
        mutate(candidate)
        actual = bridge_shape_refusal(candidate)
        report(actual == expected, "v2 bridge refuses " + name, f"expected {expected}, got {actual}")
    changed = copy.deepcopy(payload)
    changed["bridge"]["assignment"]["plan_digest"] = "sha256:" + "2" * 64
    report(bridge_shape_refusal(changed, "1" * 64) == "approved-plan-digest",
           "v2 bridge refuses plan digest mismatch despite well-formed sha256 prefix")

    qualification = json.loads((root / "fixtures/positive/qualification-evidence.bridge-v2-synthetic.json").read_text())["input"]
    statement = json.loads((root / "fixtures/positive/qualification-attestation.bridge-v2-synthetic.json").read_text())["input"]
    build_receipt = json.loads((root / "fixtures/positive/qualification-build-receipt.bridge-v2-synthetic.json").read_text())["input"]
    build_bundle = canonicalize({"fixture_statement": build_receipt})
    protected_envelope = json.loads((root / "fixtures/positive/qualification-host-signature.bridge-v2-synthetic.json").read_text())["input"]
    cooperative = json.loads((root / "fixtures/qualification/macos/host-cooperative.json").read_text())
    cooperative_raw = canonicalize(cooperative)
    cooperative_envelope = {
        "schema_version": 1, "purpose": "agent-bot/qualification-host-report/v1",
        "host_id": cooperative["host"]["id"], "signer_id": "fixture-host-key",
        "report_sha256": _digest(cooperative_raw),
        "report_base64url": base64.urlsafe_b64encode(cooperative_raw).rstrip(b"=").decode(),
        "signature_base64url": "A" * 86,
    }
    payloads = {"protected_report": canonicalize(payload), "cooperative_report": cooperative_raw}
    envelopes = {"protected_report": canonicalize(protected_envelope), "cooperative_report": canonicalize(cooperative_envelope)}
    record = canonicalize(qualification)

    def check_release(name, expected, *, q=record, s=statement, p=payloads, e=envelopes,
                      b=build_bundle, approved_tree=qualification["souls_build"]["source_tree"],
                      measured_souls=qualification["souls_build"]["package_sha256"]):
        actual = release_binding_refusal(schemas, q, s, p, e, b, approved_tree, measured_souls)
        report(actual == expected, "v2 release " + name, f"expected {expected}, got {actual}")

    check_release("binds protected v2 and cooperative v1 exact bytes", None)
    changed = copy.deepcopy(statement)
    changed["predicate"]["host_reports"]["protected_report"]["payload"]["sha256"] = "sha256:" + "a" * 64
    check_release("refuses statement report substitution", "statement-report-binding", s=changed)
    changed = copy.deepcopy(statement)
    changed["predicate"]["host_reports"]["protected_report"]["signature"]["sha256"] = "sha256:" + "a" * 64
    check_release("refuses unsigned envelope substitution", "statement-report-binding", s=changed)
    check_release("refuses changed protected payload bytes", "report-or-envelope-bytes",
                  p={**payloads, "protected_report": payloads["protected_report"] + b"\n"})
    check_release("refuses changed signature envelope bytes", "report-or-envelope-bytes",
                  e={**envelopes, "protected_report": envelopes["protected_report"] + b"\n"})
    check_release("refuses changed signed build receipt bytes", "build-receipt-bytes", b=build_bundle + b"\n")
    check_release("refuses changed installed Souls archive", "installed-souls-package",
                  measured_souls="sha256:" + "f" * 64)
    changed = copy.deepcopy(statement)
    changed["predicate"]["souls_build"]["source_tree"] = "f" * 40
    check_release("refuses Statement source-tree substitution", "statement-build-binding", s=changed)
    check_release("refuses same package from unapproved source tree", "unapproved-source-tree", approved_tree="f" * 40)
    changed = copy.deepcopy(qualification)
    changed["souls_build"]["source_tree"] = "f" * 40
    changed_raw = canonicalize(changed)
    repacked = copy.deepcopy(statement)
    repacked["subject"][0]["digest"]["sha256"] = _digest(changed_raw)[7:]
    repacked["predicate"]["souls_build"] = changed["souls_build"]
    check_release("refuses other source with identical package bytes and old receipt",
                  "build-receipt-binding", q=changed_raw, s=repacked, approved_tree="f" * 40)
    changed = copy.deepcopy(statement)
    changed["predicateType"] = "https://true-line.ai/soul-contracts/adapter/v1/macos-protected-qualification"
    check_release("refuses v1 statement predicate", "statement-shape", s=changed)
    changed = copy.deepcopy(qualification)
    changed["conformance"]["protected_report"]["report_schema_version"] = 1
    changed_raw = canonicalize(changed)
    repacked = copy.deepcopy(statement)
    repacked["subject"][0]["digest"]["sha256"] = _digest(changed_raw)[7:]
    check_release("refuses v1 protected report", "qualification-shape", q=changed_raw, s=repacked)
    changed = copy.deepcopy(qualification)
    changed["conformance"]["runner_observations"].pop("direct_ipv4_ipv6_egress")
    changed_raw = canonicalize(changed)
    repacked = copy.deepcopy(statement)
    repacked["subject"][0]["digest"]["sha256"] = _digest(changed_raw)[7:]
    check_release("refuses missing runner egress observation", "qualification-shape", q=changed_raw, s=repacked)
