"""Synthetic v4 qualification/Statement byte joins; no trust or gate verdict."""

import copy
import hashlib
import json
from datetime import datetime

from jcs import canonicalize


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _join(qualification, statement, vectors):
    if qualification["schema_version"] != 4 or statement["predicateType"] != \
            "https://true-line.ai/soul-contracts/adapter/v4/macos-measured-qualification":
        return False
    if statement["subject"] != [{"name": "qualification.json",
                                  "digest": {"sha256": _digest(canonicalize(qualification))[7:]}}]:
        return False
    if statement["predicate"]["host_reports"] != {name + "_report": qualification["conformance"][name + "_report"]
                                                  for name in ("protected", "cooperative")}:
        return False
    if statement["predicate"]["souls_build"] != qualification["souls_build"] or \
            statement["predicate"]["soul_artifact_sha256"] != qualification["soul_artifact_sha256"]:
        return False
    try:
        qualified_at = datetime.fromisoformat(qualification["recorded_at"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(statement["predicate"]["expires_at"].replace("Z", "+00:00"))
        if expires_at <= qualified_at:
            return False
        for name in ("protected", "cooperative"):
            vector = vectors[name]
            report = vector["report"]
            ref = qualification["conformance"][name + "_report"]
            if (ref["report_schema_version"] != 4 or
                    ref["signature_purpose"] != "agent-bot/qualification-host-report/v4" or
                    ref["payload"]["sha256"] != _digest(canonicalize(report)) or
                    ref["signature"]["sha256"] != _digest(canonicalize(vector["host_signature_envelope"])) or
                    ref["completed_run"]["sha256"] != _digest(vector["commitment_envelope_jcs"].encode()) or
                    report["profile_in_force"] != "managed-" + name or
                    report["recorded_at"] > qualification["recorded_at"]):
                return False
            for field in ("adapter", "launch", "harness", "runner", "host", "renders", "cost_bound", "evaluation_cells"):
                if qualification[field] != report[field]:
                    return False
        protected = vectors["protected"]["report"]
        cooperative = vectors["cooperative"]["report"]
        return (qualification["soul_start"] == protected["soul_start"] and
                qualification["conformance"]["suite_revision"] == protected["suite_revision"] == cooperative["suite_revision"] and
                qualification["conformance"]["run_id"] == protected["run_id"] != cooperative["run_id"] and
                qualification["conformance"]["checks"] == protected["checks"] and
                protected["run_evidence"]["challenge_sha256"] != cooperative["run_evidence"]["challenge_sha256"])
    except (KeyError, TypeError, ValueError):
        return False


def check_qualification_release_v4_fixtures(root, schemas, report):
    qualification = json.loads((root / "fixtures/positive/qualification-evidence.authenticated-v4-synthetic.json").read_text())["input"]
    statement = json.loads((root / "fixtures/positive/qualification-attestation.authenticated-v4-synthetic.json").read_text())["input"]
    vectors = json.loads((root / "fixtures/qualification/v4/report-q-join-synthetic.json").read_text())
    q_schema = schemas["adapter/v4/qualification-evidence.schema.json"]
    s_schema = schemas["adapter/v4/qualification-attestation.schema.json"]
    report(q_schema.is_valid(qualification) and s_schema.is_valid(statement) and
           _join(qualification, statement, vectors), "v4 release pins exact report and commitment bytes")
    wrong = copy.deepcopy(qualification)
    wrong["conformance"]["cooperative_report"]["signature_purpose"] = "agent-bot/qualification-host-report/v3"
    report(not q_schema.is_valid(wrong) and not _join(wrong, statement, vectors),
           "v4 release refuses older host purpose")
    wrong = copy.deepcopy(qualification)
    wrong["runner"]["binary_sha256"] = "sha256:" + "0" * 64
    report(q_schema.is_valid(wrong) and not _join(wrong, statement, vectors),
           "v4 release refuses changed runner bytes")
    wrong = copy.deepcopy(statement)
    wrong["subject"][0]["digest"]["sha256"] = "0" * 64
    report(s_schema.is_valid(wrong) and not _join(qualification, wrong, vectors),
           "v4 release refuses changed qualification subject")
    wrong = copy.deepcopy(vectors)
    wrong["cooperative"]["commitment_envelope_jcs"] += " "
    report(not _join(qualification, statement, wrong),
           "v4 release refuses changed post-sign commitment bytes")
