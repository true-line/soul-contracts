"""Fixture oracle for the three-file, unsigned Appendix C example."""
import hashlib
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory

from jcs import canonicalize, parse_strict


PREFIX = b"SOUL-DEFINITION-EXAMPLE-1\n"
MODES = {"Resources/SOUL.md": "0644", "SoulInfo.json": "0644", "SoulLock.json": "0644"}
REVISION = "36a0351bd2ac3db3b091b65c85def71064632889c34215e75a97ae88595ce768"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def inventory(files):
    return [
        {"path": path, "mode": files[path][0], "sha256": sha256(files[path][1])}
        for path in sorted(files, key=lambda path: path.encode("ascii"))
    ]


def refusal(files, expected):
    for name in ("SoulInfo.json", "SoulLock.json"):
        try:
            manifest = parse_strict(files[name][1].decode("utf-8"))
        except ValueError as exc:
            if str(exc).startswith("duplicate key "):
                return "duplicate-manifest-key"
            raise
        if "exclusions" in manifest:
            return "candidate-controlled-exclusion"
    if set(files) != MODES.keys():
        return "inventory-path-mismatch"
    if any(files[path][0] != mode for path, mode in MODES.items()):
        return "undeclared-mode"
    if inventory(files) != expected:
        return "file-digest-mismatch"
    return None


def portable_record_refusal(record):
    """Cross-field constraints on a schema-valid core-v1 record."""
    if record["kind"] == "definition":
        registered = [record["founding_orchestrator"], *record["adopted_harnesses"]]
        if any(profile["harness"] not in registered for profile in record["execution_profiles"].values()):
            return "unregistered-harness"
    if record["kind"] == "checkpoint":
        # Both inventories share one Contents tree. Record the spelling and role
        # of every prefix, including directories implied by multiple files.
        seen = {}
        for entry in record["definition_inventory"] + record["selected_life"]:
            parts = entry["path"].split("/")
            for end in range(1, len(parts) + 1):
                prefix = "/".join(parts[:end])
                key = prefix.lower()  # The schema restricts paths to ASCII.
                directory = end < len(parts)
                if key in seen and (not directory or seen[key] != (prefix, True)):
                    return "inventory-path-conflict"
                seen[key] = (prefix, directory)
    return None


def appendix_files(contents):
    """Inspect physical entries before reading any of the three golden files."""
    if not stat.S_ISDIR(contents.lstat().st_mode):
        raise ValueError("expected a directory: " + str(contents))
    paths = set()
    for path in contents.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("expected a single-link regular file: " + str(path))
        paths.add(path.relative_to(contents).as_posix())
    if paths != MODES.keys():
        raise ValueError("unexpected Appendix C file inventory")
    return {name: (mode, (contents / name).read_bytes()) for name, mode in MODES.items()}


def check_link_refusals(files, report):
    # Git cannot store hard-link relationships. Materialize both cases with the
    # exact expected bytes, so a content-only check would accept either one.
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        contents = base / "Contents"
        (contents / "Resources").mkdir(parents=True)
        for name, (_, data) in files.items():
            (contents / name).write_bytes(data)
        target = base / "target"
        target.write_bytes(files["SoulLock.json"][1])
        entry = contents / "SoulLock.json"
        for kind, link in (("symbolic link", os.symlink), ("hard link", os.link)):
            entry.unlink()
            link(target, entry)
            try:
                appendix_files(contents)
            except ValueError as exc:
                refused = str(exc).startswith("expected a single-link regular file:")
            else:
                refused = False
            report(refused, "Appendix C refuses " + kind + " input")


def check_record_vectors(fixtures, schemas, report):
    vectors = parse_strict((fixtures / "package/core-v1/record-vectors.json").read_bytes())
    for group in vectors:
        base = parse_strict((fixtures / group["base_fixture"]).read_bytes())
        for case in group["cases"]:
            candidate = {**base["input"], **case["replace"]}
            report(schemas[base["schema"]].is_valid(candidate)
                   and portable_record_refusal(candidate) == case["expected_refusal"],
                   "portable core " + case["case"])


def check_portable_package_fixtures(root, schemas, report):
    fixtures = root / "fixtures"
    folder = fixtures / "package/appendix-c"
    vector = parse_strict((folder / "vectors.json").read_text())
    contents = folder / "Contents"
    try:
        files = appendix_files(contents)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"FAIL Appendix C physical inventory: {exc}") from exc
    check_link_refusals(files, report)
    check_record_vectors(fixtures, schemas, report)
    entries = inventory(files)
    report(refusal(files, vector["inventory"]) is None,
           "Appendix C exact paths, portable modes and three file hashes")
    lengths = [len(files[entry["path"]][1]) for entry in entries]
    report(lengths == vector["byte_lengths"] == [29, 54, 16], "Appendix C file lengths")

    preimage = PREFIX + canonicalize(entries)
    revision = sha256(preimage)
    report(vector["preimage_file"] == "preimage.txt" and preimage == (folder / "preimage.txt").read_bytes()
           and len(preimage) == vector["preimage_length"] == 376
           and revision == vector["definition_revision"] == REVISION, "Appendix C revision " + revision)

    def record(path):
        return parse_strict((fixtures / path).read_text())["input"]

    identities = [record(path) for path in vector["identity_fixtures"]]
    soul_ids = [item["soul_id"] for item in identities]
    checkpoint = record(vector["checkpoint_fixture"])
    report(soul_ids == ["urn:uuid:655fc577-804b-4e75-a5d8-70f9a21a19ce",
                        "urn:uuid:2d36cd18-b647-4b71-b673-f0c4ecec5827"]
           and len({item["identity_key_ref"] for item in identities}) == 2
           and all(item["kind"] == "identity" for item in identities)
           and all(item["revision_profile"] == vector["encoding"] == "soul-core-example-1"
                   and item["definition_revision"] == "sha256:" + revision
                   for item in [*identities, checkpoint]), "Appendix C distinct identities bind computed revision")
    report(checkpoint["kind"] == "checkpoint" and checkpoint["soul_id"] == soul_ids[0]
           and checkpoint["definition_inventory"] == entries and checkpoint["selected_life"] == []
           and checkpoint["source_restriction_epoch"] == 0, "Appendix C selected checkpoint")

    # These limited results apply only to these unsigned inputs and the empty lock.
    report(parse_strict(files["SoulInfo.json"][1]) == {"format": vector["encoding"], "layout": "contents-1"}
           and parse_strict(files["SoulLock.json"][1]) == {"artifacts": []}
           and all(item["identity_event_refs"] == [] for item in identities)
           and vector["expected_inspection"] == {
               "definition_integrity": "pass", "identity_authentication": "unverified",
               "restriction_freshness": "unknown", "execution_readiness": "unavailable",
               "protected_content": "not-applicable",
           }, "Appendix C unsigned, unencrypted inspection outcomes")

    template = vector["transfer_selections"]["template"]
    life = vector["transfer_selections"]["life"]
    report(template == {"definition_paths": list(MODES), "template_provenance": {
               "source_soul_id": soul_ids[0], "source_definition_revision": "sha256:" + revision},
               "destination_identity": "new"}
           and life == {"definition_paths": list(MODES), "identity_fixture": vector["identity_fixtures"][0],
                        "checkpoint_fixture": vector["checkpoint_fixture"], "prior_placement": "unresolved",
                        "destination_identity": "preserve"}, "Appendix C template and life selections")

    expected_refusals = set()
    for case in vector["negative_vectors"]:
        candidate = files.copy()
        for path, replacement in case["files"].items():
            candidate[path] = (replacement["mode"], replacement["utf8"].encode("utf-8"))
        reason = refusal(candidate, vector["inventory"])
        expected_refusals.add(reason)
        report(reason is not None and reason == case["expected_refusal"], "Appendix C " + case["case"])
        if reason == "file-digest-mismatch":
            old, new = files["Resources/SOUL.md"][1], candidate["Resources/SOUL.md"][1]
            recomputed = sha256(PREFIX + canonicalize(inventory(candidate)))
            report(len(old) == len(new) and sum(a != b for a, b in zip(old, new)) == 1
                   and revision != recomputed == case["recomputed_revision"], "Appendix C one-byte revision")
        if reason == "candidate-controlled-exclusion":
            manifest = parse_strict(candidate["SoulInfo.json"][1])
            report(any(path not in files and candidate[path][0] == "0755"
                       for path in manifest["exclusions"] if path in candidate),
                   "Appendix C exclusion targets an actual added executable")
    report({"file-digest-mismatch", "duplicate-manifest-key", "candidate-controlled-exclusion"}
           <= expected_refusals, "Appendix C distinct required refusals")
