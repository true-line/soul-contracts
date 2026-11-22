"""Stage 2a canonical measurement vectors; not a filesystem or custody verifier."""
import copy
import hashlib
import json

from jcs import canonicalize, parse_strict

DEFINITION_PURPOSE = b"agent-bot/stage2a-definition-opt-closure/v1"
LAUNCH_PURPOSE = b"agent-bot/stage2a-launch-inputs/v1"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_SYSTEM_IMAGES_BYTES = 512 * 1024
MAX_LAUNCH_OBJECT_BYTES = 1024 * 1024


def bounded_json(value, max_bytes, max_depth=16, max_nodes=4096):
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > max_depth or nodes > max_nodes:
            return False
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return len(canonicalize(value)) <= max_bytes


def domain_digest(records, scope):
    purpose = DEFINITION_PURPOSE if scope == "definition" else LAUNCH_PURPOSE
    return "sha256:" + hashlib.sha256(purpose + b"\0" + canonicalize(records)).hexdigest()


def records_refusal(records, scope, schemas, approved=None, staged=None, preexec=None, host_bytes=None):
    """Reject contradicting fixture claims before hashing; physical checks remain Machine's."""
    if scope not in ("definition", "launch"):
        return "record-scope"
    files = records if scope == "definition" else records.get("files") if isinstance(records, dict) else None
    if isinstance(files, list) and any(isinstance(item, dict) and isinstance(item.get("path"), str)
                                       and "\\" in item["path"] for item in files):
        return "backslash-path"
    schema = schemas[f"machine/v1/{'definition' if scope == 'definition' else 'launch-input'}-records.schema.json"]
    if not schema.is_valid(records):
        return "record-shape-or-limit"
    if scope == "launch" and (not all(bounded_json(records["host_projection"][name], MAX_CONFIG_BYTES)
                                      for name in ("adapters", "installation"))
                               or not bounded_json(records["effective_config"], MAX_CONFIG_BYTES)
                               or not bounded_json(records["environment"], MAX_CONFIG_BYTES)
                               or not bounded_json(records["argv"], MAX_CONFIG_BYTES)
                               or not bounded_json(records["system_images"], MAX_SYSTEM_IMAGES_BYTES)
                               or not bounded_json(records, MAX_LAUNCH_OBJECT_BYTES)):
        return "launch-object-limit"
    paths = [record["path"] for record in files]
    if paths != sorted(paths, key=lambda path: path.encode("utf-8")):
        return "record-order"
    if len(set(paths)) != len(paths) or len(set(path.casefold() for path in paths)) != len(paths):
        return "path-alias"
    if sum(record.get("size", 0) for record in files) > MAX_TOTAL_BYTES:
        return "aggregate-limit"
    if scope == "definition":
        indexed = {record["path"]: record for record in files}
        base = {"Contents", "Contents/SoulInfo.json", "Contents/SoulLock.json", "Contents/primitives", "Contents/opt"}
        if not base.issubset(indexed) or any(
            path not in base and not (path.startswith("Contents/primitives/") or path.startswith("Contents/opt/"))
            for path in paths
        ):
            return "definition-scope"
        if any(indexed[path]["kind"] != ("regular" if path.endswith(".json") and path.startswith("Contents/Soul") else "directory") for path in base):
            return "definition-scope"
        for path in paths:
            parent = path.rpartition("/")[0]
            if parent and (parent not in indexed or indexed[parent]["kind"] != "directory"):
                return "missing-parent-directory"
    else:
        image_paths = [item["path"] for item in records["system_images"]["selected"]]
        if image_paths != sorted(image_paths, key=lambda path: path.encode("utf-8")):
            return "system-image-order"
        if len({path.casefold() for path in image_paths}) != len(image_paths):
            return "system-image-alias"
        if records["argv"][0] != records["selected_command"]:
            return "argv0-command"
        if "B_ONLY_TOKEN" in records["environment"]:
            return "b-only-secret-environment"
        indexed = {record["path"]: record for record in files}
        for field, path in (("adapters", "host/adapters.json"), ("installation", "host/installation.json")):
            raw = host_bytes.get(field) if isinstance(host_bytes, dict) else None
            if path not in indexed or raw is None or len(raw) > MAX_CONFIG_BYTES or \
               indexed[path]["sha256"] != hashlib.sha256(raw).hexdigest():
                return "host-projection-bytes"
            try:
                if parse_strict(raw.decode("utf-8")) != records["host_projection"][field]:
                    return "host-projection-values"
            except (UnicodeError, ValueError):
                return "host-projection-values"
        if records["sandbox_policy_digest"][7:] not in {r["sha256"] for r in files}:
            return "sandbox-policy-bytes"
        if any(value[7:] not in {r["sha256"] for r in files} for value in records["component_digests"].values()):
            return "component-bytes"
    if approved is not None and records != approved:
        return "approved-inventory"
    if staged is not None:
        if set(staged) != set(paths):
            return "custody-inventory"
        inodes = set()
        for record in files:
            path = record["path"]
            seen = staged[path]
            if (seen.get("kind") != record["kind"] or seen.get("mode") != record["mode"]
                    or seen.get("owner_uid") != 0 or seen.get("acl_allow") is not False
                    or seen.get("runner_writable_ancestor") is not False
                    or not isinstance(seen.get("device"), int) or not isinstance(seen.get("inode"), int)
                    or seen["device"] <= 0 or seen["inode"] <= 0):
                return "custody"
            key = (seen["device"], seen["inode"])
            if key in inodes:
                return "inode-alias"
            inodes.add(key)
            if record["kind"] == "regular":
                if (seen.get("nlink") != 1 or seen.get("opened_size") != record["size"]
                        or seen.get("opened_sha256") != record["sha256"]):
                    return "opened-file"
        if preexec is not None and preexec != staged:
            return "snapshot-changed-before-exec"
    return None


def binding_refusal(binding, definition, launch, schemas, *, approved_mapping,
                    installed_plan_digest, expected_package_sha256, expected_installation, expected_start,
                    expected_launch, expected_host, expected_plan, expected_profile, expected_hq_epoch,
                    expected_snapshots):
    if isinstance(binding, dict) and isinstance(binding.get("snapshots"), dict) and any(
        isinstance(snapshot, dict) and isinstance(snapshot.get("root_path"), str)
        and "\\" in snapshot["root_path"] for snapshot in binding["snapshots"].values()
    ):
        return "backslash-path"
    if not schemas["machine/v1/measurement-binding.schema.json"].is_valid(binding):
        return "binding-shape"
    if binding["definition_measurement"] != domain_digest(definition, "definition"):
        return "definition-digest"
    if binding["launch_input_measurement"] != domain_digest(launch, "launch"):
        return "launch-digest"
    if binding["installed_plan_digest"] != installed_plan_digest:
        return "installed-plan"
    if binding["package_sha256"] != expected_package_sha256:
        return "installed-package"
    key = (binding["soul_id"], binding["claimed_definition_digest"], binding["definition_measurement"])
    if key not in approved_mapping:
        return "unapproved-definition-mapping"
    if binding["installation_id"] != expected_installation or binding["start_id"] != expected_start or \
       binding["launch_id"] != expected_launch or \
       binding["host_id"] != expected_host or binding["plan_id"] != expected_plan or \
       binding["profile_in_force"] != expected_profile or binding["hq_epoch"] != expected_hq_epoch:
        return "start-context"
    if launch["effective_config"]["profile"] != binding["profile_in_force"]:
        return "launch-profile"
    d, l = binding["snapshots"]["definition"], binding["snapshots"]["launch_inputs"]
    if d["root_path"] == l["root_path"] or (d["device"], d["inode"]) == (l["device"], l["inode"]):
        return "snapshot-alias"
    if any(int(s["mode"], 8) & 0o222 for s in (d, l)):
        return "writable-snapshot"
    if binding["snapshots"] != expected_snapshots:
        return "snapshot-identity"
    command = launch["selected_command"]
    launch_root, definition_root = l["root_path"], d["root_path"]
    launch_files = {r["path"] for r in launch["files"] if r["kind"] == "regular" and
                    r["path"] not in {"host/adapters.json", "host/installation.json"} and
                    int(r["mode"], 8) & 0o111}
    definition_files = {r["path"] for r in definition if r["kind"] == "regular" and
                        r["path"].startswith("Contents/opt/") and int(r["mode"], 8) & 0o111}
    in_launch = command.startswith(launch_root + "/") and command[len(launch_root) + 1:] in launch_files
    in_definition = command.startswith(definition_root + "/") and command[len(definition_root) + 1:] in definition_files
    if not (in_launch or in_definition):
        return "selected-command-not-measured"
    return None


def check_stage2a_measurement_fixtures(root, schemas, report):
    fixtures = root / "fixtures/positive"
    definition = json.loads((fixtures / "definition-records.stage2a-synthetic.json").read_text())["input"]
    launch = json.loads((fixtures / "launch-input-records.stage2a-synthetic.json").read_text())["input"]
    vector = json.loads((root / "fixtures/measurement/v1/byte-vectors.json").read_text())
    for name, records in (("definition", definition), ("launch-input", launch)):
        raw = (root / f"fixtures/measurement/v1/{name}-records.canonical.json").read_bytes()
        report(raw == canonicalize(records) and not raw.startswith(b"\xef\xbb\xbf") and not raw.endswith(b"\n")
               and parse_strict(raw.decode()) == records,
               f"Stage 2a {name} exact JCS bytes without BOM/newline")
    report(domain_digest(definition, "definition") == vector["definition_measurement"], "Stage 2a definition domain-separated JCS digest")
    report(domain_digest(launch, "launch") == vector["launch_inputs_measurement"], "Stage 2a launch-input domain-separated JCS digest")
    report(domain_digest(definition, "definition") != domain_digest(definition, "launch"), "Stage 2a digest domains are distinct")
    def staged_facts(records, offset):
        facts = {}
        for index, record in enumerate(records):
            item = {"kind": record["kind"], "mode": record["mode"], "owner_uid": 0,
                    "acl_allow": False, "runner_writable_ancestor": False,
                    "device": 1, "inode": offset + index}
            if record["kind"] == "regular":
                item.update(nlink=1, opened_size=record["size"], opened_sha256=record["sha256"])
            facts[record["path"]] = item
        return facts

    staged = staged_facts(definition, 1000)
    launch_staged = staged_facts(launch["files"], 2000)
    host_bytes = {name: canonicalize(launch["host_projection"][name]) for name in ("adapters", "installation")}
    report(records_refusal(definition, "definition", schemas, definition, staged, copy.deepcopy(staged)) is None,
           "Stage 2a synthetic exact inventory and staged/pre-exec custody")
    report(records_refusal(launch, "launch", schemas, launch, launch_staged, copy.deepcopy(launch_staged), host_bytes) is None,
           "Stage 2a synthetic root-owned launch projection custody")
    spaced_launch = copy.deepcopy(launch)
    spaced_bytes = {**host_bytes, "adapters": host_bytes["adapters"] + b" "}
    spaced_record = next(r for r in spaced_launch["files"] if r["path"] == "host/adapters.json")
    spaced_record["size"] = len(spaced_bytes["adapters"])
    spaced_record["sha256"] = hashlib.sha256(spaced_bytes["adapters"]).hexdigest()
    spaced_staged = staged_facts(spaced_launch["files"], 2000)
    report(records_refusal(spaced_launch, "launch", schemas, spaced_launch, spaced_staged,
                           copy.deepcopy(spaced_staged), spaced_bytes) is None,
           "Stage 2a accepts exact raw noncanonical host JSON bytes with equal parsed values")
    oversized_bytes = {**host_bytes, "adapters": host_bytes["adapters"] + b" " * (MAX_CONFIG_BYTES + 1)}
    oversized_launch = copy.deepcopy(launch)
    oversized_record = next(r for r in oversized_launch["files"] if r["path"] == "host/adapters.json")
    oversized_record["size"] = len(oversized_bytes["adapters"])
    oversized_record["sha256"] = hashlib.sha256(oversized_bytes["adapters"]).hexdigest()
    oversized_staged = staged_facts(oversized_launch["files"], 2000)
    report(records_refusal(oversized_launch, "launch", schemas, oversized_launch, oversized_staged,
                           copy.deepcopy(oversized_staged), oversized_bytes) == "host-projection-bytes",
           "Stage 2a refuses oversized raw host JSON despite valid parsed values")
    cases = json.loads((root / "fixtures/measurement/v1/negative-vectors.json").read_text())
    for case in cases:
        target = copy.deepcopy(definition if case["scope"] == "definition" else launch)
        target_files = target if case["scope"] == "definition" else target["files"]
        expected = case["expect"]
        candidate_staged = copy.deepcopy(staged if case["scope"] == "definition" else launch_staged)
        preexec = copy.deepcopy(candidate_staged)
        op = case["mutation"]
        if op == "reverse": target_files.reverse()
        elif op == "omit-opt": target = [r for r in target if r["path"] != "Contents/opt/quickstart-adapter.mjs"]
        elif op == "extra-opt": target.append({"path": "Contents/opt/z.mjs", "kind": "regular", "mode": "0444", "size": 1, "sha256": "0" * 64}); target.sort(key=lambda r: r["path"].encode())
        elif op == "changed-bytes": target_files[-1]["sha256"] = "0" * 64
        elif op == "changed-mode": target_files[-1]["mode"] = "0644"
        elif op == "case-alias": target.append({"path": "Contents/opt/Quickstart-adapter.mjs", "kind": "regular", "mode": "0444", "size": 1, "sha256": "0" * 64}); target.sort(key=lambda r: r["path"].encode())
        elif op == "writable-checker": target.append({"path": "Contents/workspaces/scratch/check.mjs", "kind": "regular", "mode": "0444", "size": 1, "sha256": "0" * 64}); target.sort(key=lambda r: r["path"].encode())
        elif op == "aggregate-limit":
            for r in target:
                if r["kind"] == "regular": r["size"] = MAX_FILE_BYTES
            target.append({"path": "Contents/opt/z.mjs", "kind": "regular", "mode": "0444", "size": 1, "sha256": "0" * 64}); target.sort(key=lambda r: r["path"].encode())
        elif op == "definition-entry-limit":
            target.extend({"path": f"Contents/opt/extra-{i:03}.mjs", "kind": "regular", "mode": "0444", "size": 0, "sha256": "0" * 64}
                          for i in range(513 - len(target)))
            target.sort(key=lambda r: r["path"].encode())
        elif op == "launch-entry-limit":
            target_files.extend({"path": f"modules/extra-{i:03}.mjs", "kind": "regular", "mode": "0444", "size": 0, "sha256": "0" * 64}
                                for i in range(65 - len(target_files)))
            target_files.sort(key=lambda r: r["path"].encode())
        elif op == "launch-aggregate-limit":
            for r in target_files: r["size"] = MAX_FILE_BYTES
            target_files.append({"path": "modules/extra.mjs", "kind": "regular", "mode": "0444", "size": 1, "sha256": "0" * 64})
            target_files.sort(key=lambda r: r["path"].encode())
        elif op == "duplicate-path": target.append(copy.deepcopy(target[-1]))
        elif op == "unicode-path": target[-1]["path"] = "Contents/opt/é.mjs"
        elif op == "dot-component": target[-1]["path"] = "Contents/opt/../opt/check.mjs"
        elif op == "backslash-path": target[-1]["path"] = "Contents/opt/alias\\check.mjs"
        elif op == "hard-link": candidate_staged[target_files[-1]["path"]]["nlink"] = 2
        elif op == "inode-alias": candidate_staged[target_files[-1]["path"]]["inode"] = candidate_staged[target_files[-2]["path"]]["inode"]
        elif op == "acl-allow": candidate_staged[target_files[-1]["path"]]["acl_allow"] = True
        elif op == "writable-ancestor": candidate_staged[target_files[-1]["path"]]["runner_writable_ancestor"] = True
        elif op == "inode-swap": preexec[target_files[-1]["path"]]["inode"] += 1
        elif op == "changed-launch-input": target_files[0]["sha256"] = "0" * 64
        elif op == "changed-launch-path": target_files[0]["path"] = "bin/other-node"; target_files.sort(key=lambda r: r["path"].encode())
        elif op == "missing-launch-input": target_files.pop()
        elif op == "argv-tail": target["argv"][-1] = "--changed"
        elif op == "argv0": target["argv"][0] = "/private/stage2a/snapshot-launch/bin/other-node"
        elif op == "environment": target["environment"]["HOME"] = "/private/stage2a/other-home"
        elif op == "b-only-env": target["environment"]["B_ONLY_TOKEN"] = "fixture-secret"
        elif op == "effective-config": target["effective_config"]["profile"] = "managed-cooperative"
        elif op == "selected-command": target["selected_command"] = "/private/stage2a/snapshot-launch/bin/adapter"
        elif op == "selected-command-and-argv0":
            target["selected_command"] = "/private/stage2a/snapshot-launch/bin/adapter"
            target["argv"][0] = target["selected_command"]
        elif op == "system-build": target["system_images"]["build_version"] = "24G208"
        elif op == "system-signing": target["system_images"]["selected"][0]["signing_requirement"] = "anchor other"
        elif op == "system-cdhash": target["system_images"]["selected"][0]["cdhash"] = "f" * 40
        elif op == "system-image-order": target["system_images"]["selected"].reverse()
        elif op == "system-image-alias":
            image = copy.deepcopy(target["system_images"]["selected"][0])
            image["path"] = image["path"].lower()
            target["system_images"]["selected"].append(image)
            target["system_images"]["selected"].sort(key=lambda r: r["path"].encode())
        elif op == "host-projection-limit": target["host_projection"]["adapters"]["oversized"] = "x" * (MAX_CONFIG_BYTES + 1)
        elif op == "effective-config-limit": target["effective_config"]["oversized"] = "x" * (MAX_CONFIG_BYTES + 1)
        elif op == "host-projection": target["host_projection"]["adapters"]["selected"] = "other-adapter"
        elif op == "sandbox-policy": target["sandbox_policy_digest"] = "sha256:" + "0" * 64
        elif op == "component-bridge": target["component_digests"]["bridge"] = "sha256:" + "0" * 64
        elif op == "component-comms": target["component_digests"]["comms_broker"] = "sha256:" + "0" * 64
        else: raise ValueError("unknown fixture mutation " + op)
        actual = records_refusal(target, case["scope"], schemas,
                                 definition if case["scope"] == "definition" else launch,
                                 candidate_staged, preexec, host_bytes if case["scope"] == "launch" else None)
        report(actual == expected, "Stage 2a refuses " + case["name"], f"expected {expected}, got {actual}")
        if case["scope"] == "launch" and op in ("argv-tail", "argv0", "selected-command",
                                                "selected-command-and-argv0", "environment", "effective-config",
                                                "system-build", "system-signing", "system-cdhash", "host-projection", "sandbox-policy",
                                                "component-bridge", "component-comms"):
            report(domain_digest(target, "launch") != vector["launch_inputs_measurement"],
                   "Stage 2a launch digest changes for " + case["name"])

    binding = json.loads((fixtures / "measurement-binding.stage2a-synthetic.json").read_text())["input"]
    mapping = {(binding["soul_id"], binding["claimed_definition_digest"], binding["definition_measurement"])}
    context = {"approved_mapping": mapping, "installed_plan_digest": binding["installed_plan_digest"],
               "expected_package_sha256": binding["package_sha256"],
               "expected_installation": binding["installation_id"], "expected_start": binding["start_id"],
               "expected_launch": binding["launch_id"],
               "expected_host": binding["host_id"], "expected_plan": binding["plan_id"],
               "expected_profile": binding["profile_in_force"], "expected_hq_epoch": binding["hq_epoch"],
               "expected_snapshots": copy.deepcopy(binding["snapshots"])}
    report(binding_refusal(binding, definition, launch, schemas, **context) is None,
           "Stage 2a per-start binding matches accepted mapping and distinct snapshots")
    opt_launch = copy.deepcopy(launch)
    opt_command = binding["snapshots"]["definition"]["root_path"] + "/Contents/opt/quickstart-check.mjs"
    opt_launch["selected_command"] = opt_command
    opt_launch["argv"][0] = opt_command
    opt_binding = copy.deepcopy(binding)
    opt_binding["launch_input_measurement"] = domain_digest(opt_launch, "launch")
    report(records_refusal(opt_launch, "launch", schemas, opt_launch, launch_staged,
                           copy.deepcopy(launch_staged), host_bytes) is None
           and binding_refusal(opt_binding, definition, opt_launch, schemas, **context) is None,
           "Stage 2a accepts measured frozen opt command under definition snapshot")
    unmeasured_launch = copy.deepcopy(launch)
    unmeasured_launch["selected_command"] = "/private/stage2a/runner-home/check.mjs"
    unmeasured_launch["argv"][0] = unmeasured_launch["selected_command"]
    unmeasured_binding = copy.deepcopy(binding)
    unmeasured_binding["launch_input_measurement"] = domain_digest(unmeasured_launch, "launch")
    report(binding_refusal(unmeasured_binding, definition, unmeasured_launch, schemas, **context)
           == "selected-command-not-measured", "Stage 2a refuses unmeasured writable command after resealed digest")
    nonexec_launch = copy.deepcopy(launch)
    next(r for r in nonexec_launch["files"] if r["path"] == "bin/node")["mode"] = "0444"
    nonexec_binding = copy.deepcopy(binding)
    nonexec_binding["launch_input_measurement"] = domain_digest(nonexec_launch, "launch")
    report(binding_refusal(nonexec_binding, definition, nonexec_launch, schemas, **context)
           == "selected-command-not-measured", "Stage 2a refuses nonexecutable selected command after resealed digest")
    cooperative = copy.deepcopy(binding)
    cooperative_launch = copy.deepcopy(launch)
    cooperative_launch["effective_config"]["profile"] = "managed-cooperative"
    cooperative["start_id"] = "st_" + "3" * 24
    cooperative["launch_id"] = "ln_" + "4" * 24
    cooperative["profile_in_force"] = "managed-cooperative"
    cooperative["launch_input_measurement"] = domain_digest(cooperative_launch, "launch")
    coop_context = {**context, "expected_start": cooperative["start_id"],
                    "expected_launch": cooperative["launch_id"], "expected_profile": cooperative["profile_in_force"]}
    report(binding_refusal(cooperative, definition, cooperative_launch, schemas, **coop_context) is None,
           "Stage 2a T21 reuses frozen definition with separate start/profile/launch inputs")
    binding_cases = json.loads((root / "fixtures/measurement/v1/binding-negative-vectors.json").read_text())
    for case in binding_cases:
        changed = copy.deepcopy(binding)
        op = case["mutation"]
        if op == "definition-digest": changed["definition_measurement"] = "sha256:" + "0" * 64
        elif op == "launch-digest": changed["launch_input_measurement"] = "sha256:" + "0" * 64
        elif op == "claim": changed["claimed_definition_digest"] = "sha256:" + "0" * 64
        elif op == "plan": changed["installed_plan_digest"] = "0" * 64
        elif op == "package": changed["package_sha256"] = "0" * 64
        elif op == "installation": changed["installation_id"] = "other-installation"
        elif op == "start": changed["start_id"] = "st_" + "9" * 24
        elif op == "launch": changed["launch_id"] = "ln_" + "9" * 24
        elif op == "profile": changed["profile_in_force"] = "managed-cooperative"
        elif op == "epoch": changed["hq_epoch"] = "0" * 64
        elif op == "host": changed["host_id"] = "other-host"
        elif op == "plan-id": changed["plan_id"] = "other-plan"
        elif op == "same-snapshot": changed["snapshots"]["launch_inputs"] = copy.deepcopy(changed["snapshots"]["definition"])
        elif op == "writable-snapshot": changed["snapshots"]["definition"]["mode"] = "0755"
        elif op == "snapshot-inode": changed["snapshots"]["definition"]["inode"] = "9999"
        elif op == "snapshot-generation": changed["snapshots"]["launch_inputs"]["generation"] = "9999"
        elif op == "snapshot-path": changed["snapshots"]["launch_inputs"]["root_path"] = "/private/stage2a/other-launch"
        elif op == "snapshot-backslash": changed["snapshots"]["launch_inputs"]["root_path"] = "/private/stage2a/alias\\launch"
        else: raise ValueError("unknown binding mutation " + op)
        actual = binding_refusal(changed, definition, launch, schemas, **context)
        report(actual == case["expect"], "Stage 2a binding refuses " + case["name"],
               f"expected {case['expect']}, got {actual}")
