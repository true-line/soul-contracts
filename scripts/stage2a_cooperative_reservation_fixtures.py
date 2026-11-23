"""Cooperative reservation vectors and cross-field checks."""

import base64
import copy
import hashlib
from pathlib import PurePosixPath
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jcs import canonicalize, parse_strict
from stage2a_hr_v3_fixtures import H_PURPOSE, inventory_ref, signed_payload

PURPOSE = b"agent-bot/soul-cooperative-reservation/v3"
BRIDGE_PURPOSE = b"agent-bot/soul-cooperative-bridge-assignment/v3"
LAUNCH_PURPOSE = b"agent-bot/stage2a-cooperative-launch-inputs/v3"
H_ENVELOPE = "machine/v3/h-service-descriptor-signed.schema.json"
H_PAYLOAD = "machine/v3/h-service-descriptor-payload.schema.json"
INVENTORY = "machine/v3/domain-inventory.schema.json"
INVENTORY_REF = "machine/v3/inventory-ref.schema.json"
PAYLOAD = "machine/v3/soul-cooperative-reservation-payload.schema.json"
ENVELOPE = "machine/v3/soul-cooperative-signed-reservation.schema.json"
BRIDGE_PAYLOAD = "machine/v3/soul-cooperative-bridge-assignment-payload.schema.json"
BRIDGE_ENVELOPE = "machine/v3/soul-cooperative-bridge-signed-assignment.schema.json"


def decode(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def topology_matches(payload, private_assignment=None):
    assignment = payload["assignment"]
    endpoints = payload["endpoints"]
    h = assignment["hq_uid"]
    r = assignment["runner_uid"]
    rg = assignment["runner_gid"]
    expected = {"admission": (h, rg, r), "broker": (h, rg, r)}
    if private_assignment is not None:
        bridge = private_assignment["bridge"]
        b, bg = bridge["uid"], bridge["gid"]
        if b in (h, r, assignment["machine_uid"]) or bg == rg or bridge["account"] == assignment["runner_account"]:
            return False
        if bridge["state_root"] == assignment["state_root"] or bridge["argv"][0] != bridge["executable_path"]:
            return False
        private_endpoints = private_assignment["endpoints"]
        if any(private_endpoints[name] != endpoints[name] for name in ("member", "relay")):
            return False
        endpoints = {**endpoints, "broker": private_endpoints["broker"]}
        expected.update(broker=(h, bg, b), member=(r, bg, b), relay=(b, rg, r))

    if set(endpoints) != set(expected):
        return False
    paths = set()
    for name, endpoint in endpoints.items():
        if (endpoint["owner_uid"], endpoint["group_gid"], endpoint["expected_peer_uid"]) != expected[name]:
            return False
        socket = PurePosixPath(endpoint["socket_path"])
        if socket.parent != PurePosixPath(endpoint["directory"]) or socket in paths:
            return False
        paths.add(socket)
    return True


def bridge_assignment_matches(payload, private_assignment, envelope_raw):
    assignment = payload["assignment"]
    return (
        payload["adapter_transport"] == "brokered-b"
        and private_assignment["reservation_sha256"] == digest(envelope_raw)
        and all(private_assignment[field] == payload[field] for field in ("host_id", "expires_at"))
        and all(private_assignment[field] == assignment[field]
                for field in ("installation_id", "start_id", "launch_id", "plan_id", "plan_digest", "hq_epoch"))
        and payload["bridge_launch_sha256"] == private_assignment["bridge_launch_sha256"]
        and private_assignment["bridge_launch_sha256"] == digest(canonicalize(private_assignment["bridge"]))
        and topology_matches(payload, private_assignment)
    )


def qualification_provider_matches(payload, launch_records):
    provider = payload.get("qualification_provider")
    measured = launch_records["effective_config"].get("qualification_provider_config_sha256")
    if provider is None:
        return measured is None
    return measured == provider["config_sha256"]


def check_stage2a_cooperative_reservation_fixtures(root, schemas, report):
    vectors = root / "fixtures/reservation/v3"
    for vector_type in ("synthetic", "brokered-b.synthetic"):
        check_reservation(root, vectors / f"soul-cooperative-signed-reservation.{vector_type}.json", schemas, report)


def check_reservation(root, path, schemas, report):
    try:
        vector = parse_strict(path.read_bytes())
        envelope_raw = vector["reservation_envelope_jcs"].encode()
        envelope = parse_strict(envelope_raw)
        require(canonicalize(envelope) == envelope_raw, "envelope must be exact JCS bytes")
        require(schemas[ENVELOPE].is_valid(envelope), "purpose-separated envelope shape")
        payload_raw = decode(envelope["payload_base64url"])
        require(payload_raw == vector["reservation_payload_jcs"].encode(), "exact payload bytes")
        require(digest(payload_raw) == envelope["payload_sha256"], "payload digest")
        payload = parse_strict(payload_raw)
        require(canonicalize(payload) == payload_raw, "payload must be exact JCS bytes")
        require(schemas[PAYLOAD].is_valid(payload), "cooperative payload schema")
        challenge = decode(vector["admission_challenge_base64url"])
        require(len(challenge) == 32 and digest(challenge) == payload["admission_challenge_sha256"],
                "synthetic admission challenge preimage matches signed digest")
        public_key = decode(envelope["issuer_public_key_base64url"])
        require(public_key == decode(vector["issuer_public_key_base64url"]), "pinned synthetic issuer key")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            decode(envelope["signature_base64url"]), PURPOSE + b"\0" + payload_raw)

        private_assignment = None
        if payload["adapter_transport"] == "brokered-b":
            private_raw = vector["bridge_envelope_jcs"].encode()
            private_envelope = parse_strict(private_raw)
            require(canonicalize(private_envelope) == private_raw, "private assignment envelope is exact JCS")
            private_assignment, _ = signed_payload(
                private_envelope, BRIDGE_PURPOSE, schemas[BRIDGE_ENVELOPE], schemas[BRIDGE_PAYLOAD], public_key)
            require(bridge_assignment_matches(payload, private_assignment, envelope_raw),
                    "private B authority joins the exact signed primary, launch commitment and endpoints")

        # Re-open the same static H descriptor and sidecar named by the signed binding.
        h_envelope_raw = vector["h_envelope_jcs"].encode()
        h_envelope = parse_strict(h_envelope_raw)
        h_payload, h_raw = signed_payload(
            h_envelope, H_PURPOSE, schemas[H_ENVELOPE], schemas[H_PAYLOAD],
            decode(vector["h_issuer_public_key_base64url"]))
        require(canonicalize(h_envelope) == h_envelope_raw and h_raw == vector["h_payload_jcs"].encode(),
                "exact H descriptor envelope and payload")
        h_digest = digest(H_PURPOSE + b"\0" + h_raw)
        require(h_digest == vector["h_descriptor_digest"], "purpose-separated H descriptor digest")
        require(h_digest == payload["measurement_binding"]["h_service_descriptor_digest"],
                "H descriptor digest bound by reservation")
        h_inventory = parse_strict(vector["h_inventory_jcs"])
        inventory_ref(h_inventory, h_payload["h_inventory"], schemas)

        # Exact complete R sidecar and cooperative input records accompany the signed refs.
        r_vector_path = root / vector["r_inventory_fixture"]
        launch_vector_path = root / vector["launch_input_fixture"]
        fixture_type = "brokered-b.synthetic" if payload["adapter_transport"] == "brokered-b" else "synthetic"
        require(r_vector_path == root / "fixtures/reservation/v3/soul-cooperative-r-inventory.synthetic.json" and
                launch_vector_path == root / f"fixtures/reservation/v3/soul-cooperative-launch-inputs.{fixture_type}.json",
                "fixed in-tree inventory and launch-input fixtures")
        r_vector = parse_strict(r_vector_path.read_bytes())
        r_inventory = parse_strict(r_vector["inventory_jcs"])
        r_ref = r_vector["reference"]
        inventory_ref(r_inventory, r_ref, schemas)
        require(r_ref == payload["measurement_binding"]["r_inventory"], "exact R reference equals signed binding")
        require(schemas[INVENTORY].is_valid(r_inventory) and schemas[INVENTORY_REF].is_valid(r_ref),
                "R inventory and reference schemas")
        launch_vector = parse_strict(launch_vector_path.read_bytes())
        launch_raw = launch_vector["records_jcs"].encode()
        launch_records = parse_strict(launch_raw)
        require(canonicalize(launch_records) == launch_raw, "launch-input records are exact JCS bytes")
        launch_ref = "https://true-line.ai/soul-contracts/machine/v3/soul-cooperative-reservation-payload.schema.json#/$defs/cooperativeLaunchInputRecords"
        launch_validator = schemas[PAYLOAD].evolve(schema={"$ref": launch_ref})
        require(launch_validator.is_valid(launch_records), "cooperative launch-input schema")
        require(len(launch_raw) <= 1_048_576, "cooperative launch-input JCS size bound")
        launch_digest = digest(LAUNCH_PURPOSE + b"\0" + launch_raw)
        require(launch_vector["domain"] == LAUNCH_PURPOSE.decode() and launch_vector["sha256"] == launch_digest and
                launch_digest == payload["measurement_binding"]["launch_input_measurement"],
                "purpose-separated launch-input digest equals signed binding")

        assignment, binding, endpoints = payload["assignment"], payload["measurement_binding"], payload["endpoints"]
        require(binding["profile_in_force"] == "managed-cooperative", "cooperative-only measurement profile")
        require(payload["host_id"] == binding["host_id"], "host binding")
        require(assignment["expires_at"] == payload["expires_at"], "assignment lease expiry binding")
        require(datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00")) <
                datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00")) <=
                datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00")) + timedelta(seconds=30),
                "one-use lease is positive and at most 30 seconds")
        for field in ("installation_id", "soul_id", "start_id", "launch_id", "plan_id", "hq_epoch"):
            require(assignment[field] == binding[field], field + " binding")
        require(assignment["plan_digest"] == binding["installed_plan_digest"], "installed plan digest binding")
        require(assignment["package_sha256"] == binding["package_sha256"] and
                assignment["soul_artifact_sha256"] == binding["soul_artifact_sha256"], "artifact binding")
        require(assignment["package_root"] == binding["snapshots"]["definition"]["root_path"],
                "package root binds frozen definition snapshot")
        require(assignment["launch_inputs_root"] == binding["snapshots"]["launch_inputs"]["root_path"],
                "launch inputs root binds frozen launch-input snapshot")
        inventory_binding = binding["r_inventory"]
        require(inventory_binding["domain"] == "R-runtime", "R installed inventory reference")
        require(inventory_binding["installation_id"] == assignment["installation_id"], "R installation binding")
        require(inventory_binding["owner_plan_digest"] == "sha256:" + assignment["plan_digest"], "R plan binding")
        require(inventory_binding["reader_uid"] == assignment["runner_uid"] and
                inventory_binding["reader_gid"] == assignment["runner_gid"], "runner and R inventory binding")
        require(assignment["runtime_root"] == inventory_binding["snapshot"]["path"],
                "runtime root binds sealed R inventory snapshot")
        require(assignment["node_path"] == assignment["runtime_root"].rstrip("/") + "/bin/node" and
                assignment["entry_path"] == assignment["runtime_root"].rstrip("/") + "/bin/agent-bot-souls.mjs",
                "fixed Node and entry paths inside R runtime")
        require(assignment["state_root"] == f"/private/var/agent-bot-soul-runner-{assignment['runner_account']}/state" and
                assignment["state_root_mode"] == "0700", "dedicated external runner state path and mode")
        require(binding["h_service_descriptor_digest"], "H descriptor digest is bound")
        require(topology_matches(payload, private_assignment), "assigned endpoint ownership, peer and path topology")
        require(launch_records["adapter_transport"] == payload["adapter_transport"],
                "signed adapter transport equals measured launch transport")
        require(launch_records.get("bridge_launch_sha256") == payload.get("bridge_launch_sha256"),
                "signed B launch commitment equals measured launch-input record")
        admission_directory = PurePosixPath(endpoints["admission"]["directory"])
        start_slot = hashlib.sha256(b"agent-bot-soul-endpoint-start/v1\0" +
                                    assignment["installation_id"].encode() + b"\0" +
                                    assignment["start_id"].encode()).hexdigest()[:20]
        require(admission_directory.parent.name == "c" and
                PurePosixPath(endpoints["admission"]["socket_path"]).name == start_slot + ".sock",
                "cooperative admission uses the per-installation c/start path")
        argv = [assignment["node_path"], assignment["entry_path"], "run", "--soul", assignment["package_root"],
                "--admission-socket", endpoints["admission"]["socket_path"]]
        if payload["adapter_transport"] == "direct-comms":
            broker_directory = "/Library/Application Support/ai.true-line.agent-bot-hq/broker/" + assignment["runner_account"]
            require(endpoints["broker"]["directory"] == broker_directory and
                    endpoints["broker"]["socket_path"] == broker_directory + "/broker.sock",
                    "direct broker path is H-owned and scoped to the assigned runner account")
            argv += ["--broker-socket", endpoints["broker"]["socket_path"]]
        else:
            argv += ["--member-socket", endpoints["member"]["socket_path"],
                     "--relay-socket", endpoints["relay"]["socket_path"]]
        argv += ["--profile", "managed-cooperative", "--cooperative-start-fd", "3"]
        require(launch_records["selected_command"] == assignment["node_path"] and
                launch_records["argv"] == argv, "complete launch inputs bind fixed T21 argv")
        require(launch_records["environment"].get("PATH") == "/usr/bin:/bin" and
                launch_records["environment"].get("AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH") == "1" and
                launch_records["environment"].get("HOME") == assignment["state_root"],
                "fixed cooperative environment and HQ launch guard")
        require(launch_records["host_projection"]["installation"].get("id") == assignment["installation_id"],
                "host projection binds the selected installation")
        launch_files = {row["path"]: row for row in launch_records["files"]}
        inventory_files = {row["path"]: row for row in r_inventory["files"]}
        for relpath, fullpath in (("bin/node", assignment["node_path"]),
                                  ("bin/agent-bot-souls.mjs", assignment["entry_path"])):
            row = inventory_files.get(relpath)
            require(row is not None and
                    fullpath == assignment["runtime_root"].rstrip("/") + "/" + relpath and
                    row["component_id"] == "souls", relpath + " exact R sidecar row")
        package_json_row = inventory_files.get("package.json")
        package_json_bytes = r_vector["package_json_bytes"].encode()
        package_json = parse_strict(package_json_bytes)
        require(package_json_row is not None and package_json_row["mode"] == "0440" and
                package_json_row["component_id"] == "souls" and
                package_json_row["size_bytes"] == len(package_json_bytes) and
                package_json_row["sha256"] == digest(package_json_bytes) and
                isinstance(package_json.get("version"), str) and package_json["version"],
                "CLI package.json version is in the sealed R inventory")
        require("package.json" not in launch_files and
                "bin/node" not in launch_files and "bin/agent-bot-souls.mjs" not in launch_files,
                "launch-input snapshot does not duplicate A-sealed R closure bytes")
        require(set(launch_records["component_digests"]) ==
                {"machine", "hq", "souls", "comms_broker", "adapter", "harness", "test_provider"},
                "T21 qualification vector pins all seven H/R/Q components")
        ordinary_components = copy.deepcopy(launch_records["component_digests"])
        ordinary_components.pop("harness")
        ordinary_components.pop("test_provider")
        ordinary_launch = copy.deepcopy(launch_records)
        ordinary_launch["component_digests"] = ordinary_components
        ordinary_launch["effective_config"].pop("qualification_provider_config_sha256")
        require(launch_validator.is_valid(ordinary_launch), "ordinary cooperative schema does not require installed harnesses")
        partial_q = copy.deepcopy(launch_records)
        partial_q["component_digests"].pop("harness")
        require(not launch_validator.is_valid(partial_q), "qualification harness and test provider are paired")
        h_components = {component["component_id"]: component for component in h_payload["components"]}
        h_rows = {row["path"]: row for row in h_inventory["files"]}
        r_rows = {row["path"]: row for row in r_inventory["files"]}
        hq_broker = binding["hq_broker"]
        # The inventory sidecar is separate from its signed compact reference.
        h_prefix = h_payload["h_inventory"]["snapshot"]["path"]
        broker_relative_path = "vendor/plugins/agent-comms/lib/hq-plugin/broker.mjs"
        broker_component = h_components.get("comms_broker", {})
        broker_manifest = vector["h_broker_release_manifest"]
        require(digest(canonicalize(broker_manifest)) == broker_component.get("release_manifest_sha256") and
                broker_manifest == [{"path": broker_relative_path, "sha256": hq_broker["module_sha256"]}],
                "H component provenance binds exact hosted broker row")
        require(hq_broker["module_path"] == h_prefix + "/" + broker_relative_path and
                h_rows.get(broker_relative_path, {}).get("sha256") == hq_broker["module_sha256"] and
                h_rows.get(broker_relative_path, {}).get("component_id") == "comms_broker" and
                broker_component.get("release_artifact_sha256") == hq_broker["module_sha256"] and
                hq_broker["module_sha256"] == "sha256:15efd590844f747f279ae4089178bca134f7ae76e9911a7ed5fea8d3310452a1",
                "same-process Comms broker module is an H descriptor component and H-sealed inventory row")
        qualification_provider = payload["qualification_provider"]
        provider_raw = decode(qualification_provider["config_base64url"])
        provider_config = parse_strict(provider_raw)
        require(canonicalize(provider_config) == provider_raw and digest(provider_raw) == qualification_provider["config_sha256"] and
                set(provider_config) == {"model", "request_sha256", "response_text"} and
                provider_config["request_sha256"].startswith("sha256:"),
                "exact canonical Machine qualification provider config bytes are digest-bound")
        require(qualification_provider_matches(payload, launch_records),
                "measured effective config binds exact canonical qualification provider bytes")
        missing_provider_digest = copy.deepcopy(launch_records)
        del missing_provider_digest["effective_config"]["qualification_provider_config_sha256"]
        require(not launch_validator.is_valid(missing_provider_digest),
                "qualification launch inputs require measured provider config digest")
        wrong_provider_digest = copy.deepcopy(launch_records)
        wrong_provider_digest["effective_config"]["qualification_provider_config_sha256"] = digest(b"wrong provider config")
        require(launch_validator.is_valid(wrong_provider_digest) and
                not qualification_provider_matches(payload, wrong_provider_digest),
                "wrong measured provider digest reaches the cross-field equality check")
        adapter = binding["adapter_release"]
        require(adapter["executable_path"] == assignment["runtime_root"] + "/adapter/cli" and
                adapter["executable_sha256"] == r_rows["adapter/cli"]["sha256"],
                "adapter executable pin joins to its A-sealed R row")
        h_entry = h_payload["runtime"]["entry_path"]
        require(h_entry == h_prefix + "/hq/main.mjs" and
                h_rows.get("hq/main.mjs", {}).get("sha256") == h_payload["runtime"]["entry_sha256"],
                "H selected HQ entry joins to the H-sealed row")
        require(launch_records["component_digests"]["souls"] == r_rows["bin/agent-bot-souls.mjs"]["sha256"] and
                launch_records["component_digests"]["adapter"] == r_rows["adapter/cli"]["sha256"] and
                launch_records["component_digests"]["hq"] == h_payload["runtime"]["entry_sha256"] and
                launch_records["component_digests"]["comms_broker"] == hq_broker["module_sha256"],
                "component digests join to authenticated launched code rows")
        require("broker_executable" not in binding, "cooperative reservation has no protected B broker executable")
        require(set(hq_broker) == {"module_path", "module_sha256"},
                "ordinary H-hosted broker binding carries only H module identity")
        require({"harness", "test_provider"} <= set(launch_records["component_digests"]) and
                "qualification_provider" in payload,
                "Q qualification provider config is present only with its paired Q component pins")

        protected_payload = copy.deepcopy(payload)
        protected_envelope = copy.deepcopy(envelope)
        protected_envelope["purpose"] = "agent-bot/stage2a-reservation/v3"
        require(not schemas[ENVELOPE].is_valid(protected_envelope), "protected purpose cannot authorize cooperative payload")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                decode(envelope["signature_base64url"]), b"agent-bot/stage2a-reservation/v3\0" + payload_raw)
        except InvalidSignature:
            pass
        else:
            raise ValueError("protected purpose must not verify the cooperative signature")
        require(not schemas["machine/v3/stage2a-reservation-payload.schema.json"].is_valid(protected_payload),
                "protected reservation schema refuses cooperative payload")
        if private_assignment is None:
            wrong_peer = copy.deepcopy(payload)
            wrong_peer["endpoints"]["broker"]["expected_peer_uid"] += 1
            require(schemas[PAYLOAD].is_valid(wrong_peer), "wrong peer fixture reaches semantic binding check")
            require(not topology_matches(wrong_peer), "wrong broker peer is rejected by runner binding")
        else:
            check_b_refusals(payload, private_assignment, envelope_raw, schemas)
        bridged = copy.deepcopy(payload)
        bridged["assignment"]["bridge_uid"] = 333
        require(not schemas[PAYLOAD].is_valid(bridged), "cooperative schema refuses legacy assignment bridge claims")
        report(True, str(path.relative_to(root)))
    except (KeyError, OSError, ValueError, InvalidSignature) as exc:
        report(False, str(path.relative_to(root)), str(exc))


def check_b_refusals(payload, private_assignment, envelope_raw, schemas):
    primary_schema, private_schema = schemas[PAYLOAD], schemas[BRIDGE_PAYLOAD]
    for field in ("adapter_transport", "bridge_launch_sha256"):
        missing = copy.deepcopy(payload)
        del missing[field]
        require(not primary_schema.is_valid(missing), f"B reservation requires {field}")
    leaked = copy.deepcopy(payload)
    leaked["endpoints"]["broker"] = private_assignment["endpoints"]["broker"]
    require(not primary_schema.is_valid(leaked), "R-visible B reservation refuses the private H broker")
    direct = copy.deepcopy(payload)
    direct["adapter_transport"] = "direct-comms"
    require(not primary_schema.is_valid(direct), "direct transport refuses B commitments and endpoints")
    for name in ("member", "relay"):
        missing = copy.deepcopy(payload)
        del missing["endpoints"][name]
        require(not primary_schema.is_valid(missing), f"B reservation requires {name} endpoint")
    for name in ("broker", "member", "relay"):
        missing_inode = copy.deepcopy(private_assignment)
        del missing_inode["endpoints"][name]["parent_inode"]
        require(not private_schema.is_valid(missing_inode), f"B assignment requires {name} parent inode")
        premature = copy.deepcopy(private_assignment)
        premature["endpoints"][name]["socket_inode"] = "1099"
        require(not private_schema.is_valid(premature), f"B assignment cannot preclaim {name} socket inode")
    for name, field, value in (
        ("broker", "expected_peer_uid", payload["assignment"]["runner_uid"]),
        ("member", "parent_inode", "1099"),
        ("relay", "group_gid", private_assignment["bridge"]["gid"]),
    ):
        broken = copy.deepcopy(private_assignment)
        broken["endpoints"][name][field] = value
        require(private_schema.is_valid(broken) and not bridge_assignment_matches(payload, broken, envelope_raw),
                f"B wrong {name} {field} fails the primary join")
    wrong_launch = copy.deepcopy(private_assignment)
    wrong_launch["bridge"]["executable_sha256"] = digest(b"wrong executable")
    require(private_schema.is_valid(wrong_launch) and not bridge_assignment_matches(payload, wrong_launch, envelope_raw),
            "B executable change fails measured launch digest")
    wrong_reservation = copy.deepcopy(private_assignment)
    wrong_reservation["reservation_sha256"] = digest(b"other reservation")
    require(private_schema.is_valid(wrong_reservation) and not bridge_assignment_matches(payload, wrong_reservation, envelope_raw),
            "B assignment for another primary reservation is refused")
    same_role = copy.deepcopy(private_assignment)
    same_role["bridge"]["uid"] = payload["assignment"]["runner_uid"]
    require(private_schema.is_valid(same_role) and not topology_matches(payload, same_role),
            "B cannot share the R principal")
