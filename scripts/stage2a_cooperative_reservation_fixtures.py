"""Bridge-free cooperative reservation vectors and cross-field checks."""

import base64
import copy
import hashlib
from pathlib import PurePosixPath
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jcs import canonicalize, parse_strict
from stage2a_hr_v3_fixtures import H_PURPOSE, INVENTORY_PURPOSE, inventory_ref, signed_payload

PURPOSE = b"agent-bot/soul-cooperative-reservation/v3"
LAUNCH_PURPOSE = b"agent-bot/stage2a-cooperative-launch-inputs/v3"
H_ENVELOPE = "machine/v3/h-service-descriptor-signed.schema.json"
H_PAYLOAD = "machine/v3/h-service-descriptor-payload.schema.json"
INVENTORY = "machine/v3/domain-inventory.schema.json"
INVENTORY_REF = "machine/v3/inventory-ref.schema.json"
PAYLOAD = "machine/v3/soul-cooperative-reservation-payload.schema.json"
ENVELOPE = "machine/v3/soul-cooperative-signed-reservation.schema.json"


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


def peers_match(payload):
    assignment = payload["assignment"]
    return all(endpoint["expected_peer_uid"] == assignment["runner_uid"]
               for endpoint in payload["endpoints"].values())


def check_stage2a_cooperative_reservation_fixtures(root, schemas, report):
    path = root / "fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json"
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
        public_key = decode(envelope["issuer_public_key_base64url"])
        require(public_key == decode(vector["issuer_public_key_base64url"]), "pinned synthetic issuer key")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            decode(envelope["signature_base64url"]), PURPOSE + b"\0" + payload_raw)

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
        require(r_vector_path == root / "fixtures/reservation/v3/soul-cooperative-r-inventory.synthetic.json" and
                launch_vector_path == root / "fixtures/reservation/v3/soul-cooperative-launch-inputs.synthetic.json",
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
        require(launch_validator.is_valid(launch_records), "bridge-free cooperative launch-input schema")
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
        require(set(endpoints) == {"admission", "broker"}, "exact admission and broker endpoints")
        require(peers_match(payload), "both endpoints expect the assigned R peer")
        paths = set()
        for name, endpoint in endpoints.items():
            require(endpoint["owner_uid"] == assignment["hq_uid"], name + " is H-owned")
            require(endpoint["group_gid"] == assignment["runner_gid"], name + " grants runner group access")
            require(endpoint["expected_peer_uid"] == assignment["runner_uid"], name + " expects assigned R peer")
            require(endpoint["dir_mode"] == 0o2750 and endpoint["socket_mode"] == 0o660,
                    name + " has only H-owner and assigned R-group access")
            require(endpoint["socket_path"].startswith(endpoint["directory"].rstrip("/") + "/"), name + " socket is inside directory")
            paths.add(endpoint["socket_path"])
        require(len(paths) == 2, "admission and broker sockets are distinct")
        admission_directory = PurePosixPath(endpoints["admission"]["directory"])
        require(admission_directory.parent.name == "c" and
                PurePosixPath(endpoints["admission"]["socket_path"]).name == assignment["start_id"] + ".sock",
                "cooperative admission uses the per-installation c/start path")
        broker_directory = "/Library/Application Support/ai.true-line.agent-bot-hq/broker/" + assignment["runner_account"]
        require(endpoints["broker"]["directory"] == broker_directory and
                endpoints["broker"]["socket_path"] == broker_directory + "/broker.sock",
                "broker path is H-owned and scoped to the assigned runner account")
        argv = [assignment["node_path"], assignment["entry_path"], "run", "--soul", assignment["package_root"],
                "--admission-socket", endpoints["admission"]["socket_path"], "--broker-socket",
                endpoints["broker"]["socket_path"], "--profile", "managed-cooperative",
                "--cooperative-start-fd", "3"]
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
                "T21 qualification vector pins all seven components; no bridge")
        ordinary_components = copy.deepcopy(launch_records["component_digests"])
        ordinary_components.pop("harness")
        ordinary_components.pop("test_provider")
        ordinary_launch = copy.deepcopy(launch_records)
        ordinary_launch["component_digests"] = ordinary_components
        require(launch_validator.is_valid(ordinary_launch), "ordinary cooperative schema does not require installed harnesses")
        partial_q = copy.deepcopy(launch_records)
        partial_q["component_digests"].pop("harness")
        require(not launch_validator.is_valid(partial_q), "qualification harness and test provider are paired")
        r_components = {component["component_id"]: component for component in binding["r_components"]}
        h_components = {component["component_id"]: component for component in h_payload["components"]}
        require(launch_records["component_digests"]["souls"] == r_components["souls"]["release_artifact_sha256"] and
                launch_records["component_digests"]["adapter"] == binding["adapter_release"]["package_sha256"],
                "souls and adapter digests point to authenticated R components")
        require(launch_records["component_digests"]["hq"] == h_components["hq"]["release_artifact_sha256"] and
                launch_records["component_digests"]["comms_broker"] == binding["broker_executable"]["sha256"],
                "HQ and broker digests point to authenticated service refs")

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
        wrong_peer = copy.deepcopy(payload)
        wrong_peer["endpoints"]["broker"]["expected_peer_uid"] += 1
        require(schemas[PAYLOAD].is_valid(wrong_peer), "wrong peer fixture reaches semantic binding check")
        require(not peers_match(wrong_peer), "wrong broker peer is rejected by runner binding")
        bridged = copy.deepcopy(payload)
        bridged["assignment"]["bridge_uid"] = 333
        require(not schemas[PAYLOAD].is_valid(bridged), "cooperative schema refuses bridge claims")
        report(True, str(path.relative_to(root)))
    except (KeyError, OSError, ValueError, InvalidSignature) as exc:
        report(False, str(path.relative_to(root)), str(exc))
