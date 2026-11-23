"""Synthetic Machine v3 H/R bytes and cross-reference refusal vectors.

These are contract oracles. They confer no installed key, release authority,
physical custody, runtime code closure, or qualification.
"""

import base64
import copy
import hashlib
import json
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from jcs import canonicalize, parse_strict

H_PURPOSE = b"agent-bot/stage2a-h-service-descriptor/v3"
R_PURPOSE = b"agent-bot/stage2a-reservation/v3"
INVENTORY_PURPOSE = {
    "H-code": b"agent-bot/stage2a-h-code-inventory/v3",
    "R-runtime": b"agent-bot/stage2a-r-runtime-inventory/v3",
}


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def decode(value):
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("noncanonical base64url")
    return raw


def require(value, label):
    if not value:
        raise ValueError(label)


def signed_payload(envelope, purpose, schema, payload_schema, pinned):
    require(schema.is_valid(envelope), "envelope schema")
    require(envelope["purpose"].encode() == purpose, "fixed purpose")
    require(decode(envelope["issuer_public_key_base64url"]) == pinned, "installed A key pin")
    raw = decode(envelope["payload_base64url"])
    require(envelope["payload_sha256"] == digest(raw), "payload byte digest")
    payload = parse_strict(raw)
    require(canonicalize(payload) == raw and payload_schema.is_valid(payload), "canonical payload schema")
    try:
        Ed25519PublicKey.from_public_bytes(pinned).verify(
            decode(envelope["signature_base64url"]), purpose + b"\0" + raw)
    except InvalidSignature as exc:
        raise ValueError("A signature") from exc
    return payload, raw


def inventory_ref(inv, ref, schemas):
    require(schemas["machine/v3/domain-inventory.schema.json"].is_valid(inv), "inventory schema")
    require(schemas["machine/v3/inventory-ref.schema.json"].is_valid(ref), "ref schema")
    paths = [r["path"] for r in inv["files"]]
    require(paths == sorted(set(paths)), "sorted unique regular paths")
    dirs = [r["path"] for r in inv["directories"]]
    require(dirs == sorted(set(dirs)), "sorted unique directory paths")
    parents = set()
    for path in paths:
        pieces = path.split("/")
        parents.update("/".join(pieces[:i]) for i in range(1, len(pieces)))
    require(dirs == sorted(parents), "exact directory closure; no empty or missing directory")
    require(not set(paths) & set(dirs), "file/directory alias")
    limits = inv["limits"]
    require(len(paths) <= limits["max_files"], "approved file count bound")
    require(all(row["size_bytes"] <= limits["max_file_bytes"] for row in inv["files"]), "per-file bound")
    total = sum(row["size_bytes"] for row in inv["files"])
    require(total == inv["total_bytes"] and total <= limits["max_total_bytes"], "aggregate bound")
    raw = canonicalize(inv)
    purpose = INVENTORY_PURPOSE[inv["domain"]]
    inv_digest = digest(purpose + b"\0" + raw)
    for field in ("domain", "installation_id"):
        require(inv[field] == ref[field], field + " binding")
    require(ref["inventory_digest"] == inv_digest, "purpose-separated inventory digest")
    require(ref["reviewed_source_inventory_digest"] == inv_digest, "reviewed source inventory")
    require(ref["sidecar"]["sha256"] == digest(raw) and ref["sidecar"]["size_bytes"] == len(raw),
            "sidecar exact JCS bytes")
    require(ref["file_count"] == len(paths) and ref["directory_count"] == len(dirs) and
            ref["total_bytes"] == total, "compact counts")
    root, sidecar = ref["snapshot"], ref["sidecar"]
    require(root["owner_uid"] == sidecar["owner_uid"] == ref["machine_uid"], "A-owned nodes")
    require(root["owner_gid"] == sidecar["owner_gid"] == ref["reader_gid"], "dedicated reader group")
    require(not sidecar["path"].startswith(root["path"] + "/") and sidecar["path"] != root["path"],
            "sidecar outside inventoried tree")
    return {row["path"]: row for row in inv["files"]}


def released_rows(rows, component, manifest):
    require(digest(canonicalize(manifest)) == component["release_manifest_sha256"], "release manifest digest")
    require(all("path" in row and "sha256" in row for row in manifest), "release manifest row")
    released = {row["path"]: row["sha256"] for row in manifest}
    require(len(released) == len(manifest), "unique release paths")
    selected = [row for row in rows.values() if row["component_id"] == component["component_id"]]
    require(len(selected) == len(released), "all and only released files installed")
    for row in selected:
        require(released.get(row["release_path"]) == row["sha256"], "released file maps to installed row")


def verify(vector, schemas, pinned, now):
    h_inv = parse_strict(vector["h_inventory_jcs"].encode())
    r_inv = parse_strict(vector["r_inventory_jcs"].encode())
    for name, inv in (("h_inventory_jcs", h_inv), ("r_inventory_jcs", r_inv)):
        require(canonicalize(inv) == vector[name].encode(), name + " canonical bytes")
    h_env = parse_strict(vector["h_envelope_jcs"].encode())
    h, h_raw = signed_payload(h_env, H_PURPOSE,
        schemas["machine/v3/h-service-descriptor-signed.schema.json"],
        schemas["machine/v3/h-service-descriptor-payload.schema.json"], pinned)
    require(canonicalize(h_env) == vector["h_envelope_jcs"].encode(), "canonical H envelope")
    require(h_raw == vector["h_payload_jcs"].encode(), "H exact payload vector")
    h_digest = digest(H_PURPOSE + b"\0" + h_raw)
    require(h_digest == vector["h_descriptor_digest"], "purpose-separated H descriptor digest")
    h_rows = inventory_ref(h_inv, h["h_inventory"], schemas)
    require(h["h_inventory"]["domain"] == "H-code" and
            h["hq_installation_id"] == h["h_inventory"]["installation_id"] and
            h["owner_plan_digest"] == h["h_inventory"]["owner_plan_digest"], "H service plan binding")
    require("soul_id" not in h and "hq_epoch" not in h, "static H descriptor")
    components = {c["component_id"]: c for c in h["components"]}
    require(len(components) == len(h["components"]), "unique H components")
    for name, component in components.items():
        released_rows(h_rows, component, vector["release_manifests"][name])
    require(set(components) == {row["component_id"] for row in h_rows.values()}, "all H rows released")
    runtime = h["runtime"]
    for name in ("node", "preloader", "entry"):
        path = runtime[name + "_path"]
        prefix = h["h_inventory"]["snapshot"]["path"] + "/"
        require(path.startswith(prefix), name + " inside H tree")
        require(h_rows.get(path[len(prefix):], {}).get("sha256") == runtime[name + "_sha256"],
                name + " exact installed H row")
    argv = runtime["argv"]
    require(argv[:7] == [runtime["node_path"], "--no-addons", "--disallow-code-generation-from-strings",
                         "--import", runtime["preloader_path"], runtime["entry_path"], "run"],
            "fixed preloader-before-entry argv")
    require(argv == vector["owner_approved_h_argv"], "owner-approved exact argv; no override")

    r_env = parse_strict(vector["reservation_envelope_jcs"].encode())
    r, r_raw = signed_payload(r_env, R_PURPOSE,
        schemas["machine/v3/stage2a-signed-reservation.schema.json"],
        schemas["machine/v3/stage2a-reservation-payload.schema.json"], pinned)
    require(canonicalize(r_env) == vector["reservation_envelope_jcs"].encode(), "canonical reservation envelope")
    require(r_raw == vector["reservation_payload_jcs"].encode(), "reservation exact payload vector")
    assignment, binding = r["assignment"], r["measurement_binding"]
    r_rows = inventory_ref(r_inv, binding["r_inventory"], schemas)
    require(binding["r_inventory"]["domain"] == "R-runtime", "R domain")
    require(h["h_inventory"]["snapshot"]["path"] != binding["r_inventory"]["snapshot"]["path"] and
            h["h_inventory"]["sidecar"]["path"] != binding["r_inventory"]["sidecar"]["path"] and
            h["h_inventory"]["reader_gid"] != binding["r_inventory"]["reader_gid"],
            "disjoint H/R roots, sidecars and reader groups")
    require(binding["h_service_descriptor_digest"] == assignment["h_service_descriptor_digest"] == h_digest,
            "one-use H descriptor digest")
    require(binding["r_inventory"]["inventory_digest"] == assignment["r_inventory_digest"], "one-use R digest")
    require(h["host_id"] == binding["host_id"] == r["host_id"], "designated host")
    require(binding["installation_id"] == assignment["installation_id"] ==
            binding["r_inventory"]["installation_id"], "Soul installation")
    require(binding["installed_plan_digest"] == assignment["plan_digest"], "installed Soul plan")
    require(binding["r_inventory"]["owner_plan_digest"] ==
            "sha256:" + binding["installed_plan_digest"], "R inventory in approved Soul plan")
    for field in ("soul_id", "start_id", "launch_id", "plan_id", "hq_epoch", "package_sha256", "soul_artifact_sha256"):
        require(binding[field] == assignment[field], field + " binding")
    require(assignment["runner_uid"] == binding["r_inventory"]["reader_uid"] and
            assignment["runner_gid"] == binding["r_inventory"]["reader_gid"] and
            assignment["hq_uid"] == h["h_inventory"]["reader_uid"] and
            assignment["machine_uid"] == binding["r_inventory"]["machine_uid"] ==
            h["h_inventory"]["machine_uid"], "exact A/H/R role binding")
    require(300 <= assignment["hq_uid"] < 400 and assignment["runner_uid"] >= 300 and
            assignment["bridge_uid"] >= 300 and assignment["machine_uid"] >= 400 and
            len({assignment[x] for x in ("hq_uid", "runner_uid", "bridge_uid", "machine_uid")}) == 4,
            "distinct dedicated A/H/R/B identities")
    adapter = binding["adapter_release"]
    r_components = {c["component_id"]: c for c in binding["r_components"]}
    require(len(r_components) == len(binding["r_components"]) and
            set(r_components) == {row["component_id"] for row in r_rows.values()}, "all R components released")
    for name, component in r_components.items():
        released_rows(r_rows, component, vector["release_manifests"][name])
    require(r_components[adapter["component_id"]]["release_artifact_sha256"] == adapter["package_sha256"] and
            r_components[adapter["component_id"]]["release_attestation_sha256"] == adapter["release_attestation_sha256"] and
            r_components[adapter["component_id"]]["release_manifest_sha256"] == adapter["release_manifest_sha256"],
            "qualified adapter equals released R component")
    require(adapter["package_sha256"] != "sha256:" + binding["package_sha256"],
            "adapter package distinct subject from Machine package")
    adapter_manifest = vector["release_manifests"][adapter["component_id"]]
    released_rows(r_rows, {"component_id": adapter["component_id"],
                           "release_manifest_sha256": adapter["release_manifest_sha256"]}, adapter_manifest)
    prefix = binding["r_inventory"]["snapshot"]["path"] + "/"
    require(adapter["executable_path"].startswith(prefix) and
            r_rows.get(adapter["executable_path"][len(prefix):], {}).get("sha256") ==
            adapter["executable_sha256"], "released adapter executable installed R row")
    code_inputs = parse_strict(vector["adapter_code_inputs_jcs"].encode())
    require(canonicalize(code_inputs) == vector["adapter_code_inputs_jcs"].encode() and
            digest(b"agent-bot/stage2a-adapter-code-inputs/v3\0" + canonicalize(code_inputs)) ==
            adapter["code_inputs_digest"] and
            len(code_inputs) == adapter["code_input_count"], "qualified launch code-input list")
    require(code_inputs == sorted(set(code_inputs)) and all(path.startswith(prefix) and
            path[len(prefix):] in r_rows and r_rows[path[len(prefix):]]["component_id"] == adapter["component_id"]
            for path in code_inputs), "qualified code inputs map to R rows")
    issued = datetime.fromisoformat(r["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(r["expires_at"].replace("Z", "+00:00"))
    require(issued <= now < expires and 0 < (expires - issued).total_seconds() <= 30 and
            r["expires_at"] == assignment["expires_at"], "one-use reservation expiry")
    return True


def check_stage2a_hr_v3_fixtures(root, schemas, report):
    vector = json.loads((root / "fixtures/reservation/v3/machine-hr-synthetic.json").read_text())
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["seed_hex"]))
    pinned = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    now = datetime.fromisoformat(vector["verification_at"].replace("Z", "+00:00"))
    try:
        require(base64.urlsafe_b64encode(pinned).rstrip(b"=").decode() ==
                vector["issuer_public_key_base64url"], "public synthetic key")
        verify(vector, schemas, pinned, now)
        report(True, "Machine v3 H/R exact canonical signed synthetic vector")
    except Exception as exc:
        report(False, "Machine v3 H/R exact canonical signed synthetic vector", str(exc))

    def mutate_payload(which, change):
        candidate = copy.deepcopy(vector)
        pfield = "h_payload_jcs" if which == "h" else "reservation_payload_jcs"
        efield = "h_envelope_jcs" if which == "h" else "reservation_envelope_jcs"
        purpose = H_PURPOSE if which == "h" else R_PURPOSE
        payload = parse_strict(candidate[pfield].encode())
        change(payload)
        raw = canonicalize(payload)
        env = parse_strict(candidate[efield].encode())
        env["payload_sha256"] = digest(raw)
        env["payload_base64url"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        env["signature_base64url"] = base64.urlsafe_b64encode(key.sign(purpose + b"\0" + raw)).rstrip(b"=").decode()
        candidate[pfield] = raw.decode()
        candidate[efield] = canonicalize(env).decode()
        if which == "h":
            candidate["h_descriptor_digest"] = digest(H_PURPOSE + b"\0" + raw)
        return candidate

    cases = {
        "wrong installed A key": (vector, bytes(32)),
        "H release row mismatch": ({**vector, "release_manifests": {**vector["release_manifests"],
             "hq": [{"path": "main.mjs", "sha256": "sha256:" + "0" * 64}]}}, pinned),
        "extra empty H directory": ({**vector, "h_inventory_jcs": canonicalize({
             **parse_strict(vector["h_inventory_jcs"].encode()),
             "directories": parse_strict(vector["h_inventory_jcs"].encode())["directories"] +
             [{"path": "unused", "kind": "directory", "mode": "0555"}]}).decode()}, pinned),
        "H preloader row digest": (mutate_payload("h", lambda p: p["runtime"].__setitem__("preloader_sha256", "sha256:" + "0" * 64)), pinned),
        "H argv override": (mutate_payload("h", lambda p: p["runtime"]["argv"].append("--plugin-dir=/tmp")), pinned),
        "H service installation": (mutate_payload("h", lambda p: p.__setitem__("hq_installation_id", "other")), pinned),
        "R/H UID substitution": (mutate_payload("r", lambda p: p["assignment"].__setitem__("runner_uid", 309)), pinned),
        "R inventory digest substitution": (mutate_payload("r", lambda p: p["assignment"].__setitem__("r_inventory_digest", "sha256:" + "0" * 64)), pinned),
        "R owner plan substitution": (mutate_payload("r", lambda p: p["measurement_binding"]["r_inventory"].__setitem__("owner_plan_digest", "sha256:" + "0" * 64)), pinned),
        "R sidecar inside measured tree": (mutate_payload("r", lambda p: p["measurement_binding"]["r_inventory"]["sidecar"].__setitem__("path", p["measurement_binding"]["r_inventory"]["snapshot"]["path"] + "/sidecar.json")), pinned),
        "R sidecar byte digest": (mutate_payload("r", lambda p: p["measurement_binding"]["r_inventory"]["sidecar"].__setitem__("sha256", "sha256:" + "0" * 64)), pinned),
        "R root alias of H": (mutate_payload("r", lambda p: p["measurement_binding"]["r_inventory"]["snapshot"].__setitem__("path", parse_strict(vector["h_payload_jcs"].encode())["h_inventory"]["snapshot"]["path"])), pinned),
        "shared H/R reader group": (mutate_payload("r", lambda p: (
            p["measurement_binding"]["r_inventory"].__setitem__("reader_gid", 309),
            p["measurement_binding"]["r_inventory"]["snapshot"].__setitem__("owner_gid", 309),
            p["measurement_binding"]["r_inventory"]["sidecar"].__setitem__("owner_gid", 309),
            p["assignment"].__setitem__("runner_gid", 309))), pinned),
        "R release row mismatch": ({**vector, "release_manifests": {**vector["release_manifests"],
             "adapter": [{"path": "cli", "sha256": "sha256:" + "0" * 64}]}}, pinned),
        "adapter executable row digest": (mutate_payload("r", lambda p: p["measurement_binding"]["adapter_release"].__setitem__("executable_sha256", "sha256:" + "0" * 64)), pinned),
        "adapter code input substitution": ({**vector, "adapter_code_inputs_jcs": '["/tmp/unmeasured.mjs"]'}, pinned),
        "stale one-use reservation": (mutate_payload("r", lambda p: (p.__setitem__("expires_at", "2026-11-22T14:15:19Z"), p["assignment"].__setitem__("expires_at", "2026-11-22T14:15:19Z"))), pinned),
    }
    for name, (candidate, candidate_pin) in cases.items():
        try:
            verify(candidate, schemas, candidate_pin, now)
        except (ValueError, KeyError, TypeError, AssertionError):
            report(True, "Machine v3 refuses " + name)
        else:
            report(False, "Machine v3 refuses " + name)
