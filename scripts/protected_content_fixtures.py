"""Offline interoperability checks for package/protected-v1. All keys are fixture data."""
import hashlib
from copy import deepcopy

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from jcs import canonicalize, parse_strict
from portable_package_fixtures import portable_record_refusal


AAD = b"SOUL-PROTECTED-MANIFEST-1\0"
SIGNATURE_DOMAIN = b"SOUL-PROTECTED-RESTRICTIONS-1\0"


def binding(record):
    return "sha256:" + hashlib.sha256(canonicalize(record)).hexdigest()


def inspect_locked(env):
    return {"result": "metadata-only", "unlock": "locked", "logical_integrity": "unchecked",
            "identity": "unverified", "execution": "unavailable",
            "credential_status": {"contract": "package/protected-v1", "kind": "credential-status",
                                  "capability": "content-custody", "status": "unknown"},
            "metadata": {"contract": env["contract"], "suite": env["suite"], "recipient_ref": env["recipient_ref"],
                         "ciphertext_tag_bytes": len(bytes.fromhex(env["ciphertext_tag_hex"]))}}


def verify_restrictions(signed, checkpoint, trust):
    body = signed["statement"]
    if any(body[k] != trust[k] for k in ("journal", "signer", "soul_id")):
        return "checkpoint-unauthenticated"
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust["public_key_hex"]))
    try:
        key.verify(bytes.fromhex(signed["signature_hex"]), SIGNATURE_DOMAIN + canonicalize(body))
    except InvalidSignature:
        return "checkpoint-unauthenticated"
    if (body["checkpoint_sha256"] != binding(checkpoint) or body["soul_id"] != checkpoint["soul_id"]
            or body["epoch"] != checkpoint["source_restriction_epoch"]
            or checkpoint["source_installation_id"] != trust["source_installation_id"]):
        return "checkpoint-binding-mismatch"
    return None


def lineage(sources, version):
    """Return every contributing immutable version, failing closed on a missing edge."""
    seen = set()
    pending = [version]
    while pending:
        item = pending.pop()
        if item not in seen:
            seen.add(item)
            pending.extend(sources[item]["parents"])
    return seen


def check_manifest(manifest, identity, trust):
    if manifest["identity"] != identity:
        return "identity-binding-mismatch"
    cp = manifest["checkpoint"]
    if (any(cp[k] != identity[k] for k in ("soul_id", "revision_profile", "definition_revision"))
            or portable_record_refusal(cp)):
        return "checkpoint-binding-mismatch"
    refusal = verify_restrictions(manifest["restrictions"], cp, trust)
    if refusal:
        return refusal
    files = {}
    sources = {s["version"]: s for s in manifest["sources"]}
    for s in manifest["sources"]:
        if (binding({k: s[k] for k in ("path", "bytes_hex", "parents")}) != s["version"]
                or not set(s["parents"]).issubset(sources) or s["path"] in files):
            return "source-binding-mismatch"
        files[s["path"]] = hashlib.sha256(bytes.fromhex(s["bytes_hex"])).hexdigest()
    selected = {e["path"]: e["sha256"] for e in cp["selected_life"]}
    if files != selected:
        return "checkpoint-binding-mismatch"
    selection = {k: v for k, v in manifest.items() if k != "restrictions"}
    if manifest["restrictions"]["statement"]["selection_sha256"] != binding(selection):
        return "selection-binding-mismatch"
    return None


def crypto_result(case, vector, records, identity, schemas):
    env = dict(records["envelope"])
    external = vector["external_test_context"]
    action = case["action"]
    if action == "inspect":
        return inspect_locked(env)
    if action == "verify-manifest":
        manifest = deepcopy(records["manifest"])
        if "omit_source_index" in case:
            del manifest["sources"][case["omit_source_index"]]
        if "source_replace" in case:
            manifest["sources"][case["source_index"]].update(case["source_replace"])
        return check_manifest(manifest, identity, external["journal_trust"])
    if action == "verify-restrictions":
        signed = deepcopy(records["restrictions"])
        signed["statement"].update(case.get("statement_replace", {}))
        cp = {**records["manifest"]["checkpoint"], **case.get("checkpoint_replace", {})}
        return verify_restrictions(signed, cp, external["journal_trust"])
    keys = {k: bytes.fromhex(v) for k, v in external["keks_hex"].items()}
    if action == "recover":
        if (not case.get("recovery_allowed", external["recovery_allowed"])
                or case["key_slot"] != external["recovery_slot"] or case["key_slot"] not in keys):
            return "recovery-unavailable"
        env.update(vector["rewrapped_header"])
    key_slot = case.get("key_slot", env["recipient_ref"])
    try:
        data_key = aes_key_unwrap(keys[key_slot], bytes.fromhex(env["wrapped_key_hex"]))
    except InvalidUnwrap:
        return "unwrap-failed"
    ciphertext = bytearray.fromhex(env["ciphertext_tag_hex"])
    if "flip_ciphertext_byte" in case:
        ciphertext[case["flip_ciphertext_byte"]] ^= 1
    try:
        raw = AESGCM(data_key).decrypt(bytes.fromhex(env["nonce_hex"]), bytes(ciphertext), AAD)
    except InvalidTag:
        return "authentication-failed"
    manifest = parse_strict(raw)
    validator = schemas["package/protected-v1/protected-manifest.schema.json"]
    if raw != canonicalize(records["manifest"]) or not validator.is_valid(manifest):
        return "manifest-mismatch"
    refusal = check_manifest(manifest, identity, external["journal_trust"])
    if refusal:
        return refusal
    if action == "rewrap":
        policy = vector["rewrap_policy"]
        if policy != {"identity_sha256": binding(identity), "from": key_slot, "to": case["destination"]}:
            return "rewrap-denied"
        new_key = keys[case["destination"]]
        wrapped = aes_key_wrap(new_key, data_key)
        if {"recipient_ref": case["destination"], "wrapped_key_hex": wrapped.hex()} != vector["rewrapped_header"]:
            return "rewrap-mismatch"
        destination_key = aes_key_unwrap(new_key, wrapped)
        reopened = AESGCM(destination_key).decrypt(bytes.fromhex(env["nonce_hex"]), bytes(ciphertext), AAD)
        if reopened != raw:
            return "rewrap-mismatch"
    return "same-logical-content"


def charged(ledger):
    return sum(r["output_bytes"] for r in ledger["receipts"])


def decision(request, state, records, grants, sources, external):
    op = request["operation"]
    if op == "inspect":
        return "metadata-only"
    manifest = records["manifest"]
    if state["restore_result"] == "checkpoint-conflict" or op == "restore":
        return state["restore_result"]
    if state["credential_status"]["status"] != "available":
        return "custody-unavailable"
    status = state["credential_status"]
    if {"capability": status["capability"], "binding": status["binding"]} not in manifest["credential_requirements"]:
        return "credential-binding-mismatch"
    grant = grants[request["credential"]]
    now, version = request["now"], request["version"]
    if grant["grant_id"] in state["revoked_grants"]:
        return "grant-revoked"
    if now >= grant["expires"]:
        return "grant-expired"
    scope = state["ledger"]["scope"]
    if (grant["scope"] != scope or scope["soul_id"] != manifest["identity"]["soul_id"]
            or scope["corpus"] != manifest["corpus"]
            or any(request[k] != scope[k] for k in ("recipient", "corpus"))
            or any(request[k] != grant[k] for k in ("peer", "session", "purpose"))
            or grant["definition_revision"] != manifest["identity"]["definition_revision"]
            or version not in sources or version not in grant["versions"]):
        return "grant-scope-mismatch"
    if op not in grant["operations"]:
        return "operation-denied"
    affected = lineage(sources, version)
    if op in ("release", "quarantine"):
        if (request["peer"] != state["review_authority"] or request["purpose"] == "dream"
                or not request.get("decision_ref")):
            return "independent-authority-required"
    elif affected & state["held"]:
        return "version-held"
    if state["freshness"] != "current":
        recovery = records["recovery"]
        if not (request.get("recovery") and state["recovery_verified"]
                and recovery["authority"] == external["recovery_authority"]
                and recovery["host"] == scope["host"] and recovery["soul_id"] == scope["soul_id"]
                and recovery["checkpoint_sha256"] == binding(manifest["checkpoint"])
                and op in recovery["operations"] and affected <= set(recovery["versions"])
                and now < recovery["expires"]):
            return "freshness-unknown"
    if op in ("release", "quarantine"):
        state["local_epoch"] += 1
        if op == "quarantine":
            state["held"].add(version)
            return "held"
        state["held"].discard(version)
        return "released"
    if not affected <= set(grant["versions"]):
        return "grant-scope-mismatch"
    if op in ("disclose", "export"):
        ledger = state["ledger"]
        size = len(bytes.fromhex(sources[version]["bytes_hex"]))
        if size > grant["max_output_bytes"]:
            return "output-limit"
        if any(r["id"] == request.get("receipt") for r in ledger["receipts"]):
            return "receipt-already-used"
        if charged(ledger) + size > ledger["limit_bytes"]:
            return "budget-exhausted"
        ledger["receipts"].append({"id": request["receipt"], "grant_id": grant["grant_id"],
                                   "version": version, "output_bytes": size})
        if request.get("delivery") == "unknown":
            return "reserved-delivery-unknown"
    return "allowed"


def check_protected_content_fixtures(root, schemas, report):
    fixtures = root / "fixtures"

    def read(path):
        return parse_strict((fixtures / path).read_bytes())

    vector = read("package/protected-v1/crypto.json")
    scenarios = read("package/protected-v1/scenarios.json")
    records = {k: read(v)["input"] for k, v in vector["records"].items()}
    appendix = read(vector["appendix_c"])
    identities = [read(p)["input"] for p in appendix["identity_fixtures"]]
    manifest = records["manifest"]
    report(manifest["identity"] == identities[0] and manifest["checkpoint"]["definition_inventory"] == appendix["inventory"]
           and identities[0]["definition_revision"] == "sha256:" + appendix["definition_revision"]
           and manifest["restrictions"] == records["restrictions"], "protected selection binds Appendix C instance A")
    for case in vector["cases"]:
        identity = identities[case.get("expected_identity_index", 0)]
        report(crypto_result(case, vector, records, identity, schemas) == case["expected"], "protected " + case["name"])

    grants = {"base": records["grant"]}
    for name, changes in scenarios["grant_changes"].items():
        grants[name] = {**records["grant"], **changes}
    report(all(schemas["package/protected-v1/protected-grant.schema.json"].is_valid(g) for g in grants.values()),
           "protected host grant shapes")
    manifest_refusal = check_manifest(manifest, identities[0], vector["external_test_context"]["journal_trust"])
    if not report(manifest_refusal is None, "protected policy inputs authenticated", manifest_refusal):
        return
    sources = {s["version"]: s for s in manifest["sources"]}
    statement = manifest["restrictions"]["statement"]
    for case in scenarios["cases"]:
        state = {**scenarios["host_defaults"], **case, "ledger": deepcopy(records["ledger"])}
        state["credential_status"] = {**records["credential_status"], "status": state["custody"]}
        state["credential_status"]["binding"] = {**records["credential_status"]["binding"],
                                                 **case.get("binding_replace", {})}
        state["local_epoch"] = 0
        state["held"] = set(state["known_held"])
        # known_epoch/known_held describe the receiver's authenticated high-water
        # mark in this source journal. Local holds remain an independent overlay.
        if statement["epoch"] < state["known_epoch"]:
            state["restore_result"] = "checkpoint-stale"
        elif statement["epoch"] == state["known_epoch"] and state["held"] != set(statement["held_versions"]):
            state["restore_result"] = "checkpoint-conflict"
        else:
            state["restore_result"] = "restored"
            state["held"] = set(statement["held_versions"])
        state["held"].update(state.get("local_held", []))
        for i, step in enumerate(case["steps"], 1):
            request = {"now": state["now"], **scenarios["request_defaults"], **step}
            if step.get("reload_ledger"):
                state["ledger"] = parse_strict(canonicalize(state["ledger"]))
            result = decision(request, state, records, grants, sources, vector["external_test_context"])
            report(result == step["expected"] and ("expected_spent" not in step or
                   charged(state["ledger"]) == step["expected_spent"]),
                   f"protected {case['name']} step {i}", f"got {result}, spent {charged(state['ledger'])}")
        report(schemas["package/protected-v1/protected-ledger.schema.json"].is_valid(state["ledger"]),
               f"protected {case['name']} durable ledger")
