"""Independent receiver for the AAE A2A cross-run.

Implements the server decision of spec Sections 7 and 8 of the AAE
extension profile v1 (inputs/aae-a2a-extension-v1.md, at the pinned
commit) from the artefacts in the exchange directory alone: the
presentation, and later the challenge response. It imports nothing from
the reference implementation and nothing from client.py. It never reads
the cases' expect blocks. Its verdict logic was not adjusted to any
expected outcome; where the profile leaves a value open, this receiver
fixes one and findings.md names the choice.

Two stages, matching the two-message exchange of spec Section 3:
- stage1: protocol checks (7.1), steps 1-3 and issuer acceptance
  (7.2, 7.5); on success it mints the challenge of Section 6.2.
- stage2: steps 1-9 again and in order (7.4), then the result of
  Section 8.2 or the receipt of Section 8.3, then the supplier skill
  rule stated in inputs/cases.json.

The nonce authenticator is HMAC-SHA256 under a receiver test secret over
"<random>.<expiry>". The -02 nonce form is fixed by reference, not
reproduced in the profile, so this construction is an invention of this
run, named in findings.md. The receiver verifies only nonces it minted
itself, which is the behaviour Section 7.3 requires.

Usage:
  python3 receiver.py stage1 CASE_ID EXCHANGE_DIR
  python3 receiver.py stage2 CASE_ID EXCHANGE_DIR
Standard library only. No network.
"""

import hashlib
import hmac
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import jcs
import jose_min
import profile_params as pp

ROOT = Path(__file__).resolve().parent
INPUTS = ROOT / "inputs"

NOW = datetime(2026, 10, 30, 20, 15, 0, tzinfo=timezone.utc)
NOW_UNIX = int(NOW.timestamp())
MAX_JWS_BYTES = 65536  # this run's input bound (spec 10.6 leaves it to the server)
IAT_WINDOW_PAST = 300   # seconds; invention, the profile names an iat window but gives none
IAT_WINDOW_FUTURE = 60  # seconds; invention, same reason

STEP_NAMES = {
    0: "profile",
    1: "signature",
    2: "payload_schema",
    3: "temporal_validity",
    4: "subject_binding",
    5: "single_use",
    6: "action",
    7: "constraints",
    8: "revocation",
    9: "delegation_chain",
}

CASES_DOC = json.loads((INPUTS / "cases.json").read_text(encoding="utf-8"))
SUPPLIER = CASES_DOC["supplier"]
CARD = {
    "required": True,
    "audience": pp.AUDIENCE,
    "skills": SUPPLIER["skills"],
    "accepted_issuers": SUPPLIER["accepted_issuers"],
    "did_methods": SUPPLIER["did_methods"],
}
CATALOGUE = SUPPLIER["catalogue"]

DID_DOCS = {}
for path in sorted((INPUTS / "did").glob("*.json")):
    doc = json.loads(path.read_text(encoding="utf-8"))
    DID_DOCS[doc["id"]] = doc


def parse_instant(text):
    if not isinstance(text, str):
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def find_vm(doc, kid):
    for vm in doc.get("verificationMethod", []):
        if vm.get("id") == kid:
            return vm
    return None


def vm_key_bytes(vm):
    jwk = vm.get("publicKeyJwk") or {}
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None
    try:
        return jose_min.b64url_decode(jwk.get("x", ""))
    except jose_min.JoseError:
        return None


class Reject(Exception):
    def __init__(self, step, reason_code):
        super().__init__(reason_code)
        self.step = step
        self.reason_code = reason_code


def decode_jws(jws, malformed_code, header_code):
    """Split and header-parse a compact JWS. Returns (header, payload_bytes, signing_input, signature)."""
    try:
        seg0, seg1, seg2 = jose_min.split_compact(jws, MAX_JWS_BYTES)
    except jose_min.JoseError:
        raise Reject(-1, malformed_code)
    try:
        header = jose_min.strict_json(jose_min.b64url_decode(seg0))
    except jose_min.JoseError:
        raise Reject(-1, header_code)
    if not isinstance(header, dict):
        raise Reject(-1, header_code)
    try:
        payload_bytes = jose_min.b64url_decode(seg1)
        signature = jose_min.b64url_decode(seg2)
    except jose_min.JoseError:
        raise Reject(-1, malformed_code)
    return header, payload_bytes, (seg0 + "." + seg1).encode("ascii"), signature


def steps_1_to_3(aae_jws):
    """-02 Section 5 steps 1-3 as profiled in spec 7.2. Returns the VC payload."""
    # Step 1: signature and signing authority.
    try:
        header, payload_bytes, signing_input, signature = decode_jws(
            aae_jws, "malformed_jws", "malformed_header"
        )
    except Reject as rej:
        raise Reject(1, rej.reason_code)
    if header.get("alg") != "EdDSA":
        raise Reject(1, "alg_not_eddsa")
    if "crit" in header:
        raise Reject(1, "crit_not_supported")
    kid = header.get("kid")
    if not isinstance(kid, str) or "#" not in kid or not kid.startswith("did:"):
        raise Reject(1, "kid_not_did_url")
    try:
        payload_lenient = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Reject(2, "payload_not_json")
    if not isinstance(payload_lenient, dict):
        raise Reject(2, "payload_not_object")
    issuer = payload_lenient.get("issuer")
    kid_did = kid.split("#", 1)[0]
    if isinstance(issuer, str) and kid_did != issuer:
        raise Reject(1, "signing_authority_mismatch")
    doc = DID_DOCS.get(kid_did)
    if doc is None:
        raise Reject(1, "did_unresolvable")
    vm = find_vm(doc, kid)
    if vm is None:
        raise Reject(1, "verification_method_absent")
    if kid not in doc.get("assertionMethod", []):
        raise Reject(1, "vm_not_authorized_assertionMethod")
    key = vm_key_bytes(vm)
    if key is None:
        raise Reject(1, "key_not_ed25519")
    import ed25519

    if not ed25519.verify(key, signing_input, signature):
        raise Reject(1, "invalid_signature")

    # Step 2: payload, schema, cty.
    if header.get("cty") != "aae+json":
        raise Reject(2, "cty_not_aae_json")
    try:
        vc = jose_min.strict_json(payload_bytes)
    except jose_min.JoseError:
        raise Reject(2, "payload_not_json")
    if "proof" in vc:
        raise Reject(2, "embedded_proof_present")
    if not isinstance(vc.get("id"), str) or not isinstance(vc.get("issuer"), str):
        raise Reject(2, "missing_id_or_issuer")
    subject = vc.get("credentialSubject")
    if not isinstance(subject, dict) or not isinstance(subject.get("id"), str):
        raise Reject(2, "missing_credentialSubject")
    aae = subject.get("aae")
    if not isinstance(aae, dict) or any(
        not isinstance(aae.get(block), dict) for block in ("mandate", "constraints", "validity")
    ):
        raise Reject(2, "missing_aae_blocks")
    mandate = aae["mandate"]
    actions = mandate.get("actions")
    if not isinstance(actions, list) or not actions or not all(isinstance(a, str) for a in actions):
        raise Reject(2, "mandate_actions_invalid")
    validity = aae["validity"]
    not_before = parse_instant(validity.get("not_before"))
    if not_before is None:
        raise Reject(2, "validity_not_before_invalid")
    not_after = parse_instant(validity.get("not_after"))
    if not_after is None:
        raise Reject(2, "validity_not_after_invalid")
    valid_from = parse_instant(vc.get("validFrom"))
    if vc.get("validFrom") is not None and valid_from is None:
        raise Reject(2, "validFrom_invalid")
    if "single_use" in validity and not isinstance(validity["single_use"], bool):
        raise Reject(2, "single_use_not_boolean")

    # Step 3: temporal validity, including validFrom.
    if NOW < not_before or (valid_from is not None and NOW < valid_from):
        raise Reject(3, "not_yet_valid_not_before")
    if NOW >= not_after:
        raise Reject(3, "expired_not_after")
    return vc


def step_4(task, vc, response_jws):
    """Subject binding, -02 Section 5 step 4 as profiled in spec 7.4 and 6.3."""
    subject_id = vc["credentialSubject"]["id"]
    try:
        header, payload_bytes, signing_input, signature = decode_jws(
            response_jws, "challenge_response_malformed", "challenge_response_malformed"
        )
    except Reject as rej:
        raise Reject(4, rej.reason_code)
    if "crit" in header:
        raise Reject(4, "challenge_response_crit_present")
    if header.get("alg") != "EdDSA":
        raise Reject(4, "challenge_response_alg_not_eddsa")
    if header.get("cty") == "aae+json":
        raise Reject(4, "challenge_response_is_envelope")
    kid = header.get("kid")
    if not isinstance(kid, str) or "#" not in kid or not kid.startswith("did:"):
        raise Reject(4, "challenge_kid_invalid")
    if kid.split("#", 1)[0] != subject_id:
        raise Reject(4, "subject_mismatch")
    doc = DID_DOCS.get(subject_id)
    vm = find_vm(doc, kid) if doc else None
    if vm is None or kid not in doc.get("authentication", []):
        raise Reject(4, "subject_key_unresolved")
    key = vm_key_bytes(vm)
    if key is None:
        raise Reject(4, "subject_key_unresolved")
    try:
        payload = jose_min.strict_json(payload_bytes)
    except jose_min.JoseError:
        raise Reject(4, "challenge_response_malformed")
    if not isinstance(payload, dict) or set(payload.keys()) != {"nonce", "aud", "iat", "aae_id"}:
        raise Reject(4, "challenge_payload_members")
    import ed25519

    if not ed25519.verify(key, signing_input, signature):
        raise Reject(4, "challenge_signature_invalid")
    if payload["aud"] != CARD["audience"]:
        raise Reject(4, "audience_mismatch")
    if payload["aae_id"] != vc["id"]:
        raise Reject(4, "aae_id_mismatch")
    nonce = payload["nonce"]
    if nonce != task["nonce"]:
        parts = nonce.split(".") if isinstance(nonce, str) else []
        if len(parts) != 3:
            raise Reject(4, "nonce_malformed")
        random_part, expiry_part, authenticator = parts
        expected = jose_min.b64url_encode(
            hmac.new(
                pp.RECEIVER_SECRET,
                (random_part + "." + expiry_part).encode("ascii"),
                hashlib.sha256,
            ).digest()
        )
        if not hmac.compare_digest(authenticator, expected):
            raise Reject(4, "nonce_not_authentic")
        raise Reject(4, "nonce_not_issued_for_task")
    if NOW_UNIX > task["nonce_expiry"]:
        raise Reject(4, "nonce_expired")
    iat = parse_instant(payload["iat"])
    if iat is None:
        raise Reject(4, "iat_malformed")
    iat_unix = int(iat.timestamp())
    if iat_unix > NOW_UNIX + IAT_WINDOW_FUTURE:
        raise Reject(4, "iat_in_future")
    if iat_unix < NOW_UNIX - IAT_WINDOW_PAST:
        raise Reject(4, "iat_too_old")
    return nonce


def step_6(vc, skill):
    action = CARD["skills"][skill]["action"]
    mandate = vc["credentialSubject"]["aae"]["mandate"]
    if "grants" in mandate:
        # Spec 7.4: a server that does not implement -02 2.2.3 MUST reject
        # every AAE that carries grants. This receiver does not implement it.
        raise Reject(6, "grant_deny")
    if action not in mandate["actions"]:
        raise Reject(6, "action_not_in_mandate")
    return action


def step_7(vc, request_part):
    constraints = vc["credentialSubject"]["aae"]["constraints"]
    transaction = request_part["transaction"]
    for name, constraint in constraints.items():
        if not isinstance(constraint, dict):
            raise Reject(2, "constraints_not_object")
        required = constraint.get("required", True)
        if name == "max_transaction_value":
            amount = transaction.get("amount")
            if amount is None:
                if required:
                    raise Reject(7, "constraint_unevaluable")
                continue
            if transaction.get("currency") != constraint.get("currency"):
                raise Reject(7, "currency_mismatch")
            if amount > constraint["value"]:
                raise Reject(7, "max_transaction_value_exceeded")
        elif name == "allowed_domains":
            host = (urlparse(CARD["audience"]).hostname or "").lower()
            allowed = [str(d).lower() for d in constraint.get("value", [])]
            if host not in allowed:
                raise Reject(7, "domain_not_in_allowlist")
        else:
            if required:
                raise Reject(7, "unrecognized_required_constraint")


def load_state(exchange_dir):
    path = exchange_dir / "receiver-state.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"tasks": {}, "used_nonces": [], "consumed_aae": []}


def save_state(exchange_dir, state):
    (exchange_dir / "receiver-state.json").write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def write_result(exchange_dir, case_id, result):
    case_dir = exchange_dir / case_id
    (case_dir / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    line = {
        "case_id": case_id,
        "task_id": result.get("task_id"),
        "task_state": result.get("task_state"),
        "verdict": (result.get("result") or {}).get("verdict"),
        "step": (result.get("result") or {}).get("step"),
        "reason_code": (result.get("result") or {}).get("reason_code") or result.get("reason_code"),
        "request_digest": (result.get("result") or {}).get("request_digest"),
        "jsonrpc_code": result.get("jsonrpc_code"),
    }
    with (exchange_dir / "decisions.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, sort_keys=True) + "\n")
    print("receiver wrote result for", case_id)


def reject_result(task_id, request_part, rej):
    result = {
        "verdict": "REJECT",
        "draft": pp.DRAFT,
        "step": rej.step,
        "step_name": STEP_NAMES[rej.step],
        "reason_code": rej.reason_code,
    }
    if request_part is not None:
        result["request_digest"] = jcs.request_digest(request_part)
    return {
        "kind": "task",
        "task_id": task_id,
        "task_state": "TASK_STATE_REJECTED",
        "result": result,
        "skill_invoked": False,
    }


def error_result(code, reason_code=None):
    result = {"kind": "error", "jsonrpc_code": code, "task_id": None, "task_state": None, "result": None}
    if reason_code:
        result["reason_code"] = reason_code
    return result


def stage1(case_id, exchange_dir):
    case_dir = exchange_dir / case_id
    presentation = json.loads((case_dir / "presentation.json").read_text(encoding="utf-8"))
    state = load_state(exchange_dir)

    # Protocol checks, spec 7.1.
    if not presentation["activate"]:
        if CARD["required"]:
            write_result(exchange_dir, case_id, error_result(-32008))
            return
    request_part = presentation["request_part"]
    well_formed = (
        isinstance(request_part, dict)
        and set(request_part.keys()) == {"skill", "transaction"}
        and isinstance(request_part.get("skill"), str)
        and isinstance(request_part.get("transaction"), dict)
    )
    if not presentation["metadata_present"] or not isinstance(presentation.get("aae"), str):
        write_result(exchange_dir, case_id, error_result(-32602, "aae_missing"))
        return
    if not well_formed:
        write_result(exchange_dir, case_id, error_result(-32602, "request_part_invalid"))
        return

    task_id = "task-" + str(
        uuid.uuid5(uuid.NAMESPACE_URL, "aae-a2a-crossrun/task/" + case_id)
    )
    skill = request_part["skill"]
    try:
        if skill not in CARD["skills"]:
            raise Reject(0, "skill_not_gated")
        vc = steps_1_to_3(presentation["aae"])
        if vc["issuer"] not in CARD["accepted_issuers"]:
            raise Reject(0, "issuer_not_accepted")
    except Reject as rej:
        write_result(exchange_dir, case_id, reject_result(task_id, request_part, rej))
        return

    random_part = jose_min.b64url_encode(
        hmac.new(pp.RECEIVER_SECRET, ("nonce/" + task_id).encode("ascii"), hashlib.sha256).digest()[:16]
    )
    expiry = NOW_UNIX + 300
    authenticator = jose_min.b64url_encode(
        hmac.new(
            pp.RECEIVER_SECRET,
            (random_part + "." + str(expiry)).encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    nonce = random_part + "." + str(expiry) + "." + authenticator
    state["tasks"][task_id] = {
        "case_id": case_id,
        "aae": presentation["aae"],
        "ancestor_jws": presentation.get("ancestor_jws"),
        "request_part": request_part,
        "aae_id": vc["id"],
        "nonce": nonce,
        "nonce_expiry": expiry,
        "challenge_spent": False,
    }
    save_state(exchange_dir, state)
    challenge = {"nonce": nonce, "aud": CARD["audience"], "aae_id": vc["id"]}
    (case_dir / "challenge.json").write_text(
        json.dumps({"task_id": task_id, "challenge": challenge}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("receiver issued challenge for", case_id)


def stage2(case_id, exchange_dir):
    case_dir = exchange_dir / case_id
    response = json.loads((case_dir / "response.json").read_text(encoding="utf-8"))
    state = load_state(exchange_dir)
    task_id = response["task_id"]
    task = state["tasks"].get(task_id)
    if task is None or task["challenge_spent"]:
        write_result(
            exchange_dir,
            case_id,
            reject_result(task_id, task["request_part"] if task else None, Reject(0, "no_pending_challenge")),
        )
        return
    request_part = task["request_part"]
    if not isinstance(response.get("challenge_response"), str):
        write_result(exchange_dir, case_id, error_result(-32602, "challenge_response_missing"))
        return
    try:
        vc = steps_1_to_3(task["aae"])
        nonce = step_4(task, vc, response["challenge_response"])
        if nonce in state["used_nonces"]:
            raise Reject(4, "nonce_replayed")
        state["used_nonces"].append(nonce)
        task["challenge_spent"] = True

        validity = vc["credentialSubject"]["aae"]["validity"]
        if validity.get("single_use"):
            if vc["id"] in state["consumed_aae"]:
                raise Reject(5, "single_use_already_consumed")
            state["consumed_aae"].append(vc["id"])

        action = step_6(vc, request_part["skill"])
        step_7(vc, request_part)

        aae_block = vc["credentialSubject"]["aae"]
        if "revocation_check" in aae_block:
            # Spec 7.4 step 8: no egress path in this receiver, fail closed.
            raise Reject(8, "revocation_status_indeterminate")
        ancestors = task.get("ancestor_jws")
        if ancestors:
            # No case in this set carries ancestors; the chain code of -02
            # Section 3 is not implemented here and the gap is logged.
            raise Reject(9, "delegation_malformed")
        if vc["issuer"] not in CARD["accepted_issuers"]:
            raise Reject(0, "issuer_not_accepted")
    except Reject as rej:
        save_state(exchange_dir, state)
        write_result(exchange_dir, case_id, reject_result(task_id, request_part, rej))
        return
    save_state(exchange_dir, state)

    receipt = {
        "verdict": "ACCEPT",
        "draft": pp.DRAFT,
        "steps_passed": [1, 2, 3, 4, 5, 6, 7],
        "aae_id": vc["id"],
        "issuer": vc["issuer"],
        "subject": vc["credentialSubject"]["id"],
        "skill": request_part["skill"],
        "action": action,
        "verified_at": pp.NOW_ISO,
        "request_digest": jcs.request_digest(request_part),
    }
    # Supplier skill rule, from inputs/cases.json: place-order succeeds
    # unless transaction.items names a sku outside the catalogue; it then
    # fails after the AAE was accepted. The receipt above stands either way.
    items = request_part["transaction"].get("items") or []
    skill_failed = any(item.get("sku") not in CATALOGUE for item in items)
    write_result(
        exchange_dir,
        case_id,
        {
            "kind": "task",
            "task_id": task_id,
            "task_state": "TASK_STATE_FAILED" if skill_failed else "TASK_STATE_COMPLETED",
            "result": receipt,
            "skill_invoked": True,
            "skill_outcome": "failed" if skill_failed else "succeeded",
        },
    )


def main():
    mode, case_id, exchange = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    if mode == "stage1":
        stage1(case_id, exchange)
    elif mode == "stage2":
        stage2(case_id, exchange)
    else:
        raise SystemExit("unknown mode " + mode)


if __name__ == "__main__":
    main()
