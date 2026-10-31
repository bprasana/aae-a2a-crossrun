"""Run harness for the AAE A2A cross-run.

Order of operations:
1. Self-tests. The Ed25519 and JCS primitives are checked against
   published material (DID documents, request-digest vectors) before any
   case runs. A failure stops the run.
2. Each case runs as the two-message exchange of spec Section 3. The
   client and the receiver run as separate processes and share only the
   files in exchange/<case>/. Neither reads the cases' expect blocks.
3. Scoring reads the expect blocks and applies the pass rule of guide
   Section 6 exactly: a task case passes when task_state, verdict and
   request_digest match, a rejection's step matches, an accepted case's
   steps_passed contains 1 to 7, and XR-06's task id differs from
   XR-01's. A differing reason_code is recorded as a note, not a failure,
   on the guide's own rule. An error case passes on jsonrpc_code.

Usage: python3 run.py
Writes exchange/, records/ and results.json beside this file.
Standard library only. No network.
"""

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import ed25519  # noqa: E402
import jcs  # noqa: E402
import jose_min  # noqa: E402


def self_tests():
    results = {}
    keys = json.loads((ROOT / "inputs" / "test-keys.json").read_text(encoding="utf-8"))["keys"]
    for name in ("issuer", "buyer"):
        seed = bytes.fromhex(keys[name]["ed25519_seed_hex"])
        pub = ed25519.public_key(seed)
        doc = json.loads((ROOT / "inputs" / "did" / (name + ".json")).read_text(encoding="utf-8"))
        expected_x = doc["verificationMethod"][0]["publicKeyJwk"]["x"]
        results["ed25519_pubkey_" + name] = jose_min.b64url_encode(pub) == expected_x
    seed = bytes.fromhex(keys["mallory"]["ed25519_seed_hex"])
    pub = ed25519.public_key(seed)
    sig = ed25519.sign(seed, b"crossrun self test")
    results["ed25519_roundtrip_mallory"] = ed25519.verify(pub, b"crossrun self test", sig) and not ed25519.verify(
        pub, b"different message", sig
    )
    vectors = json.loads((ROOT / "inputs" / "request-digest.json").read_text(encoding="utf-8"))["vectors"]
    results["jcs_vectors"] = all(
        jcs.jcs(v["request_part"]) == v["jcs"] and jcs.request_digest(v["request_part"]) == v["request_digest"]
        for v in vectors
    )
    return results


def run_case(case_id, exchange_dir):
    def call(*args):
        subprocess.run([sys.executable, *args], check=True, cwd=str(ROOT),
                       stdout=subprocess.DEVNULL)

    call(str(ROOT / "client.py"), "presentation", case_id, str(exchange_dir))
    call(str(ROOT / "receiver.py"), "stage1", case_id, str(exchange_dir))
    case_dir = exchange_dir / case_id
    if (case_dir / "challenge.json").exists():
        call(str(ROOT / "client.py"), "response", case_id, str(exchange_dir))
        call(str(ROOT / "receiver.py"), "stage2", case_id, str(exchange_dir))
    return json.loads((case_dir / "result.json").read_text(encoding="utf-8"))


def score(case, result, task_ids):
    expect = case["expect"]
    row = {
        "case_id": case["id"],
        "title": case["title"],
        "expected": expect,
        "receiver": {
            "kind": result["kind"],
            "task_id": result.get("task_id"),
            "task_state": result.get("task_state"),
            "verdict": (result.get("result") or {}).get("verdict"),
            "step": (result.get("result") or {}).get("step"),
            "reason_code": (result.get("result") or {}).get("reason_code") or result.get("reason_code"),
            "request_digest": (result.get("result") or {}).get("request_digest"),
            "steps_passed": (result.get("result") or {}).get("steps_passed"),
            "jsonrpc_code": result.get("jsonrpc_code"),
            "skill_invoked": result.get("skill_invoked"),
        },
    }
    got = row["receiver"]
    notes = []
    if expect["kind"] == "error":
        passed = got["jsonrpc_code"] == expect["jsonrpc_code"]
        if expect.get("reason_code") and got["reason_code"] != expect["reason_code"]:
            notes.append("reason_code differs: got %s" % got["reason_code"])
    else:
        passed = (
            got["task_state"] == expect["task_state"]
            and got["verdict"] == expect["verdict"]
            and got["request_digest"] == expect.get("request_digest")
        )
        if expect["verdict"] == "REJECT":
            passed = passed and got["step"] == expect["step"]
            if got["reason_code"] != expect.get("reason_code"):
                notes.append("reason_code differs: got %s" % got["reason_code"])
        if expect["verdict"] == "ACCEPT":
            passed = passed and all(s in (got["steps_passed"] or []) for s in range(1, 8))
        if expect.get("task_id_differs_from"):
            other = task_ids.get(expect["task_id_differs_from"])
            passed = passed and got["task_id"] is not None and got["task_id"] != other
    row["notes"] = notes
    row["pass"] = bool(passed)
    return row


def main():
    tests = self_tests()
    if not all(tests.values()):
        print("SELF-TEST FAILURE:", tests)
        raise SystemExit(1)
    print("self-tests pass:", tests)

    exchange_dir = ROOT / "exchange"
    records_dir = ROOT / "records"
    for path in (exchange_dir, records_dir):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)

    cases_doc = json.loads((ROOT / "inputs" / "cases.json").read_text(encoding="utf-8"))
    cases_bytes = (ROOT / "inputs" / "cases.json").read_bytes()
    rows = []
    task_ids = {}
    for case in cases_doc["cases"]:
        result = run_case(case["id"], exchange_dir)
        if result.get("task_id"):
            task_ids[case["id"]] = result["task_id"]
        row = score(case, result, task_ids)
        rows.append(row)

        case_dir = exchange_dir / case["id"]
        presentation = json.loads((case_dir / "presentation.json").read_text(encoding="utf-8"))
        challenge_path = case_dir / "challenge.json"
        record = {
            "case_id": case["id"],
            "request_part": case["request_part"],
            "aae_variant": case["aae"],
            "challenge_response_variant": case["challenge_response"],
            "activate": case["activate"],
            "aae_jws_sha256": (
                hashlib.sha256(presentation["aae"].encode("ascii")).hexdigest()
                if presentation.get("aae")
                else None
            ),
            "challenge_nonce": (
                json.loads(challenge_path.read_text(encoding="utf-8"))["challenge"]["nonce"]
                if challenge_path.exists()
                else None
            ),
            "receiver_result": result,
            "scored": row,
        }
        (records_dir / (case["id"] + ".record.json")).write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            case["id"],
            "receiver:", row["receiver"]["task_state"] or ("error " + str(row["receiver"]["jsonrpc_code"])),
            row["receiver"]["verdict"] or "",
            "| digest", "match" if row["receiver"]["request_digest"] == case["expect"].get("request_digest") else "n/a-or-MISMATCH",
            "|", "PASS" if row["pass"] else "FAIL",
            ("| notes: " + "; ".join(row["notes"])) if row["notes"] else "",
        )

    payload = {
        "run": {
            "implementation": "aae-a2a-crossrun 1.0, an independent receiver by Prasanna Bableshwar",
            "profile": cases_doc["profile"],
            "draft": cases_doc["draft"],
            "cases_format": cases_doc["format"],
            "cases_sha256": "sha256:" + hashlib.sha256(cases_bytes).hexdigest(),
            "spec_commit": "6c857eeb60a9dac379954f5be5900a10616dfc7b",
            "frozen_instant": "2026-10-30T20:15:00Z",
            "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "runtime": "Python " + sys.version.split()[0],
            "dependencies": "Python standard library only",
        },
        "self_tests": tests,
        "summary": {
            "pass": sum(1 for r in rows if r["pass"]),
            "fail": sum(1 for r in rows if not r["pass"]),
            "total": len(rows),
        },
        "cases": rows,
    }
    (ROOT / "results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("summary:", payload["summary"])


if __name__ == "__main__":
    main()
