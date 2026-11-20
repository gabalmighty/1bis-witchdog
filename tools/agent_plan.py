#!/usr/bin/env python3
"""Create a bounded security investigation plan and record test coverage.

This tool does not run scanners, call models, or contact a target.
The planner works with a private, approved Witch Dog VAPT engagement.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

from vapt import load_scope, path_check, private_output, within, write_private

VERSION = "0.1.0"
AREAS = ("transport", "authentication", "authorization", "injection",
         "business_logic", "data_protection", "deployment")
OUTCOMES = {"NO_ISSUE_FOUND", "FINDING_REPORTED", "NEEDS_FOLLOWUP",
            "NOT_APPLICABLE", "RULED_OUT"}
REASON_LIMIT = 300
MAX_EVIDENCE = 1_000_000


def manifest(scope_file: Path) -> tuple[dict, dict]:
    """Use the same approval and path checks as the VAPT runner."""
    scope, source, digest = load_scope(scope_file)
    if not source.get("engagement", {}).get("authorized"):
        raise ValueError("An approved engagement is required")
    tasks = [
        {"id": "collect-baseline", "role": "COLLECTOR", "risk": "transport",
         "status": "READY", "requires": ["approved_engagement"],
         "proof": "bounded local scan output"},
        {"id": "inspect-auth", "role": "INVESTIGATOR", "risk": "authentication",
         "status": "HOLD", "requires": ["approved_source_or_test_accounts"],
         "proof": "verified auth-flow and identity evidence"},
        {"id": "test-authz", "role": "VERIFIER", "risk": "authorization",
         "status": "READY" if scope["authz_cases"] else "HOLD",
         "requires": ["synthetic_role_tokens", "approved_GET_fixtures"],
         "proof": "expected and actual synthetic role results"},
        {"id": "check-injection", "role": "SCANNER", "risk": "injection",
         "status": "READY" if scope["mode"] == "active" else "HOLD",
         "requires": ["active_approval", "synthetic_data", "restore_snapshot",
                      "restricted_network"],
         "proof": "approved scanner output and independent reproduction"},
        {"id": "review-workflows", "role": "INVESTIGATOR", "risk": "business_logic",
         "status": "HOLD", "requires": ["approved_source_and_synthetic_flows"],
         "proof": "state transition and authorization evidence"},
        {"id": "review-data", "role": "INVESTIGATOR", "risk": "data_protection",
         "status": "HOLD", "requires": ["approved_source_or_synthetic_records"],
         "proof": "scoped data access evidence"},
        {"id": "verify-deployment", "role": "VERIFIER", "risk": "deployment",
         "status": "HOLD", "requires": ["live_runtime_readonly_attestation"],
         "proof": "signed build/commit/image identity and tested route"},
    ]
    obj = {
        "schema_version": 1, "version": VERSION,
        "engagement_id": scope["id"], "scope_sha256": digest,
        "target": scope["target"], "authorized_prefixes": scope["allowed"],
        "excluded_prefixes": scope["forbidden"],
        "mode": scope["mode"], "assurance": "PLAN_NOT_EXECUTION",
        "budgets": {
            "maximum_duration_minutes": scope["minutes"],
            "delay_between_requests_ms": scope["delay_ms"],
            "model_calls": 0,
            "requests_executed": 0,
        },
        "roles": ["PLANNER", "COLLECTOR", "SCANNER", "INVESTIGATOR",
                  "VERIFIER", "REPORTER"],
        "intents": tasks,
        "constraints": [
            "Do not run a tool because the planner marked it READY.",
            "Obtain tool authorization and enforce scope at execution time.",
            "A scanner finding does not prove a vulnerability.",
            "Record evidence before claiming no issue was found.",
            "Do not run unapproved requests or use production data.",
        ],
    }
    return scope, obj


def init(scope_file: Path, output: Path) -> dict:
    scope, obj = manifest(scope_file)
    out = private_output(output)
    if (out / "plan.json").exists() or (out / "coverage.json").exists():
        raise ValueError("Use a new folder for each plan")
    text = json.dumps(obj, indent=2, ensure_ascii=True) + "\n"
    write_private(out, "plan.json", text)
    coverage = {
        "schema_version": 1, "engagement_id": scope["id"],
        "plan_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "entries": [], "untested_areas": list(AREAS),
        "note": "NOT_TESTED is the default. No findings does not mean PASS.",
    }
    write_private(out, "coverage.json", json.dumps(coverage, indent=2) + "\n")
    return obj


def record(output: Path, surface: str, area: str, outcome: str, *,
           evidence_path: Path | None, reason: str = "") -> dict:
    out = private_output(output)
    plan_path = out / "plan.json"
    ledger_path = out / "coverage.json"
    if not plan_path.is_file() or not ledger_path.is_file():
        raise ValueError("Plan and coverage ledger are missing")
    plan_data = plan_path.read_bytes()
    plan = json.loads(plan_data.decode("utf-8"))
    ledger = json.loads(ledger_path.read_text("utf-8"))
    if (ledger.get("engagement_id") != plan.get("engagement_id") or
            ledger.get("plan_sha256") != hashlib.sha256(plan_data).hexdigest()):
        raise ValueError("Coverage ledger and plan digest mismatch")
    path_check(surface)
    if (not within(surface, plan["authorized_prefixes"]) or
            within(surface, plan["excluded_prefixes"])):
        raise ValueError("Surface is outside the approved engagement")
    if area not in AREAS or outcome not in OUTCOMES:
        raise ValueError("Unknown risk area or outcome")
    if len(reason) > REASON_LIMIT or "\n" in reason:
        raise ValueError("Reason is invalid")
    if outcome in ("RULED_OUT", "NOT_APPLICABLE") and not reason:
        raise ValueError("Rule out / not applicable needs a reason")
    evidence_hash = None
    if evidence_path is not None:
        if (evidence_path.is_symlink() or not evidence_path.is_file()
                or not 0 < evidence_path.stat().st_size <= MAX_EVIDENCE):
            raise ValueError("Evidence must be a bounded regular file")
        evidence_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    if outcome in ("NO_ISSUE_FOUND", "FINDING_REPORTED") and evidence_hash is None:
        raise ValueError("A finding or negative result needs an evidence file")
    if len(ledger.get("entries", [])) >= 200:
        raise ValueError("Coverage ledger entry limit reached")
    entry = {
        "surface": surface, "area": area, "outcome": outcome,
        "evidence_sha256": evidence_hash, "reason": reason,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "verification": "EVIDENCE_RECORDED_NOT_INDEPENDENTLY_VERIFIED",
    }
    ledger["entries"].append(entry)
    ledger["untested_areas"] = [
        x for x in AREAS if not any(i.get("area") == x for i in ledger["entries"])
    ]
    write_private(out, "coverage.json", json.dumps(ledger, indent=2) + "\n")
    return entry


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Plan security tasks and record coverage")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("init")
    create.add_argument("--scope", type=Path, required=True)
    create.add_argument("--out", type=Path, required=True)
    add = sub.add_parser("record")
    add.add_argument("--out", type=Path, required=True)
    add.add_argument("--surface", required=True)
    add.add_argument("--area", required=True, choices=AREAS)
    add.add_argument("--outcome", required=True, choices=sorted(OUTCOMES))
    add.add_argument("--evidence", type=Path)
    add.add_argument("--reason", default="")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = init(args.scope, args.out)
            print(json.dumps({"status": "PLAN_CREATED", "tasks": len(result["intents"]),
                              "requests_sent": 0}))
        else:
            result = record(args.out, args.surface, args.area, args.outcome,
                            evidence_path=args.evidence, reason=args.reason)
            print(json.dumps({"status": "RECORDED", "area": result["area"],
                              "outcome": result["outcome"]}))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "HOLD", "reason": type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
