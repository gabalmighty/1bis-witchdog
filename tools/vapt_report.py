#!/usr/bin/env python3
"""Merge privacy-minimized VAPT stage results without overstating assurance."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

from vapt import load_scope, private_output, write_private, safe

MAX_REPORT = 2_000_000
HIGH_IMPACT = [
    "authentication and account recovery",
    "role/object/tenant authorization",
    "session and CSRF",
    "injection and input validation",
    "file upload and SSRF",
    "business workflow and financial integrity",
    "data protection and privacy",
    "running deployment and exploit prerequisites",
]

def load_optional(path: Path) -> dict | None:
    if not path.exists():
        return None
    if path.is_symlink() or path.stat().st_size > MAX_REPORT:
        raise ValueError("Evidence file missing regular-file integrity/size gate")
    data = json.loads(path.read_text("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Evidence must be a JSON object")
    return data

def produce(scope_file: Path, output: Path) -> dict:
    scope, _, digest = load_scope(scope_file)
    out = private_output(output)
    manifest = load_optional(out / "manifest.json")
    if manifest and (manifest.get("scope_sha256") != digest or
                     manifest.get("engagement_id") != scope["id"]):
        raise ValueError("Engagement/manifest digest conflict")
    if manifest:
        zap_plan = out / "zap-plan.yaml"
        if (not zap_plan.is_file() or
                manifest.get("plan_sha256") != hashlib.sha256(zap_plan.read_bytes()).hexdigest()):
            raise ValueError("ZAP plan changed after evidence approval")
    zap = load_optional(out / "zap-sanitized.json")
    authz = load_optional(out / "authz-status-matrix.json")
    baseline = load_optional(out / "report.json")
    if zap and zap.get("source_digest") != digest:
        raise ValueError("ZAP summary belongs to a different engagement")
    if authz and authz.get("source_scope_sha256") != digest:
        raise ValueError("Synthetic role evidence is for another engagement")
    if baseline and baseline.get("origin") != scope["target"]:
        raise ValueError("Baseline origin is from a different engagement")
    stages = {
        "baseline": ("EXECUTED" if baseline and baseline.get("state") == "OBSERVED"
                     else "NOT_RUN"),
        "zap": ("EXECUTED" if manifest and manifest.get("execution_state") == "COMPLETE"
                and zap else "PARTIAL" if manifest and manifest.get("execution_state")
                in ("STARTED", "PARTIAL", "COMPLETE") else "NOT_RUN"),
        "synthetic_authz": ("EXECUTED" if authz and
                            authz.get("status") == "COMPLETED_WITH_EXPECTED_STATUSES"
                            else "PARTIAL" if authz else "NOT_RUN"),
        "source_review": "NOT_ATTESTED",
        "manual_vapt": "NOT_ATTESTED",
        "running_deployment_retest": "NOT_ATTESTED",
    }
    results = authz.get("results", []) if authz else []
    suspects = [x for x in results if x.get("verdict") == "REVIEW_UNEXPECTED_RESPONSE"]
    alerts = zap.get("alerts", []) if zap else []
    output_dict = {
        "schema_version": 1,
        "engagement_id": scope["id"], "scope_sha256": digest,
        "target": scope["target"], "mode": scope["mode"],
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "assurance": "SCOPED_VAPT_PARTIAL",
        "stages": stages,
        "dynamic_scanner_candidates": len(alerts),
        "synthetic_authz_unexpected_statuses": len(suspects),
        "untested_high_impact": HIGH_IMPACT,
        "findings": [
            {"engine": "ZAP", "name": safe(a.get("name", "Unknown alert"), 130),
             "risk_label": safe(a.get("risk", "UNKNOWN"), 60),
             "status": "CANDIDATE_NEEDS_INDEPENDENT_VALIDATION"}
            for a in alerts[:100]
        ] + [
            {"engine": "SYNTHETIC_AUTHZ", "name": safe(x.get("case_id", "unknown"), 100),
             "risk_label": "REVIEW", "status": "STATUS_MISMATCH_REQUIRES_INDEPENDENT_VALIDATION"}
            for x in suspects[:100]
        ],
        "limitations": [
            "Coverage is scoped to approved paths and tools, not a full application assessment.",
            "No independent verification of ZAP alerts or authz mismatch is implied.",
            "An app can retain historical Critical findings even if the new scan finds none.",
            "Raw private ZAP reports can contain sensitive response content; do not upload to LLM.",
            "External network guard, real synthetic data and recovery snapshots are operator attestations.",
            "No production deployment patch/closure can be established from this report.",
        ],
    }
    write_private(out, "vapt-assessment.json", json.dumps(output_dict, indent=2) + "\n")
    lines = [
        "# Witch Dog — scoped agentic VAPT assessment",
        "",
        "**Assurance: SCOPED_VAPT_PARTIAL. Not a complete professional penetration-test signoff.**",
        "",
        "- Engagement: " + safe(scope["id"]),
        "- Scope: " + safe(scope["target"]),
        "- Testing mode: " + safe(scope["mode"]),
        "- UTC: " + output_dict["generated_utc"],
        "",
        "## Executed stages",
        "",
        "| Stage | Status |",
        "|---|---|",
    ]
    for key, value in stages.items():
        lines.append("| " + safe(key) + " | " + safe(value) + " |")
    lines += [
        "", "## Evidence requiring review", "",
        "- Dynamic scanner alerts (unverified candidates): " + str(len(alerts)),
        "- Synthetic authorization status mismatches (unverified): " + str(len(suspects)),
        "", "| Engine | Candidate | Risk hint | Verification |",
        "|---|---|---|---|",
    ]
    for f in output_dict["findings"]:
        lines.append("| " + safe(f["engine"]) + " | " + safe(f["name"]) +
                     " | " + safe(f["risk_label"]) + " | " + safe(f["status"]) + " |")
    lines += ["", "## Untested or unverified high-impact areas", ""]
    lines += ["- " + item + " — UNKNOWN without separate authorized evidence"
              for item in HIGH_IMPACT]
    lines += ["", "## Gatekeeper notes", ""]
    lines += ["- " + item for item in output_dict["limitations"]]
    lines += ["", "Prior independent findings must be carried forward privately until directly retested.",
              "Only the owner/qualified reviewer can sign off complete WSTG/ASVS verification.",
              ""]
    write_private(out, "vapt-assessment.md", "\n".join(lines))
    return output_dict

def main():
    p = argparse.ArgumentParser(description="Assemble privacy-minimized VAPT stage assessment")
    p.add_argument("--scope", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    try:
        result = produce(args.scope, args.output)
        print("Witch Dog scoped assessment written privately; candidates=" +
              str(len(result["findings"])) + "; assurance=" + result["assurance"])
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print("Witch Dog report HOLD: " + safe(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
