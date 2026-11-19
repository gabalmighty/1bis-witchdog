#!/usr/bin/env python3
"""Validate a Witch Dog WEB-01 baseline JSON report without outside libraries.

This is a narrow schema/semantic gate, not verification that findings are true.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_CONTROLS = {
    "WEB-01.03", "WEB-02.01", "WEB-02.03", "WEB-02.04", "WEB-02.05",
    "WEB-02.06", "WEB-02.07", "WEB-02.08", "WEB-02.09", "WEB-05.01",
}
VERDICTS = {"PASS", "FAIL", "WARN", "UNKNOWN", "N/A"}

def validate_report(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > 256000:
        raise ValueError("Missing or oversized report")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Report must be an object")
    if obj.get("schema_version") != 1 or obj.get("tool") != "witchdog-web-baseline":
        raise ValueError("Wrong report schema")
    if obj.get("mode") != "BASELINE" or obj.get("authorized") is not True:
        raise ValueError("Invalid scope authorization/mode")
    if obj.get("state") not in ("OBSERVED", "BLOCKED"):
        raise ValueError("Invalid run state")
    origin = obj.get("origin")
    if not isinstance(origin, str) or len(origin) > 1024:
        raise ValueError("Invalid origin")
    u = urlsplit(origin)
    if u.scheme not in ("http", "https") or not u.hostname or u.path or u.query or u.fragment or u.username is not None or u.password is not None:
        raise ValueError("Non-origin target not allowed")
    count = obj.get("request_count")
    attempts = obj.get("network_attempts", 0)
    if type(count) is not int or not 0 <= count <= 1:
        raise ValueError("Request count exceeds baseline")
    if type(attempts) is not int or not 0 <= attempts <= 1:
        raise ValueError("Network attempts exceed baseline")
    if obj.get("redirects_followed") != 0:
        raise ValueError("Baseline followed redirect")
    state = obj["state"]
    if state == "OBSERVED":
        if count != 1 or obj.get("evidence_class") != "REMOTE_OBSERVED":
            raise ValueError("Observed state missing exactly one remote response")
        status = obj.get("status_code")
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("Invalid response status")
    elif obj.get("evidence_class") != "UNKNOWN":
        raise ValueError("Blocked result cannot claim remote observation")
    if "assurance" in obj and obj["assurance"] != "NOT_A_VAPT":
        raise ValueError("Baseline cannot claim full assurance")
    rows = obj.get("findings")
    if not isinstance(rows, list) or len(rows) > len(ALLOWED_CONTROLS):
        raise ValueError("Invalid finding count")
    ids = set()
    for f in rows:
        if not isinstance(f, dict):
            raise ValueError("Invalid finding")
        id_ = f.get("control_id")
        if id_ not in ALLOWED_CONTROLS or id_ in ids:
            raise ValueError("Unapproved or duplicate control")
        ids.add(id_)
        if f.get("verdict") not in VERDICTS or f.get("test_status") not in ("EXECUTED", "BLOCKED"):
            raise ValueError("Invalid finding status")
        if f.get("evidence_class") not in ("REMOTE_OBSERVED", "UNKNOWN"):
            raise ValueError("Invalid evidence class")
        evidence = f.get("evidence")
        if not isinstance(evidence, str) or len(evidence) > 280:
            raise ValueError("Invalid evidence length")
    if "coverage" in obj:
        coverage = obj["coverage"]
        if (not isinstance(coverage, dict) or
                type(coverage.get("executed_controls")) is not int or
                coverage["executed_controls"] != len(rows)):
            raise ValueError("Inaccurate execution coverage")
        unknown = coverage.get("high_impact_unknown")
        if not isinstance(unknown, list) or len(unknown) < 6 or any(
                not isinstance(x, str) or len(x) > 70 for x in unknown):
            raise ValueError("High-impact untested domains missing")
    limits = obj.get("limitations")
    if not isinstance(limits, list) or not limits or len(limits) > 25:
        raise ValueError("Missing limitation matrix")
    if any(not isinstance(i, str) or len(i) > 600 for i in limits):
        raise ValueError("Invalid limitation")
    return {"state": state, "controls_checked": len(ids), "request_count": count}

def main():
    p = argparse.ArgumentParser(description="Validate one authorized Witch Dog WEB-01 report")
    p.add_argument("--report", required=True, type=Path)
    args = p.parse_args()
    try:
        print(json.dumps(validate_report(args.report), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError):
        print("Witch Dog HOLD: WEB-01 report failed deterministic validation", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
