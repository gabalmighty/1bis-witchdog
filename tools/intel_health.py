#!/usr/bin/env python3
"""Check GitHub's scheduled intelligence runs. Use with an external CI monitor.

This tool checks schedule delivery, not intelligence content accuracy.
It does not change a repository or send notifications.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.request

API_URL = (
    "https://api.github.com/repos/gabalmighty/witchdog/actions/runs"
    "?event=schedule&per_page=20"
)


def audit_runs(data: dict, now: dt.datetime, max_age_hours: float = 16.0) -> dict:
    """Return HOLD when scheduled runs are missing, old, or failed."""
    if not isinstance(data, dict) or not isinstance(data.get("workflow_runs"), list):
        raise ValueError("Invalid GitHub Actions response")
    runs = [
        r for r in data["workflow_runs"]
        if isinstance(r, dict) and r.get("name") == "Witch Dog public threat intelligence"
        and r.get("event") == "schedule"
    ]
    if not runs:
        return {
            "status": "HOLD", "reason": "NO_SCHEDULE_RUNS",
            "last_success_utc": None, "age_hours": None,
        }
    runs.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
    newest = runs[0]
    if newest.get("status") == "completed" and newest.get("conclusion") != "success":
        return {
            "status": "HOLD", "reason": "LATEST_SCHEDULE_RUN_FAILED",
            "latest_run": newest.get("html_url"),
            "last_success_utc": None, "age_hours": None,
        }
    good = next(
        (r for r in runs
         if r.get("status") == "completed" and r.get("conclusion") == "success"),
        None,
    )
    if good is None:
        return {
            "status": "HOLD", "reason": "NO_SUCCESSFUL_SCHEDULE_RUN",
            "last_success_utc": None, "age_hours": None,
        }
    try:
        started = dt.datetime.fromisoformat(
            good["created_at"].replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid schedule timestamp") from exc
    if started.tzinfo is None or now.tzinfo is None:
        raise ValueError("Timezone required")
    age = (now - started).total_seconds() / 3600.0
    return {
        "status": "OK" if 0 <= age <= max_age_hours else "HOLD",
        "reason": ("RECENT_SCHEDULE_SUCCESS" if 0 <= age <= max_age_hours
                   else "SCHEDULE_SUCCESS_STALE"),
        "last_success_utc": started.isoformat(),
        "age_hours": round(age, 2),
        "latest_run": newest.get("html_url"),
    }


def fetch() -> dict:
    request = urllib.request.Request(
        API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "WitchDog-Intel-Health/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as result:
        payload = result.read(250_001)
        if result.status != 200 or len(payload) > 250_000:
            raise ValueError("Unexpected GitHub response")
        return json.loads(payload.decode("utf-8"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check scheduled intelligence runs")
    parser.add_argument("--max-age-hours", type=float, default=16.0)
    args = parser.parse_args(argv)
    if not 12 <= args.max_age_hours <= 168:
        parser.error("Age limit must be between 12 and 168 hours")
    try:
        result = audit_runs(
            fetch(), dt.datetime.now(dt.timezone.utc), args.max_age_hours
        )
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "OK" else 2
    except (ValueError, OSError, urllib.error.URLError) as exc:
        print(json.dumps({"status": "HOLD", "reason": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
