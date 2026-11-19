#!/usr/bin/env python3
"""Synthetic-role HTTP authorization matrix for explicit test fixtures.

Sends GET only to preapproved paths using pre-provisioned test tokens in local
environment variables. Never reads HTTP response bodies or prints credentials.
"""
from __future__ import annotations
import argparse
import datetime as dt
import http.client
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from vapt import load_scope, private_output, write_private, safe
from web_baseline import parse_target, pinned_addresses

VERSION = "0.1.0"

def request_status(target, ip: str, path: str, token: str | None) -> int:
    connection = http.client.HTTPConnection(target["host"], port=target["port"], timeout=5)
    sock = socket.create_connection((ip, target["port"]), timeout=5)
    try:
        if target["scheme"] == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=target["host"])
        connection.sock = sock
        connection.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        host = target["host"] if ":" not in target["host"] else "[" + target["host"] + "]"
        if target["port"] not in (80, 443):
            host += ":" + str(target["port"])
        connection.putheader("Host", host)
        connection.putheader("User-Agent", "WitchDog-SyntheticAuthz/0.1")
        connection.putheader("Accept", "application/json")
        connection.putheader("Connection", "close")
        connection.putheader("Cache-Control", "no-store")
        if token:
            connection.putheader("Authorization", "Bearer " + token)
        connection.endheaders()
        response = connection.getresponse()
        # Never read body, response headers or cookies. Status alone isn't exploit proof.
        return int(response.status)
    finally:
        connection.close()

def authz_matrix(scope_file: Path, output: Path, approval_ref: str,
                 confirmed_synthetic: bool) -> dict:
    scope, source, digest = load_scope(scope_file, for_execution=True)
    if not confirmed_synthetic:
        raise ValueError("Explicit --confirm-synthetic required")
    if approval_ref != scope["approval_ref"]:
        raise ValueError("Approval reference does not match engagement")
    if not scope["authz_cases"]:
        raise ValueError("No synthetic authorization cases configured")
    # Tokens are resolved only inside this process. Never send them to a model.
    tokens = {}
    for role, env_var in scope["role_token_env"].items():
        token = os.environ.get(env_var, "")
        if not token or any(c in token for c in "\r\n") or len(token) > 8192:
            raise ValueError("Missing or unsafe credential for role " + safe(role))
        tokens[role] = token
    target = parse_target(scope["target"], allow_http=source.get("lab_http") is True,
                          allow_private=source.get("environment") == "lab" and
                          source.get("lab_private_network_approved") is True)
    ips = pinned_addresses(target)
    count = sum(len(c["expected"]) for c in scope["authz_cases"])
    if count > 60:
        raise ValueError("More than 60 requests in synthetic matrix")
    result = {
        "schema_version": 1,
        "tool": "witchdog-synthetic-authz",
        "version": VERSION,
        "engagement_id": scope["id"],
        "source_scope_sha256": digest,
        "environment": scope["environment"],
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": "CONTROLLED_UAT", "status": "EXECUTED",
        "results": [],
        "total_attempted": 0,
        "limitations": [
            "Status-only evidence; a 200 login shell or proxy can produce false positives.",
            "Synthetic test fixture and expectation correctness must be independently verified.",
            "This tool cannot validate body-level object isolation, session cookies or every API route.",
            "Only exact approved GET requests; no redirects, mutation or payload injection.",
        ],
    }
    out = private_output(output)
    for case in scope["authz_cases"]:
        for role, expected in case["expected"].items():
            token = None if role == "anonymous" else tokens[role]
            status = None
            error_name = None
            try:
                status = request_status(target, ips[0], case["path"], token)
                verdict = "MATCH_EXPECTATION" if status in expected else "REVIEW_UNEXPECTED_RESPONSE"
            except (OSError, ssl.SSLError, ValueError, http.client.HTTPException) as exc:
                error_name = type(exc).__name__
                verdict = "UNKNOWN_NETWORK_OR_TLS"
            result["total_attempted"] += 1
            result["results"].append({
                "case_id": case["id"],
                "role": safe(role, 70),
                "path": safe(case["path"], 256),
                "method": "GET",
                "expected": expected, "observed_status": status,
                "verdict": verdict, "error_type": error_name,
                "evidence_class": "REMOTE_OBSERVED" if status is not None else "UNKNOWN",
                "security_verification": "REQUIRES_INDEPENDENT_REVIEW",
            })
            if result["total_attempted"] < count:
                time.sleep(scope["delay_ms"] / 1000)
    result["status"] = ("REVIEW" if any(x["verdict"] == "REVIEW_UNEXPECTED_RESPONSE"
                                       for x in result["results"]) else
                        "PARTIAL" if any(x["verdict"].startswith("UNKNOWN") for x in result["results"])
                        else "COMPLETED_WITH_EXPECTED_STATUSES")
    write_private(out, "authz-status-matrix.json", json.dumps(result, indent=2) + "\n")
    return result

def main() -> int:
    p = argparse.ArgumentParser(description="Synthetic-only scoped GET authorization matrix")
    p.add_argument("--scope", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--approval-ref", required=True)
    p.add_argument("--confirm-synthetic", action="store_true")
    args = p.parse_args()
    try:
        result = authz_matrix(args.scope, args.output, args.approval_ref,
                              args.confirm_synthetic)
        print("Synthetic authz matrix " + result["status"] +
              "; " + str(result["total_attempted"]) +
              " requests; status-only evidence in private output")
        return 2 if result["status"] in ("PARTIAL", "REVIEW") else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Witch Dog AUTHZ HOLD: " + safe(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
