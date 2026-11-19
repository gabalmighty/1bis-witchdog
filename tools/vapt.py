#!/usr/bin/env python3
"""Witch Dog VAPT engine: validate engagements, generate/run scoped OWASP ZAP plans.

Execution is opt-in with a preapproved engagement, synthetic staging and
independent egress controls. This tool does not provide a network sandbox.
Raw tool data is PRIVATE; sanitized summaries are for the agent/reviewer.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, unquote

VERSION = "0.1.0"
MAX_SCOPE = 131072
MAX_ZAP_REPORT = 20_000_000
ALLOWED_MODES = ("passive", "active")
ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{2,63}$")
ENV_RE = re.compile(r"^(staging|lab|uat)$")

def safe(value, length=180):
    raw = str(value).replace("\n", " ").replace("\r", " ").replace("|", "/")
    return "".join(c for c in raw if c.isprintable() and c != chr(96))[:length]

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def exact_origin(value: str, allow_http=False) -> str:
    if not isinstance(value, str) or not 8 <= len(value) <= 350:
        raise ValueError("Target must be one exact URL origin")
    if re.search(r"[\s\\\x00-\x1f]", value):
        raise ValueError("Target contains invalid characters")
    parts = urlsplit(value)
    if parts.scheme != "https" and not (allow_http and parts.scheme == "http"):
        raise ValueError("HTTPS required; HTTP only in a separately authorized lab")
    if not parts.hostname or parts.username is not None or parts.password is not None:
        raise ValueError("Target userinfo or hostname invalid")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("Scope must be an origin, no path, query or fragment")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("Port invalid") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Port invalid")
    host = parts.hostname.encode("idna").decode("ascii").lower()
    if host.endswith(".") or any(not x for x in host.split(".")):
        raise ValueError("Hostname invalid")
    if not re.fullmatch(r"[a-z0-9._:-]+", host):
        raise ValueError("Hostname invalid")
    authority = ("[" + host + "]" if ":" in host else host)
    default = 443 if parts.scheme == "https" else 80
    return parts.scheme + "://" + authority + ((":" + str(port)) if port and port != default else "")

def path_check(path: str) -> str:
    if (not isinstance(path, str) or not path.startswith("/") or
            len(path) > 256 or any(ord(x) < 33 for x in path) or
            "\\" in path or "?" in path or "#" in path or path.startswith("//")):
        raise ValueError("Path must be an exact absolute path/prefix without query/fragment")
    decoded = unquote(path)
    if "//" in decoded or "\\" in decoded or any(p in ("..", ".") for p in decoded.split("/")):
        raise ValueError("Path traversal or ambiguous path")
    return path

def within(path: str, prefixes: list[str]) -> bool:
    for prefix in prefixes:
        if prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return True
    return False

def validate_scope(obj: dict, *, for_execution=False) -> dict:
    if not isinstance(obj, dict) or obj.get("schema_version") != 1:
        raise ValueError("Schema version must be 1")
    engagement = obj.get("engagement", {})
    if not isinstance(engagement, dict):
        raise ValueError("engagement must be an object")
    identifier = engagement.get("id")
    if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
        raise ValueError("engagement.id invalid")
    approval = engagement.get("approval_ref")
    if not isinstance(approval, str) or not ID_RE.fullmatch(approval):
        raise ValueError("Non-secret approval_ref is required")
    if engagement.get("authorized") is not True:
        raise ValueError("Explicit authorized=true assertion required")
    if not isinstance(engagement.get("owner_contact"), str) or "@" not in engagement["owner_contact"]:
        raise ValueError("Owner or incident contact is required")
    expires = engagement.get("expires_utc")
    if not isinstance(expires, str):
        raise ValueError("Engagement expiration required")
    try:
        deadline = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid engagement expiration") from exc
    if deadline.tzinfo is None:
        raise ValueError("Expiration timezone required")
    if for_execution and deadline <= dt.datetime.now(dt.timezone.utc):
        raise ValueError("Engagement authorization has expired")
    if for_execution and deadline > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7):
        raise ValueError("Engagement expires too far ahead; limit authorization to <=7 days")
    environment = obj.get("environment")
    if not isinstance(environment, str) or not ENV_RE.fullmatch(environment):
        raise ValueError("VAPT requires staging/lab/uat environment, not production")
    if obj.get("lab_http") is True and environment != "lab":
        raise ValueError("Plain HTTP only allowed for explicitly isolated lab environments")
    if obj.get("lab_private_network_approved") is True and environment != "lab":
        raise ValueError("Private-network override requires an isolated lab environment")
    target = exact_origin(obj.get("target"), allow_http=obj.get("lab_http") is True)
    # Even a non-production domain may contain production data; never infer from hostname.
    allowed = obj.get("allowed_prefixes")
    forbidden = obj.get("forbidden_prefixes", [])
    seeds = obj.get("seed_paths", ["/"])
    if (not isinstance(allowed, list) or not 1 <= len(allowed) <= 20 or
            not isinstance(forbidden, list) or len(forbidden) > 30 or
            not isinstance(seeds, list) or not 1 <= len(seeds) <= 30):
        raise ValueError("Explicit bounded path scope required")
    allowed = [path_check(p) for p in allowed]
    forbidden = [path_check(p) for p in forbidden]
    seeds = [path_check(p) for p in seeds]
    if "/" in allowed and obj.get("full_origin_scope_approved") is not True:
        raise ValueError("Whole-origin scope needs full_origin_scope_approved=true")
    for seed in seeds:
        if not within(seed, allowed) or within(seed, forbidden):
            raise ValueError("Seed path outside approved scope or denied path")
    mode = obj.get("mode")
    if mode not in ALLOWED_MODES:
        raise ValueError("mode must be passive or active")
    limits = obj.get("limits", {})
    if not isinstance(limits, dict):
        raise ValueError("limits must be an object")
    minutes = limits.get("max_duration_minutes", 8)
    delay = limits.get("delay_ms", 1500)
    if type(minutes) is not int or not 1 <= minutes <= 20:
        raise ValueError("max_duration_minutes must be 1..20")
    if type(delay) is not int or not 500 <= delay <= 10000:
        raise ValueError("delay_ms must be 500..10000")
    if obj.get("synthetic_data_only") is not True:
        raise ValueError("Only synthetic-data engagements are supported in this revision")
    if obj.get("egress_allowlist_enforced") is not True:
        raise ValueError("External network egress allowlist MUST be independently enforced")
    if mode == "active":
        if obj.get("active_testing_approved") is not True:
            raise ValueError("Explicit active_testing_approved required")
        if obj.get("snapshot_restore_verified") is not True:
            raise ValueError("Active testing requires snapshot/restore verified")
        if obj.get("safe_stateful_routes_approved") is not True:
            raise ValueError("Active tools may change state; approved test-only routes required")
    cases = obj.get("authz_cases", [])
    if not isinstance(cases, list) or len(cases) > 30:
        raise ValueError("authz_cases must be a list of <=30 cases")
    role_tokens = obj.get("role_token_env", {})
    if not isinstance(role_tokens, dict) or len(role_tokens) > 8:
        raise ValueError("role_token_env invalid")
    for role, envvar in role_tokens.items():
        if not ID_RE.fullmatch(str(role)) or not re.fullmatch(r"WITCHDOG_[A-Z0-9_]+_TOKEN", str(envvar)):
            raise ValueError("Roles may only reference predefined token environment names")
    case_ids = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not ID_RE.fullmatch(case["id"]):
            raise ValueError("Each authorization test needs a stable id")
        if case["id"] in case_ids:
            raise ValueError("Duplicate authz test id")
        case_ids.add(case["id"])
        p = path_check(case.get("path"))
        if not within(p, allowed) or within(p, forbidden):
            raise ValueError("Authz test not in allowed synthetic path scope")
        if case.get("synthetic_fixture") is not True or case.get("method") != "GET":
            raise ValueError("Authz probes must use synthetic GET fixtures only")
        expected = case.get("expected")
        if not isinstance(expected, dict) or not expected:
            raise ValueError("Authz test expected status matrix required")
        for role, codes in expected.items():
            if role not in ("anonymous", *role_tokens.keys()) or not isinstance(codes, list) or not codes:
                raise ValueError("Authz matrix contains unknown role/empty expected statuses")
            if any(type(v) is not int or not 100 <= v <= 599 for v in codes):
                raise ValueError("Invalid expected HTTP status")
    return {
        "id": identifier, "approval_ref": approval, "deadline": expires,
        "target": target, "environment": environment, "mode": mode,
        "allowed": allowed, "forbidden": forbidden, "seeds": seeds,
        "minutes": minutes, "delay_ms": delay, "authz_cases": cases,
        "role_token_env": role_tokens, "scope_digest": None,
    }

def load_scope(path: Path, *, for_execution=False) -> tuple[dict, dict, str]:
    if not path.is_file() or path.stat().st_size > MAX_SCOPE:
        raise ValueError("Scope file missing or over budget")
    raw = path.read_bytes()
    source = json.loads(raw)
    return validate_scope(source, for_execution=for_execution), source, sha256(raw)

def yamlq(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)

def anchored_regex(target: str, prefix: str) -> str:
    origin = re.escape(target)
    if prefix == "/":
        return "^" + origin + r"/.*$"
    return "^" + origin + re.escape(prefix.rstrip("/")) + r"(?:/.*|(?:\?.*)?)$"

def plan_yaml(scope: dict) -> str:
    name = "WitchDog-" + scope["id"]
    minutes = scope["minutes"]
    lines = [
        "env:", "  contexts:", "    - name: " + yamlq(name),
        "      urls:", "        - " + yamlq(scope["target"]),
        "      includePaths:",
    ]
    for p in scope["allowed"]:
        lines.append("        - " + yamlq(anchored_regex(scope["target"], p)))
    if scope["forbidden"]:
        lines.append("      excludePaths:")
        for p in scope["forbidden"]:
            lines.append("        - " + yamlq(anchored_regex(scope["target"], p)))
    lines += ["  parameters:", "    failOnError: true",
              "    failOnWarning: false", "    progressToStdout: false",
              "    maxDuration: " + str(minutes * 60),
              "jobs:", "  - type: requestor", "    requests:"]
    for p in scope["seeds"]:
        lines += ["      - url: " + yamlq(scope["target"] + p),
                  "        method: GET"]
    if scope["mode"] == "active":
        lines += [
            "  - type: spider",
            "    parameters:",
            "      context: " + yamlq(name),
            "      url: " + yamlq(scope["target"] + scope["seeds"][0]),
            "      maxDuration: " + str(min(3, minutes)),
            "      maxDepth: 2",
            "      maxChildren: 10",
            "      acceptCookies: false",
            "      parseGit: false",
            "      logoutAvoidance: true",
            "  - type: activeScan",
            "    parameters:",
            "      context: " + yamlq(name),
            "      url: " + yamlq(scope["target"] + scope["seeds"][0]),
            "      defaultStrength: Low",
            "      defaultThreshold: Medium",
            "      maxRuleDurationInMins: 1",
            "      maxScanDurationInMins: " + str(minutes),
            "      addQueryParam: false",
            "      delayInMs: " + str(scope["delay_ms"]),
            "      threadPerHost: 1",
            "      maxAlertsPerRule: 5",
            "      scanHeadersAllRequests: false",
        ]
    lines += [
        "  - type: passiveScan-wait",
        "    parameters:",
        "      maxDuration: 2",
        "  - type: report",
        "    parameters:",
        "      template: traditional-json",
        "      reportDir: " + yamlq("."),
        "      reportFile: " + yamlq("zap-raw-private.json"),
        "      reportTitle: " + yamlq("Witch Dog scoped " + scope["mode"] + " assessment"),
        "      displayReport: false",
    ]
    return "\n".join(lines) + "\n"

def private_output(dirpath: Path) -> Path:
    path = dirpath.expanduser().resolve()
    project = Path(__file__).resolve().parents[1]
    if path == project or path == project.parent:
        raise ValueError("Output must be tenant-private, not the project root")
    if path.is_relative_to(project):
        relative = path.relative_to(project)
        if not relative.parts or relative.parts[0] != ".witchdog":
            raise ValueError("Do not put private reports in tracked public repo paths")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path

def write_private(path: Path, name: str, text: str) -> None:
    dest = path / name
    if dest.is_symlink():
        raise ValueError("Refusing to write via symlink")
    dest.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(dest, 0o600)

def create_plan(scope_path: Path, output_path: Path) -> dict:
    scope, source, digest = load_scope(scope_path)
    out = private_output(output_path)
    if (out / "manifest.json").exists() or (out / "zap-plan.yaml").exists():
        raise ValueError("Output already contains a plan; use a fresh run folder")
    plan = plan_yaml(scope)
    write_private(out, "zap-plan.yaml", plan)
    manifest = {
        "schema_version": 1, "engine_version": VERSION,
        "engagement_id": scope["id"], "approval_ref": scope["approval_ref"],
        "target": scope["target"], "mode": scope["mode"],
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope_sha256": digest, "plan_sha256": sha256(plan.encode("utf-8")),
        "execution_state": "NOT_RUN", "active": scope["mode"] == "active",
        "gate": "APPROVAL_AND_EGRESS_REQUIRED",
        "note": "SHA-256 digests are not signatures. Runtime network egress policy must be independently enforced.",
    }
    write_private(out, "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return manifest

def validate_generated(scope_file: Path, out: Path) -> tuple[dict, dict]:
    scope, source, digest = load_scope(scope_file, for_execution=True)
    manifest_file = out / "manifest.json"
    plan_file = out / "zap-plan.yaml"
    if not manifest_file.is_file() or not plan_file.is_file():
        raise ValueError("Plan and manifest missing; run plan first")
    manifest = json.loads(manifest_file.read_text("utf-8"))
    if (manifest.get("scope_sha256") != digest or
            manifest.get("plan_sha256") != sha256(plan_file.read_bytes()) or
            manifest.get("engagement_id") != scope["id"] or
            manifest.get("mode") != scope["mode"]):
        raise ValueError("Plan/source changed since approval; regenerate and review")
    if manifest.get("execution_state") != "NOT_RUN":
        raise ValueError("Plan has already been executed; create a new run folder")
    return scope, manifest

def execute(scope_file: Path, out: Path, approval_ref: str,
            zap_bin: str, confirm_active: bool) -> int:
    scope, manifest = validate_generated(scope_file, out)
    if approval_ref != scope["approval_ref"]:
        raise ValueError("Exact engagement approval reference required")
    if scope["mode"] == "active" and not confirm_active:
        raise ValueError("Active scan requires --ack-impact for state-changing probe risk")
    binary = shutil.which(zap_bin)
    if not binary:
        raise ValueError("ZAP binary not installed; do not download/execute an unpinned binary")
    plan_path = str((out / "zap-plan.yaml").resolve())
    # Validate the ZAP Automation Framework syntax before touching the target.
    try:
        check = subprocess.run([binary, "-cmd", "-autocheck", plan_path],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               cwd=out, timeout=75, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("ZAP pre-execution plan validation unavailable") from exc
    if check.returncode != 0:
        raise ValueError("ZAP rejected plan syntax; no network test launched")
    cmd = [binary, "-cmd", "-autorun", plan_path]
    # ZAP needs an external firewall/egress gateway. YAML context is not a sandbox.
    manifest["execution_state"] = "STARTED"
    write_private(out, "manifest.json", json.dumps(manifest, indent=2) + "\n")
    try:
        completed = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   cwd=out, timeout=scope["minutes"] * 60 + 90,
                                   check=False, shell=False)
        rc = completed.returncode
    except subprocess.TimeoutExpired:
        rc = 124
    except OSError:
        rc = 125
    manifest["exit_code"] = rc
    manifest["execution_state"] = "COMPLETE" if rc == 0 else "PARTIAL"
    manifest["zap_report_present"] = (out / "zap-raw-private.json").is_file()
    manifest["completed_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    write_private(out, "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return rc

def normalize_zap(scope_file: Path, out: Path) -> dict:
    scope, _, digest = load_scope(scope_file)
    report_path = out / "zap-raw-private.json"
    if not report_path.is_file() or report_path.stat().st_size > MAX_ZAP_REPORT:
        raise ValueError("Private ZAP report is missing or over size cap")
    raw = json.loads(report_path.read_text("utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("site"), list):
        raise ValueError("Unexpected ZAP report structure")
    alerts = []
    for site in raw["site"][:50]:
        if not isinstance(site, dict):
            continue
        s = site.get("@name", "")
        parsed = urlsplit(s)
        if exact_origin(parsed.scheme + "://" + parsed.netloc) != scope["target"]:
            raise ValueError("Out-of-scope ZAP report site; HOLD and inspect privately")
        for item in site.get("alerts", [])[:300]:
            if not isinstance(item, dict):
                continue
            entries = item.get("instances", [])
            alerts.append({
                "plugin_id": safe(item.get("pluginid", "unknown"), 20),
                "name": safe(item.get("alert", "Unknown ZAP alert"), 130),
                "risk": safe(item.get("riskdesc", "UNKNOWN"), 60),
                "confidence": safe(item.get("confidence", "UNKNOWN"), 40),
                "cwe": safe(item.get("cweid", ""), 12),
                "occurrences": len(entries) if isinstance(entries, list) else 0,
                "status": "CANDIDATE_NEEDS_INDEPENDENT_VALIDATION",
            })
    result = {
        "schema_version": 1, "engagement_id": scope["id"], "tool": "OWASP_ZAP",
        "mode": scope["mode"], "source_digest": digest,
        "observation": "SCANNER_REPORTED_NOT_INDEPENDENTLY_VERIFIED",
        "alerts": alerts[:300], "confidence_limitations": [
            "ZAP alerts are candidates, not independently verified exploitation.",
            "Raw report may contain sensitive evidence; keep in private tenant storage.",
            "Not equivalent to complete WSTG/ASVS or manual VAPT.",
            "Out-of-scope and untested authorization/business logic remain UNKNOWN.",
        ]}
    write_private(out, "zap-sanitized.json", json.dumps(result, indent=2, ensure_ascii=True) + "\n")
    return result

def draft_scope(target: str, output_path: Path) -> dict:
    origin = exact_origin(target, allow_http=True)
    out = private_output(output_path)
    dest = out / "engagement.json"
    if dest.exists():
        raise ValueError("Refusing to overwrite existing engagement")
    identifier = "WD-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)).replace(
        microsecond=0).isoformat()
    doc = {
        "schema_version": 1,
        "engagement": {
            "id": identifier, "authorized": False,
            "approval_ref": "REPLACE_WITH_APPROVAL",
            "owner_contact": "security@example.invalid", "expires_utc": expires
        },
        "target": origin, "environment": "staging", "lab_http": False,
        "lab_private_network_approved": False,
        "synthetic_data_only": False, "egress_allowlist_enforced": False,
        "mode": "passive", "active_testing_approved": False,
        "snapshot_restore_verified": False,
        "safe_stateful_routes_approved": False,
        "full_origin_scope_approved": False,
        "allowed_prefixes": ["/"], "forbidden_prefixes": [
            "/logout", "/api/delete", "/api/payroll/live", "/admin/destroy"],
        "seed_paths": ["/"], "limits": {"max_duration_minutes": 8, "delay_ms": 1500},
        "role_token_env": {}, "authz_cases": []
    }
    write_private(out, "engagement.json", json.dumps(doc, indent=2) + "\n")
    return doc

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Witch Dog engagement-gated OWASP ZAP VAPT engine")
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("init", "preflight", "plan", "execute", "ingest"):
        p = sub.add_parser(cmd)
        if cmd == "init":
            p.add_argument("--target", required=True)
            p.add_argument("--output", type=Path, required=True)
        else:
            p.add_argument("--scope", type=Path, required=True)
            if cmd != "preflight":
                p.add_argument("--output", type=Path, required=True)
        if cmd == "execute":
            p.add_argument("--approval-ref", required=True)
            p.add_argument("--zap-bin", default=("zap.bat" if os.name == "nt" else "zap.sh"))
            p.add_argument("--ack-impact", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            draft = draft_scope(args.target, args.output)
            print("Witch Dog PRIVATE engagement draft created for " +
                  safe(draft["target"]) +
                  ". Complete authorization, test boundaries and egress before plan/run.")
            return 0
        if args.command == "preflight":
            scope, _, digest = load_scope(args.scope)
            print(json.dumps({
                "verdict": "PLAN_READY" if scope["mode"] == "passive" else "ACTIVE_WITH_GATES",
                "engagement_id": scope["id"], "mode": scope["mode"],
                "duration_limit_minutes": scope["minutes"],
                "zap_present": bool(shutil.which("zap.sh") or shutil.which("zap.bat")),
                "scope_sha256": digest,
                "limitations": "Approval claims are operator attestations; egress policy and real deployment require independent verification.",
            }, indent=2))
            return 0
        out = private_output(args.output)
        if args.command == "plan":
            result = create_plan(args.scope, out)
            print("Witch Dog plan generated privately: " + safe(out) +
                  " (mode " + result["mode"] + "; NO requests sent)")
            return 0
        if args.command == "execute":
            rc = execute(args.scope, out, args.approval_ref, args.zap_bin, args.ack_impact)
            print("Witch Dog ZAP execution finished with tool exit " + str(rc) +
                  ". Raw evidence private. Run ingest separately.")
            return 0 if rc == 0 else 2
        result = normalize_zap(args.scope, out)
        print("Witch Dog sanitized " + str(len(result["alerts"])) +
              " ZAP alerts; all require independent triage.")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Witch Dog VAPT HOLD: " + safe(exc, 320), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
