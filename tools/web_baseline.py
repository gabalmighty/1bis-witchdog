#!/usr/bin/env python3
"""Witch Dog WEB-01: one-request HTTPS/HTTP header baseline for authorized origins.

Standard-library only. No cookies or credentials sent, no body read, no redirects
followed, no crawl, no injection, no WAF evasion, no client data publication.
DNS answers are checked *and pinned to the TCP connection* to resist rebinding.
"""
from __future__ import annotations

import argparse
import hashlib
import datetime as dt
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "0.1.0"
TIMEOUT = 5
MAX_COOKIES = 20

def scrub(value: object, limit: int = 180) -> str:
    raw = str(value).replace("\r", " ").replace("\n", " ").replace("|", "/")
    return "".join(c for c in raw if c.isprintable() and c not in ("\x1b", chr(96)))[:limit]

def parse_target(url: str, *, allow_private=False, allow_http=False) -> dict:
    if not isinstance(url, str) or len(url) > 1024 or any(ord(c) < 33 for c in url):
        raise ValueError("Target URL must be a bounded, whitespace-free http(s) origin")
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.netloc:
        raise ValueError("Target URL must be an explicit http(s) origin")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("Embedded credentials/userinfo are forbidden")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("Target must be an origin only, without path/query/fragment")
    if parts.scheme == "http" and not allow_http:
        raise ValueError("Plain HTTP requires explicit --allow-http (laboratory use)")
    host = parts.hostname
    if not host or "%" in host or "\\" in host:
        raise ValueError("Invalid hostname")
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if not literal:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Invalid IDNA hostname") from exc
        labels = host.split(".")
        if len(host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x)
                                        for x in labels):
            raise ValueError("Invalid DNS hostname")
    try:
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Port is out of range")
    origin = parts.scheme + "://" + ("[" + host + "]" if ":" in host else host)
    if port != (443 if parts.scheme == "https" else 80):
        origin += ":" + str(port)
    return {"scheme": parts.scheme, "host": host, "port": port, "origin": origin,
            "allow_private": bool(allow_private)}

def pinned_addresses(target: dict) -> list[str]:
    try:
        results = socket.getaddrinfo(target["host"], target["port"], type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("DNS resolution failed") from exc
    addresses = []
    for entry in results:
        address = entry[4][0].split("%", 1)[0]
        obj = ipaddress.ip_address(address)
        if not obj.is_global and not target["allow_private"]:
            raise ValueError("Non-global DNS destination denied; explicit --allow-private needed")
        if obj.is_multicast or obj.is_unspecified or obj.is_reserved or obj.is_link_local:
            raise ValueError("Unroutable/reserved destination denied")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("No usable DNS destinations")
    return addresses[:8]

def one_request(target: dict, ip: str) -> dict:
    conn = http.client.HTTPConnection(target["host"], port=target["port"], timeout=TIMEOUT)
    tls = {"status": "NOT_APPLICABLE", "version": None, "certificate_not_after": None}
    try:
        socket_obj = socket.create_connection((ip, target["port"]), timeout=TIMEOUT)
        if target["scheme"] == "https":
            context = ssl.create_default_context()
            try:
                socket_obj = context.wrap_socket(socket_obj, server_hostname=target["host"])
            except BaseException:
                socket_obj.close()
                raise
            cert = socket_obj.getpeercert()
            tls = {
                "status": "VERIFIED", "version": scrub(socket_obj.version(), 30),
                "certificate_not_after": scrub(cert.get("notAfter", ""), 70),
            }
        conn.sock = socket_obj
        conn.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
        host_header = target["host"] if ":" not in target["host"] else "[" + target["host"] + "]"
        if target["port"] != (443 if target["scheme"] == "https" else 80):
            host_header += ":" + str(target["port"])
        conn.putheader("Host", host_header)
        conn.putheader("User-Agent", "WitchDog-WebBaseline/0.1 (+authorized passive inspection)")
        conn.putheader("Accept", "text/html,application/json;q=0.9,*/*;q=0.5")
        conn.putheader("Connection", "close")
        conn.endheaders()
        response = conn.getresponse()
        # Do not read HTML, JSON, sessions, or other body content.
        headers = [(key.lower(), val) for key, val in response.getheaders()][:100]
        return {"status": response.status, "headers": headers, "tls": tls,
                "method": "GET", "path": "/", "redirects_followed": 0}
    finally:
        conn.close()

def check_headers(target: dict, observed: dict) -> list[dict]:
    headers = observed["headers"]
    lookup = {}
    for key, value in headers:
        lookup.setdefault(key.lower(), []).append(value)
    findings = []

    def add(control, verdict, why):
        findings.append({"control_id": control, "verdict": verdict,
                         "test_status": "EXECUTED", "evidence_class": "REMOTE_OBSERVED",
                         "evidence": scrub(why, 280)})

    add("WEB-01.03", "PASS", "Single-origin GET returned HTTP " + str(observed["status"]) +
        "; redirects not followed")
    add("WEB-02.01", "PASS" if target["scheme"] == "https" else "UNKNOWN",
        "TLS certificate validation " + observed["tls"]["status"])
    if target["scheme"] == "https":
        value = lookup.get("strict-transport-security", [""])[0]
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d{1,12})", value, re.I)
        if not match:
            add("WEB-02.03", "WARN", "HSTS max-age not observed on this single response")
        elif int(match.group(1)) < 15552000:
            add("WEB-02.03", "WARN", "HSTS max-age is shorter than a common six-month baseline")
        else:
            add("WEB-02.03", "PASS", "HSTS max-age observed and at least six months")
    else:
        add("WEB-02.03", "N/A", "HSTS is evaluated on HTTPS, not this explicit HTTP lab request")
    csp = lookup.get("content-security-policy", [""])[0]
    if not csp:
        add("WEB-02.04", "WARN", "Content-Security-Policy absent on this origin response")
    elif "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower():
        add("WEB-02.04", "WARN", "CSP observed; contains unsafe-inline or unsafe-eval; review context")
    else:
        add("WEB-02.04", "PASS", "CSP header observed; full effectiveness NOT tested")
    add("WEB-02.05", "PASS" if "nosniff" in " ".join(lookup.get("x-content-type-options", [])).lower()
        else "WARN", "X-Content-Type-Options nosniff present" if lookup.get("x-content-type-options") and
        "nosniff" in " ".join(lookup["x-content-type-options"]).lower() else "nosniff not observed")
    if "frame-ancestors" in csp.lower() or lookup.get("x-frame-options"):
        add("WEB-02.06", "PASS", "A frame-embedding restriction is declared; browser enforcement untested")
    else:
        add("WEB-02.06", "WARN", "No frame-ancestors CSP or X-Frame-Options observed")
    add("WEB-02.07", "PASS" if lookup.get("referrer-policy") else "WARN",
        "Referrer-Policy observed" if lookup.get("referrer-policy") else "Referrer-Policy absent")
    add("WEB-02.08", "PASS" if lookup.get("permissions-policy") else "WARN",
        "Permissions-Policy observed" if lookup.get("permissions-policy") else "Permissions-Policy absent; review applicability")
    status = observed["status"]
    if 300 <= status < 400:
        location = lookup.get("location", [""])[0]
        kind = "NO_LOCATION"
        if location:
            split = urlsplit(location)
            if split.netloc and split.hostname and split.hostname.lower() != target["host"]:
                kind = "CROSS_ORIGIN_UNFOLLOWED"
            else:
                kind = "RELATIVE_OR_SAME_ORIGIN_UNFOLLOWED"
        add("WEB-02.09", "WARN", "Redirect observed: " + kind + "; no destination request")
    else:
        add("WEB-02.09", "PASS", "No redirect on the single inspected response")
    cookie_count = 0
    cookie_warnings = 0
    for name, value in headers:
        if name != "set-cookie" or cookie_count >= MAX_COOKIES:
            continue
        cookie_count += 1
        tokens = [p.strip().lower() for p in value.split(";")]
        flags = set(t.split("=", 1)[0] for t in tokens[1:])
        if "samesite" in flags:
            same_site = next((t.split("=", 1)[1] for t in tokens[1:]
                             if t.startswith("samesite=")), "")
        else:
            same_site = ""
        if target["scheme"] == "https" and "secure" not in flags:
            cookie_warnings += 1
        if same_site == "none" and "secure" not in flags:
            cookie_warnings += 1
        cookie_name = tokens[0].split("=", 1)[0]
        if re.search(r"(session|auth|token|sid|jwt)", cookie_name) and "httponly" not in flags:
            cookie_warnings += 1
    if cookie_count:
        add("WEB-05.01", "WARN" if cookie_warnings else "PASS",
            str(cookie_count) + " cookie header(s) inspected for flags only; " +
            str(cookie_warnings) + " flag concern(s); cookie names/values NOT stored")
    else:
        add("WEB-05.01", "N/A", "No Set-Cookie headers on this single response; session flow NOT tested")
    return findings

def format_md(report: dict) -> str:
    lines = ["# Witch Dog WEB-01 — authorized baseline", "",
        "> PRIVATE local evidence; **not** full VAPT or OWASP compliance proof.",
        "",
        "- Origin: " + scrub(report["origin"]),
        "- UTC: " + report["timestamp_utc"],
        "- Tier: BASELINE; authorized operator assertion: " + str(report["authorized"]),
        "- Requests issued: " + str(report["request_count"]),
        "- Redirects followed: 0",
        "- Result: " + report["state"],
        "- Observation: REMOTE_OBSERVED only; deployed origin/source UNKNOWN",
        "", "| Control | Verdict | Evidence |", "|---|---|---|"]
    for item in report["findings"]:
        lines.append("| " + item["control_id"] + " | " + item["verdict"] +
                     " | " + scrub(item["evidence"], 280) + " |")
    lines += ["", "## Coverage limitations", ""]
    lines += ["- " + scrub(x, 230) for x in report["limitations"]]
    lines += ["", "No HTML/body, session secrets, login, crawling, APIs, origin image or business-logic testing.",
              "All unexecuted WEB-XX controls are UNKNOWN / NOT_RUN.", ""]
    return "\n".join(lines)

def perform(target: dict) -> dict:
    record = {"schema_version": 1, "tool": "witchdog-web-baseline",
        "version": VERSION, "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "origin": target["origin"], "authorized": True, "mode": "BASELINE",
        "request_count": 0, "network_attempts": 0, "redirects_followed": 0, "state": "UNKNOWN",
        "evidence_class": "REMOTE_OBSERVED", "findings": [],
        "limitations": [
            "The scanner inspected only root /; all other routes and most checklist controls remain UNKNOWN",
            "No authenticated role, API, CSRF, XSS, injection, workflow or origin-runtime inspection occurred",
            "Security headers are observations, not proof of effective backend authorization",
            "HTTP/2 and HTTP/3 feature exposure, WAF bypass and deployment topology NOT tested",
        ]}
    try:
        ips = pinned_addresses(target)
        record["network_attempts"] = 1
        observed = one_request(target, ips[0])
        record["request_count"] = 1
        record["status_code"] = observed["status"]
        record["tls"] = observed["tls"]
        record["findings"] = check_headers(target, observed)
        record["state"] = "OBSERVED"
        if observed["status"] in (401, 403, 429, 503):
            record["limitations"].append("Response may be auth/rate-limit/WAF/challenge; do not infer application safety")
    except (ValueError, ssl.SSLError, OSError, http.client.HTTPException) as error:
        record["state"] = "BLOCKED"
        record["evidence_class"] = "UNKNOWN"
        record["limitations"].append("Request/DNS/TLS prevented observation: " + type(error).__name__)
        if isinstance(error, ssl.SSLError):
            record["findings"].append({"control_id": "WEB-02.01", "verdict": "WARN",
                "test_status": "BLOCKED", "evidence_class": "REMOTE_OBSERVED",
                "evidence": "TLS handshake/certificate validation failed; did NOT bypass verification"})
    return record

def main(argv=None):
    p = argparse.ArgumentParser(description="One-request, authorized root-only web baseline; not VAPT")
    p.add_argument("--target", required=True, help="Exact authorized origin, e.g. https://app.example.com")
    p.add_argument("--authorized", action="store_true", help="Assert documented ownership/permission for this origin")
    p.add_argument("--allow-private", action="store_true", help="Explicitly opt in to private/loopback LAB addresses")
    p.add_argument("--allow-http", action="store_true", help="Explicitly opt in to plain HTTP LAB requests")
    p.add_argument("--output", required=True, type=Path, help="PRIVATE local report folder")
    args = p.parse_args(argv)
    if not args.authorized:
        p.error("Explicit --authorized scope assertion is required; NO request sent")
    try:
        target = parse_target(args.target, allow_private=args.allow_private, allow_http=args.allow_http)
    except ValueError as exc:
        print("Witch Dog HOLD: " + scrub(exc), file=sys.stderr)
        return 2
    report = perform(target)
    output = args.output.expanduser().resolve()
    try:
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(output, 0o700)
        files = {"report.json": json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                 "report.md": format_md(report)}
        for name, content in files.items():
            path = output / name
            path.write_text(content, encoding="utf-8")
            if os.name == "posix":
                os.chmod(path, 0o600)
        # Digests support evidence integrity and run reproducibility; not publisher authenticity.
        project = Path(__file__).resolve().parents[1]
        def digest(path):
            return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        manifest = {
            "schema_version": 1,
            "report_sha256": digest(output / "report.json"),
            "web_prompt_sha256": digest(project / "web_prompt.md"),
            "checklist_sha256": digest(project / "checklists" / "webapp-vapt-v1.md"),
            "note": "SHA-256 evidence identifiers only; no authenticity/signature claim"
        }
        manifest_path = output / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(manifest_path, 0o600)
    except OSError:
        print("Witch Dog HOLD: failed to write private local report", file=sys.stderr)
        return 2
    print("Witch Dog WEB baseline: " + report["state"] + ", " +
          str(report["request_count"]) + " request(s), reports: " + str(output))
    return 0 if report["state"] == "OBSERVED" else 2

if __name__ == "__main__":
    raise SystemExit(main())
