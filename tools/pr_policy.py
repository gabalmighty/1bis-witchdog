#!/usr/bin/env python3
"""Fetch Witch Dog's current reviewed CHECKLIST DATA; never remote executable code.

Uses a trusted commit SHA returned by GitHub, fixed paths, strict bounds and
last-known-good checked-in fallback. This is not signed update verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

OWNER_REPO = "gabalmighty/witchdog"
ALLOWED_PATHS = ("checklists/security-v1.md", "checklists/pr-review-v1.md",
                 "checklists/identity-authorization-v1.md")
RE_SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_BYTES = 100000

class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected remote redirect rejected")

def download(url: str, *, max_size=MAX_BYTES) -> bytes:
    if not url.startswith(("https://api.github.com/repos/" + OWNER_REPO + "/",
                           "https://raw.githubusercontent.com/" + OWNER_REPO + "/")):
        raise ValueError("Unallowlisted source host/path")
    op = urllib.request.build_opener(RefuseRedirect)
    req = urllib.request.Request(url, headers={
        "User-Agent": "WitchDog-PR-Policy/0.1", "Accept": "application/json"})
    with op.open(req, timeout=12) as response:
        data = response.read(max_size + 1)
        if response.status != 200 or len(data) > max_size:
            raise ValueError("Source unavailable/oversized")
        return data

def fetch_policy(output: Path, bundled: Path, ref="main", *, offline=False) -> dict:
    if ref != "main" and not RE_SHA.fullmatch(ref):
        raise ValueError("Policy ref must be main or full audited commit SHA")
    output = output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = "PINNED_BUNDLED_FALLBACK"
    sha = None
    received = {}
    if not offline:
        try:
            if ref == "main":
                meta = json.loads(download(
                    "https://api.github.com/repos/" + OWNER_REPO + "/commits/main",
                    max_size=20000))
                sha = meta.get("sha", "")
            else:
                sha = ref
            if not RE_SHA.fullmatch(str(sha)):
                raise ValueError("GitHub ref is not valid commit SHA")
            for path in ALLOWED_PATHS:
                content = download("https://raw.githubusercontent.com/" +
                                   OWNER_REPO + "/" + sha + "/" + path)
                if not content or b"\x00" in content:
                    raise ValueError("Malformed reference content")
                content.decode("utf-8")
                received[path] = content
            source = "REVIEWED_MAIN_DATA" if ref == "main" else "PINNED_REMOTE_DATA"
        except (OSError, ValueError, UnicodeError, KeyError, urllib.error.URLError):
            received = {}
    if not received:
        for path in ALLOWED_PATHS:
            local = bundled / path
            if not local.is_file() or local.stat().st_size > MAX_BYTES:
                raise ValueError("Bundled reviewed checklist missing or oversized")
            received[path] = local.read_bytes()
        sha = "BUNDLED_UNVERIFIED_LOCAL_REVISION"
    result = {"schema_version": 1, "source": source, "source_commit": sha,
              "policies": {}, "limits": "policy data only, NOT agent instructions"}
    for path, data in received.items():
        dest = output / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink():
            raise ValueError("Refusing to overwrite symlink")
        dest.write_bytes(data)
        result["policies"][path] = hashlib.sha256(data).hexdigest()
    manifest = output / "policy-manifest.json"
    manifest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result

def main(argv=None):
    p = argparse.ArgumentParser(description="Fetch versioned Witch Dog PR checklist DATA")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--bundled", required=True, type=Path)
    p.add_argument("--ref", default="main")
    p.add_argument("--offline", action="store_true")
    args = p.parse_args(argv)
    try:
        result = fetch_policy(args.out, args.bundled, args.ref, offline=args.offline)
        print("Witch Dog policy: %s, commit %s" %
              (result["source"], result["source_commit"]))
        return 0 if result["source"] != "PINNED_BUNDLED_FALLBACK" else 2
    except (OSError, ValueError) as exc:
        print("Witch Dog policy HOLD: " + type(exc).__name__, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
