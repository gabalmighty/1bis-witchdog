#!/usr/bin/env python3
"""Validate public data before the privileged PR publication step."""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

def validate(path):
    if path.stat().st_size > 300000:
        raise ValueError("File too large")
    obj = json.loads(path.read_text(encoding="utf-8"))
    rows = obj.get("advisories")
    if obj.get("schema_version") != 1 or not isinstance(rows, list) or len(rows) > 150:
        raise ValueError("Invalid schema")
    if not isinstance(obj.get("sources"), list) or len(obj["sources"]) != 2:
        raise ValueError("Invalid sources")
    ids = set()
    for item in rows:
        if not isinstance(item, dict):
            raise ValueError("Invalid row")
        if item.get("source") not in ("cisa-kev", "cloudflare-zero-wire"):
            raise ValueError("Unknown source")
        if not isinstance(item.get("title"), str) or not 1 <= len(item["title"]) <= 180:
            raise ValueError("Invalid title")
        if not isinstance(item.get("summary", ""), str) or len(item["summary"]) > 220:
            raise ValueError("Invalid summary")
        id_ = item.get("id")
        if not isinstance(id_, str) or len(id_) > 600 or id_ in ids:
            raise ValueError("Invalid ID")
        ids.add(id_)
        parsed = urlparse(item.get("url", ""))
        if parsed.scheme != "https" or parsed.hostname not in (
            "radar.cloudflare.com", "blog.cloudflare.com", "www.cisa.gov"
        ):
            raise ValueError("Unallowlisted URL")
        if item["source"] == "cisa-kev" and not re.fullmatch(r"CVE-\d{4}-\d{4,}", item.get("cve", "")):
            raise ValueError("Invalid CVE")
    return len(rows)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--file", required=True, type=Path)
    args = p.parse_args()
    try:
        count = validate(args.file)
        print("Validated", count, "public advisories")
    except (OSError, ValueError, TypeError):
        print("Witch Dog intelligence HOLD: failed schema validation", file=sys.stderr)
        raise SystemExit(2)
