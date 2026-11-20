#!/usr/bin/env python3
"""Validate public data before the privileged PR publication step."""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

MAX_FILE_BYTES = 8_000_000
MAX_ADVISORIES = 6075  # Up to 6000 CISA KEV and 75 Cloudflare news items.

def validate(path):
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("File too large")
    obj = json.loads(path.read_text(encoding="utf-8"))
    rows = obj.get("advisories")
    if obj.get("schema_version") != 1 or not isinstance(rows, list) or len(rows) > MAX_ADVISORIES:
        raise ValueError("Invalid schema")
    if obj.get("sources") != [
        "https://radar.cloudflare.com/zero-wire/feed",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ]:
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
        if item["source"] == "cisa-kev":
            cve = item.get("cve", "")
            if (not isinstance(cve, str) or
                    not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) or
                    id_ != "cisa-kev:" + cve):
                raise ValueError("Invalid CVE or ID binding")
            for field, max_length in (("vendor", 120), ("product", 120),
                                      ("required_action", 220), ("due_date", 20)):
                val = item.get(field, "")
                if not isinstance(val, str) or len(val) > max_length:
                    raise ValueError("Invalid KEV metadata: " + field)
            for field in ("published", "due_date"):
                val = item.get(field, "")
                if val and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", val):
                    raise ValueError("Invalid KEV date: " + field)
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
