#!/usr/bin/env python3
"""Validate the curated, public developer malware reference.

This does not make a source indicator a confirmed local infection.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_CATALOG = 20000
SOURCES = {
    "https://www.sonatype.com/blog/polinrider-loader-reappears-in-hijacked-npm-packages",
    "https://blog.gitguardian.com/ghostaction-x-polinrider/",
}
CODES = {"M" + str(x).zfill(2) for x in range(1, 10)}


def validate(path: Path) -> dict:
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= MAX_CATALOG:
        raise ValueError("Curated catalog missing or oversized")
    obj = json.loads(path.read_text("utf-8"))
    if (not isinstance(obj, dict) or obj.get("schema_version") != 1 or
            obj.get("id") != "developer-supply-chain-2026" or
            obj.get("classification") != "PUBLIC_SOURCE_SUMMARY"):
        raise ValueError("Invalid curated catalog")
    sources = obj.get("sources")
    if not isinstance(sources, list) or len(sources) != 2:
        raise ValueError("Expected two primary public sources")
    seen_urls = set()
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("Invalid public source")
        url = source.get("url")
        if url not in SOURCES or url in seen_urls:
            raise ValueError("Unreviewed or duplicate public source")
        seen_urls.add(url)
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(source.get("date", ""))):
            raise ValueError("Invalid date")
        dt.date.fromisoformat(source["date"])
        if len(str(source.get("publisher", ""))) > 80:
            raise ValueError("Publisher label too long")
    if seen_urls != SOURCES:
        raise ValueError("Public source coverage incomplete")
    checks = obj.get("behavioral_checks")
    if not isinstance(checks, list) or len(checks) != 9:
        raise ValueError("Expected reviewed behavior controls")
    if {c.get("control") for c in checks if isinstance(c, dict)} != CODES:
        raise ValueError("Unexpected behavior control IDs")
    for c in checks:
        if (not isinstance(c, dict) or c.get("category") not in (
                "host", "repository", "dependency") or
                not 2 <= len(str(c.get("label", ""))) <= 90 or
                len(str(c.get("basis", ""))) > 240):
            raise ValueError("Invalid behavior control")
    entries = obj.get("npm_exact_releases")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
        raise ValueError("Invalid npm reference list")
    seen = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("Invalid npm release")
        name, version = item.get("package"), item.get("version")
        if (not isinstance(name, str) or
                not re.fullmatch(r"(?:@[a-zA-Z0-9_-]+/)?[a-zA-Z0-9_.-]{1,100}", name)
                or not isinstance(version, str)
                or not re.fullmatch(r"[0-9][A-Za-z0-9.+-]{0,69}", version)
                or (name, version) in seen):
            raise ValueError("Invalid or duplicate npm release")
        seen.add((name, version))
    return {"status": "PASS", "controls": len(checks), "releases": len(entries),
            "source_count": len(seen_urls)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate published developer-threat data")
    parser.add_argument("--file", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.file), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        print("Witch Dog threat reference HOLD: invalid published catalog", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
