#!/usr/bin/env python3
"""Deterministic public-advisory ingestion. No LLM and no untrusted code execution."""
from __future__ import annotations
import argparse
import datetime as dt
import html
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ZERO_WIRE = "https://radar.cloudflare.com/security/zero-wire/rss"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
ALLOWED_URLS = {ZERO_WIRE, CISA_KEV, CISA_KEV_MIRROR}
MAX_DOWNLOAD = 8_000_000
MAX_ITEMS = 75

def clean(value, limit=250):
    text = re.sub(r"<[^>]*>", " ", html.unescape(str(value or "")))
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]

def fetch(url):
    target = urllib.parse.urlparse(url)
    if target.scheme != "https" or url not in ALLOWED_URLS:
        raise ValueError("Feed URL is not on the explicit allowlist")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise ValueError("Unexpected feed redirect; review manually")
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "WitchDog/0.1 security-intel-ingestion"})
    with opener.open(request, timeout=20) as response:
        if response.status != 200:
            raise ValueError("HTTP status was not 200")
        body = response.read(MAX_DOWNLOAD + 1)
        if len(body) > MAX_DOWNLOAD:
            raise ValueError("Feed exceeded maximum size")
        return body

def fetch_kev():
    """Use the official CISA-maintained KEV GitHub mirror if cisa.gov blocks automated clients."""
    try:
        return fetch(CISA_KEV)
    except (urllib.error.URLError, TimeoutError, OSError):
        print("CISA primary unavailable; attempting its official GitHub mirror", file=sys.stderr)
        return fetch(CISA_KEV_MIRROR)

def parse_zero_wire(raw):
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("XML document type/entities rejected")
    root = ET.fromstring(raw)
    items = []
    for entry in root.findall(".//item")[:MAX_ITEMS]:
        title = clean(entry.findtext("title"), 180)
        link = clean(entry.findtext("link"), 500)
        guid = clean(entry.findtext("guid"), 280)
        published = clean(entry.findtext("pubDate"), 90)
        summary = clean(entry.findtext("description"), 220)
        uri = urllib.parse.urlparse(link)
        if not title or uri.scheme != "https" or uri.hostname not in ("radar.cloudflare.com", "blog.cloudflare.com"):
            continue
        items.append({"id": "zero-wire:" + (guid or link), "source": "cloudflare-zero-wire",
                      "title": title, "url": link, "published": published, "summary": summary,
                      "source_kind": "CURATED_NEWS_NOT_PATCH_AUTHORITY"})
    if not items:
        raise ValueError("Zero Wire RSS returned no valid entries")
    return items

def parse_kev(raw):
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("CISA KEV response failed schema check")
    items = []
    for row in data["vulnerabilities"]:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cveID", ""))
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        items.append({"id": "cisa-kev:" + cve, "source": "cisa-kev", "cve": cve,
                      "title": clean(row.get("vulnerabilityName", ""), 180),
                      "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                      "published": clean(row.get("dateAdded", ""), 40),
                      "summary": clean(row.get("shortDescription", ""), 220),
                      "source_kind": "KNOWN_EXPLOITED"})
    if not items:
        raise ValueError("CISA KEV response returned no CVEs")
    return sorted(items, key=lambda x: (x["published"], x["id"]), reverse=True)[:MAX_ITEMS]

def build(zero_wire, kev):
    all_items = parse_zero_wire(zero_wire) + parse_kev(kev)
    uniques = {row["id"]: row for row in all_items}
    return {"schema_version": 1, "sources": [ZERO_WIRE, CISA_KEV],
            "advisories": sorted(uniques.values(), key=lambda x: (x["source"], x["id"]))}

def sync(output):
    z = fetch(ZERO_WIRE)
    k = fetch_kev()
    result = build(z, k)
    if output.exists():
        try:
            existing = json.loads(output.read_text("utf-8"))
            old_content = {key: existing.get(key) for key in ("schema_version", "sources", "advisories")}
            if old_content == result:
                print("No intelligence changes")
                return 0
        except (OSError, ValueError):
            pass
    result["updated_utc"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(".tmp")
    tmp.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    tmp.replace(output)
    print("Updated %s with %d distinct public advisories" % (output, len(result["advisories"])))
    return 0

def main():
    p = argparse.ArgumentParser(description="Fetch allowlisted Zero Wire RSS + CISA KEV JSON")
    p.add_argument("--out", type=Path, default=Path("data/intel/latest.json"))
    args = p.parse_args()
    try:
        return sync(args.out)
    except (ValueError, urllib.error.URLError, ET.ParseError, TimeoutError, OSError) as exc:
        print("Witch Dog intelligence HOLD: " + type(exc).__name__ + "; preserving last good file", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
