"""Offline tests for complete CISA KEV retention and schema limits."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


intel = module("intel_sync")
validator = module("validate_intel")
RSS = b"""<rss><channel><item><title>Example notice</title>
<link>https://radar.cloudflare.com/zero-wire/example</link>
<guid>example-one</guid></item></channel></rss>"""


def row(index):
    return {
        "cveID": "CVE-2026-" + str(10000 + index),
        "vulnerabilityName": "Example testing vulnerability",
        "dateAdded": "2026-11-20",
        "dueDate": "2026-12-11",
        "vendorProject": "Fixture vendor",
        "product": "Fixture product",
        "requiredAction": "Patch in an isolated fixture.",
        "shortDescription": "Synthetic, not a real advisory.",
    }


def feed(count):
    return json.dumps({"vulnerabilities": [row(i) for i in range(count)]}).encode("utf-8")


class KeVCompletenessTests(unittest.TestCase):
    def test_every_kev_is_retained_not_only_recent_seventy_five(self):
        result = intel.parse_kev(feed(81))
        self.assertEqual(len(result), 81)
        self.assertEqual(len({x["cve"] for x in result}), 81)
        self.assertEqual(result[0]["due_date"], "2026-12-11")
        self.assertEqual(result[0]["vendor"], "Fixture vendor")
        self.assertEqual(result[0]["product"], "Fixture product")
        self.assertEqual(result[0]["source_kind"], "KNOWN_EXPLOITED")

    def test_build_and_validation_accept_complete_catalog(self):
        doc = intel.build(RSS, feed(81))
        self.assertEqual(len(doc["advisories"]), 82)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "latest.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual(validator.validate(p), 82)

    def test_oversized_kev_holds_instead_of_truncating(self):
        with self.assertRaisesRegex(ValueError, "complete-catalog safety"):
            intel.parse_kev(feed(intel.MAX_KEV_ITEMS + 1))

    def test_malformed_entry_holds_instead_of_silent_drop(self):
        malformed = json.dumps({
            "vulnerabilities": [row(0), {"cveID": "UNKNOWN"}]
        }).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "refuse partial catalog"):
            intel.parse_kev(malformed)

    def test_mismatched_cve_id_or_invalid_due_date_is_rejected(self):
        doc = intel.build(RSS, feed(2))
        kev = next(x for x in doc["advisories"] if x["source"] == "cisa-kev")
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "latest.json"
            kev["id"] = "cisa-kev:CVE-2026-99999"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CVE or ID"):
                validator.validate(p)
            kev["id"] = "cisa-kev:" + kev["cve"]
            kev["due_date"] = "today!"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "KEV date"):
                validator.validate(p)

    def test_sources_must_use_verified_public_feeds(self):
        doc = intel.build(RSS, feed(1))
        doc["sources"][0] = "https://unknown.example/feeds"
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "latest.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sources"):
                validator.validate(p)

    def test_non_kev_published_rss_date_does_not_require_iso(self):
        rss = b"""<rss><channel><item><title>Example notice</title>
        <link>https://radar.cloudflare.com/zero-wire/example</link>
        <pubDate>Fri, 20 Nov 2026 00:00:00 GMT</pubDate>
        </item></channel></rss>"""
        doc = intel.build(rss, feed(1))
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "latest.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual(validator.validate(p), 2)


if __name__ == "__main__":
    unittest.main()
