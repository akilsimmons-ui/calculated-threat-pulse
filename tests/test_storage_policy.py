"""Storage policy and retention regression checks."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build
import cve_pages
import storage_policy


def row(cve, date):
    return {"cveID": cve, "dateAdded": date, "vendorProject": "Example",
            "product": "Sample", "vulnerabilityName": "Example issue",
            "shortDescription": "Published CISA source record.",
            "requiredAction": "Review current vendor guidance.",
            "dueDate": "", "knownRansomwareCampaignUse": "", "notes": ""}


class TestStoragePolicy(unittest.TestCase):
    def test_full_source_catalog_is_not_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            cached = Path(tmp) / "kev.json"
            records = [row(f"CVE-2026-{x:04d}", "2026-10-12") for x in range(220)]
            cached.write_text(json.dumps({"dateReleased": "2026-10-12",
                                           "vulnerabilities": records}))
            with patch.object(build, "DATA", cached):
                data, _, _ = build.load_data()
                self.assertEqual(len(data), 220)

    def test_page_cap_keeps_prior_urls_and_skips_new_pages(self):
        config = {"site_name": "Test", "site_url": "https://pulse.example.org", "ads_enabled": False}
        older = row("CVE-2026-11111", "2026-10-12")
        newer = row("CVE-2026-22222", "2026-10-13")
        with tempfile.TemporaryDirectory() as tmp, patch.object(cve_pages, "CVE_PAGE_LIMIT", 1):
            root = Path(tmp)
            old_pages = cve_pages.build_cve_library(
                config, [older], root, build.chrome, build.esc)
            self.assertIn("/cve/CVE-2026-11111.html", old_pages)
            new_pages = cve_pages.build_cve_library(
                config, [newer, older], root, build.chrome, build.esc)
            self.assertEqual(len(new_pages), 2)  # index and original CVE
            self.assertTrue((root / "cve" / "CVE-2026-11111.html").exists())
            self.assertFalse((root / "cve" / "CVE-2026-22222.html").exists())

    def test_public_site_and_source_size_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "kev.json"
            raw.write_bytes(b"1234567890")
            with patch.object(storage_policy, "MAX_SOURCE_BYTES", 10):
                self.assertIsNone(storage_policy.check_source_budget(raw))
                raw.write_bytes(b"longer-than-budget")
                with self.assertRaisesRegex(RuntimeError, "safety limit"):
                    storage_policy.check_source_budget(raw)
            published = root / "public"
            published.mkdir()
            (published / "index.html").write_bytes(b"12345")
            with patch.object(storage_policy, "MAX_PUBLIC_BYTES", 5):
                self.assertEqual(storage_policy.check_public_budget(published), 5)
                (published / "extra.txt").write_bytes(b"z")
                with self.assertRaisesRegex(RuntimeError, "limit"):
                    storage_policy.check_public_budget(published)


if __name__ == "__main__":
    unittest.main()
