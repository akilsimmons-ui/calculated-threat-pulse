"""SEO regression tests: CVE pages must stay traceable, safe, and linkable."""
import json
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import build
from cve_pages import build_cve_library

class TestCveLibrary(unittest.TestCase):
    def sample(self, cve="CVE-2026-12345", date="2026-10-13"):
        return {
            "cveID": cve, "dateAdded": date, "vendorProject": "Acme",
            "product": "Router", "vulnerabilityName": "Example vulnerability",
            "shortDescription": "A source-record description, not a severity rating.",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2026-11-03", "knownRansomwareCampaignUse": "Unknown",
            "notes": "Source notes."
        }

    def test_pages_schema_escaping_and_preservation(self):
        cfg = {"site_name": "Test", "site_url": "https://pulse.example.org", "ads_enabled": False}
        first = self.sample()
        first["vendorProject"] = "<script>alert('x')</script>"
        with tempfile.TemporaryDirectory() as tmp:
            public = Path(tmp)
            urls = build_cve_library(cfg, [first], public, build.chrome, build.esc)
            self.assertIn("/cve/index.html", urls)
            self.assertIn("/cve/CVE-2026-12345.html", urls)
            text = (public / "cve" / "CVE-2026-12345.html").read_text()
            self.assertNotIn("<script>alert('x')</script>", text)
            self.assertIn("&lt;script&gt;", text)
            self.assertIn('rel="canonical" href="https://pulse.example.org/cve/CVE-2026-12345.html"', text)
            match = re.search(r'<script type="application/ld\+json">(.*?)</script>', text, re.S)
            self.assertIsNotNone(match)
            article = json.loads(match.group(1))
            self.assertEqual(article["@type"], "TechArticle")
            self.assertEqual(article["about"]["name"], "CVE-2026-12345")
            self.assertNotIn("severity", article)
            self.assertNotIn("cvss", article)
            self.assertNotIn("pagead2.googlesyndication.com", text)

            # When a new CVE arrives, the existing URL must not disappear.
            newer = self.sample("CVE-2026-54321", "2026-10-14")
            urls = build_cve_library(cfg, [newer, first], public, build.chrome, build.esc, initial_limit=1)
            self.assertEqual(len(urls), 3)
            self.assertTrue((public / "cve" / "CVE-2026-12345.html").exists())
            self.assertTrue((public / "cve" / "CVE-2026-54321.html").exists())

    def test_only_valid_source_records(self):
        cfg = {"site_name": "Test", "site_url": "https://pulse.example.org"}
        with tempfile.TemporaryDirectory() as tmp:
            public = Path(tmp)
            bad = self.sample("../../index")
            self.assertEqual(build_cve_library(cfg, [bad], public, build.chrome, build.esc), [])
            self.assertFalse((public / "cve" / "index.html").exists())
            self.assertEqual(build_cve_library(cfg, [], public, build.chrome, build.esc), [])

    def test_sitemap_and_internal_links_are_built(self):
        with tempfile.TemporaryDirectory() as tmp:
            public = Path(tmp) / "site"
            data = Path(tmp) / "kev.json"
            data.write_text(json.dumps({"catalogVersion": "test", "dateReleased": "2026-10-13",
                                         "vulnerabilities": [self.sample()]}))
            with patch.object(build, "PUBLIC", public), patch.object(build, "DATA", data):
                build.build()
                home = (public / "index.html").read_text()
                alerts = (public / "alerts.html").read_text()
                sitemap = ET.fromstring((public / "sitemap.xml").read_text())
                locs = [el.text for el in sitemap.iter() if el.tag.endswith("loc")]
                self.assertIn("https://pulse.calculatedit.com/cve/index.html", locs)
                self.assertIn("https://pulse.calculatedit.com/cve/CVE-2026-12345.html", locs)
                self.assertIn('href="/cve/CVE-2026-12345.html"', alerts)
                self.assertIn('href="/cve/index.html"', home)
                self.assertNotIn("pagead2.googlesyndication.com", home)

if __name__ == "__main__":
    unittest.main()
