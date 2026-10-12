import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build

class TestSite(unittest.TestCase):
    def test_escape_untrusted_feed(self):
        feed = {k: '' for k in ['cveID','dateAdded','vendorProject','product','vulnerabilityName','shortDescription','requiredAction','dueDate','knownRansomwareCampaignUse','notes']}
        feed.update(cveID='CVE-2025-12345', dateAdded='2026-09-01', vulnerabilityName='<script>alert(1)</script>')
        html = build.alert_card(feed)
        self.assertNotIn('<script>alert(1)', html)
        self.assertIn('&lt;script&gt;', html)

    def test_no_ads_enabled_for_bad_publisher(self):
        cfg = {'adsense_publisher_id': 'example', 'adsense_slot_id': '123'}
        self.assertIn('Ads only appear', build.ad(cfg))
        self.assertNotIn('adsbygoogle', build.ad(cfg))

    def test_ads_account_verification_while_disabled(self):
        cfg = {'site_name': 'Test', 'adsense_publisher_id': 'ca-pub-1234567890123456',
               'adsense_slot_id': '1234567890', 'ads_enabled': False}
        head = build.chrome(cfg, 'Title', 'Description', '<p>Content</p>')
        self.assertIn('google-adsense-account', head)
        self.assertNotIn('pagead2.googlesyndication.com', head)
        self.assertIn('Ads only appear', build.ad(cfg))

    def test_ads_txt_requires_real_publisher_id(self):
        self.assertEqual(build.ads_txt_line({}), '')
        self.assertEqual(build.ads_txt_line({'adsense_publisher_id': 'fake'}), '')
        self.assertEqual(build.ads_txt_line({'adsense_publisher_id': 'ca-pub-1234567890123456'}),
                         'google.com, pub-1234567890123456, DIRECT, f08c47fec0942fa0\n')

    def test_source_validation_and_sorting(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'kev.json'
            file.write_text(json.dumps({'dateReleased':'2026-10-01', 'vulnerabilities':[
                {'cveID':'CVE-2024-1234','dateAdded':'2026-09-01'},
                {'cveID':'NOT-CVE','dateAdded':'2026-10-01'},
                {'cveID':'CVE-2025-12345','dateAdded':'2026-10-01'}]}))
            with patch.object(build, 'DATA', file):
                records, _, _ = build.load_data()
                self.assertEqual(len(records), 2)
                self.assertEqual(records[0]['cveID'], 'CVE-2025-12345')

if __name__ == '__main__':
    unittest.main()
