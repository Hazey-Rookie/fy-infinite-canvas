import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = ROOT / "static" / "index.html"


class Tripo3dEmbedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = INDEX_HTML.read_text(encoding="utf-8")

    def test_menu_switches_to_embedded_page_without_new_tab(self):
        self.assertIn("onclick=\"switchUI(this, 'tripo3d')\"", self.source)
        self.assertNotRegex(
            self.source,
            r'href="https://developers\.tripo3d\.ai/zh/models"[^>]*target="_blank"',
        )
        self.assertRegex(self.source, r"const PAGE_IDS = \[[^\]]*'tripo3d'")

    def test_external_frame_uses_expected_privacy_boundary(self):
        self.assertRegex(
            self.source,
            r'id="frame-tripo3d"[^>]*data-src="https://developers\.tripo3d\.ai/zh/models"[^>]*referrerpolicy="no-referrer"',
        )
        sync_auth = re.search(
            r"function syncAuthToFrame\(iframe\) \{(?P<body>.*?)\n        \}",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(sync_auth)
        self.assertIn("origin !== window.location.origin", sync_auth.group("body"))
        self.assertIn("postMessage({type:'studio-auth'", sync_auth.group("body"))


if __name__ == "__main__":
    unittest.main()
