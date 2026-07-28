import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = ROOT / "static" / "index.html"


class Tripo3dEmbedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = INDEX_HTML.read_text(encoding="utf-8")

    def test_menu_opens_official_site_in_a_new_tab(self):
        self.assertRegex(
            self.source,
            r'<a class="nav-item" href="https://www\.tripo3d\.ai/" target="_blank" rel="noopener noreferrer"',
        )
        self.assertIn('onclick="markExternalNavActive(this)"', self.source)
        self.assertNotIn('window.location.assign(TRIPO3D_URL)', self.source)
        self.assertNotRegex(self.source, r"const PAGE_IDS = \[[^\]]*'tripo3d'")

    def test_old_embedded_frame_is_removed(self):
        self.assertNotIn('id="frame-tripo3d"', self.source)


if __name__ == "__main__":
    unittest.main()
