import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = ROOT / "static" / "index.html"
COMMON_I18N = ROOT / "static" / "js" / "i18n" / "common.js"


class MiaomiaoNavEmbedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = INDEX_HTML.read_text(encoding="utf-8")
        cls.common_i18n = COMMON_I18N.read_text(encoding="utf-8")

    def test_menu_and_frame_are_registered(self):
        self.assertIn("onclick=\"switchUI(this, 'miao-nav')\"", self.source)
        self.assertIn('data-i18n="nav.miaoNav">妙妙屋导航</span>', self.source)
        self.assertRegex(
            self.source,
            r'id="frame-miao-nav"[^>]*data-src="http://dh\.iiicg\.com/"[^>]*referrerpolicy="no-referrer"[^>]*title="画忆的妙妙屋导航"',
        )
        self.assertRegex(self.source, r"const PAGE_IDS = \[[^\]]*'miao-nav'")

    def test_page_title_and_translation_are_present(self):
        self.assertIn("document.title = menuName ? `棱镜 - ${menuName}` : '棱镜';", self.source)
        self.assertIn("updateDocumentTitle(document.querySelector('.nav-item.active, .side-pill.active'));", self.source)
        self.assertIn('"nav.miaoNav": { zh: "妙妙屋导航", en: "MiaoMiao Navigation" }', self.common_i18n)

    def test_menu_is_first_navigation_entry(self):
        nav_start = self.source.index("            <nav>")
        first_entry = self.source.index("onclick=\"switchUI(this, 'miao-nav')\"", nav_start)
        first_other_entry = self.source.index("onclick=\"switchUI(this, '", first_entry + 1)
        self.assertLess(first_entry, first_other_entry)


if __name__ == "__main__":
    unittest.main()
