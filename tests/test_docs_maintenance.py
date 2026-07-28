import datetime as dt
import tempfile
import unittest
from pathlib import Path

from tools.docs_maintenance import archive, archive_candidates, parse_frontmatter


class DocumentationMaintenanceTests(unittest.TestCase):
    def test_parse_frontmatter_converts_booleans_and_preserves_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.md"
            path.write_text(
                "---\nid: FY-1\nverified: true\nfeishu_url: https://example.test/a:b\n---\n# Title\n",
                encoding="utf-8",
            )
            metadata = parse_frontmatter(path)
        self.assertEqual(metadata["id"], "FY-1")
        self.assertIs(metadata["verified"], True)
        self.assertEqual(metadata["feishu_url"], "https://example.test/a:b")

    def test_archive_requires_verified_implementation_and_uses_quarter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / ".codex" / "project-docs" / "requirements" / "active"
            active.mkdir(parents=True)
            source = active / "FY-1-example.md"
            source.write_text(
                "---\nid: FY-1\ntitle: Example\nstatus: implemented\nverified: true\nimplementation_ref: abc123\ncompleted_at: 2026-07-24\n---\n",
                encoding="utf-8",
            )
            candidates = archive_candidates(root, dt.date(2026, 7, 24))
            self.assertEqual(candidates[0][2].relative_to(root).as_posix(), ".codex/project-docs/requirements/archive/2026/Q3/FY-1-example.md")
            messages = archive(root, apply=True, today=dt.date(2026, 7, 24))
            self.assertEqual(len(messages), 1)
            self.assertFalse(source.exists())
            self.assertTrue((root / ".codex/project-docs/requirements/archive/2026/Q3/FY-1-example.md").exists())


if __name__ == "__main__":
    unittest.main()
