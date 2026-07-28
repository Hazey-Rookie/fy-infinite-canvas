import json
import os
import sys
import unittest
from unittest.mock import patch


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from main import api_headers  # noqa: E402


class ApiMartCompatibilityTests(unittest.TestCase):
    def test_apimart_gemini_override_uses_bearer_auth(self):
        provider = {
            "id": "custom-apimart",
            "name": "APIMART",
            "base_url": "https://api.apimart.ai",
            "protocol": "openai",
            "model_protocols": {"gemini-image": "gemini"},
        }
        with patch("main.provider_env_key_value", return_value="secret"):
            headers = api_headers(provider=provider, model="gemini-image")
        self.assertEqual(headers["Authorization"], "Bearer secret")
        self.assertNotIn("x-goog-api-key", headers)

    def test_native_gemini_provider_keeps_google_api_key_header(self):
        provider = {
            "id": "native-gemini",
            "name": "Gemini",
            "base_url": "https://generativelanguage.googleapis.com",
            "protocol": "gemini",
        }
        with patch("main.provider_env_key_value", return_value="secret"):
            headers = api_headers(provider=provider, model="gemini-image")
        self.assertEqual(headers["x-goog-api-key"], "secret")
        self.assertNotIn("Authorization", headers)


class HighResolutionLazyLoadContractTests(unittest.TestCase):
    def test_canvas_frontends_use_viewport_aware_high_resolution_loading(self):
        expectations = {
            "static/js/canvas.js": (
                "const CANVAS_HIGH_RES_ZOOM_THRESHOLD = 0.86;",
                "canvasImageNearViewport",
                "scheduleCanvasImageResolutionSync(nodesEl, 120);",
            ),
            "static/js/smart-canvas.js": (
                "const SMART_HIGH_RES_ZOOM_THRESHOLD = 0.86;",
                "smartImageNearViewport",
                "scheduleSmartImageResolutionSync(world, 120);",
            ),
        }
        for relative_path, markers in expectations.items():
            with self.subTest(path=relative_path):
                with open(os.path.join(ROOT, relative_path), encoding="utf-8") as handle:
                    source = handle.read()
                for marker in markers:
                    self.assertIn(marker, source)
                self.assertIn("const IMAGE_GENERATION_MAX = 3;", source)

    def test_upstream_notes_match_installed_version(self):
        with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as handle:
            version = handle.read().strip()
        with open(os.path.join(ROOT, "static", "update-notes.json"), encoding="utf-8") as handle:
            notes = json.load(handle)
        self.assertEqual(version, "2026.07.28.1")
        self.assertEqual(notes["version"], version)
        self.assertEqual(len(notes["items"]), 2)


if __name__ == "__main__":
    unittest.main()
