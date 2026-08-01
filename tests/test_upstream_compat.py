import json
import os
import sys
import unittest
from unittest.mock import patch


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from main import (  # noqa: E402
    api_headers,
    app,
    extract_images,
    normalize_provider,
    tudou_async_resolution,
    tudou_async_size,
)


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

    def test_apimart_markdown_data_url_is_extracted(self):
        raw = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "![image](data:image/jpeg;base64,YWJj)"}
                        ]
                    }
                }
            ]
        }
        self.assertEqual(
            extract_images(raw),
            [{"type": "b64", "value": "YWJj", "mime_type": "image/jpeg"}],
        )


class UpstreamProtocolCompatibilityTests(unittest.TestCase):
    def test_tudou_host_migrates_to_dedicated_async_image_mode(self):
        provider = normalize_provider(
            {
                "id": "tudou",
                "name": "Tudou",
                "base_url": "https://api.ai-tudou.net",
                "protocol": "openai",
                "image_models": ["gpt-image-2-4k"],
            }
        )
        self.assertEqual(provider["protocol"], "openai")
        self.assertEqual(provider["image_request_mode"], "tudou-async")
        self.assertEqual(tudou_async_size("2048x2048", "16:9"), "16:9")
        self.assertEqual(tudou_async_resolution("gpt-image-2-4k", "", ""), "4k")

    def test_midjourney_routes_and_canvas_entry_are_present(self):
        route_paths = {route.path for route in app.routes}
        self.assertTrue(
            {
                "/api/midjourney/submit",
                "/api/midjourney/actions",
                "/api/midjourney/modal",
                "/api/midjourney/tasks/{task_id}",
            }.issubset(route_paths)
        )
        with open(os.path.join(ROOT, "static", "canvas.html"), encoding="utf-8") as handle:
            html = handle.read()
        with open(os.path.join(ROOT, "static", "js", "canvas.js"), encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("menuAdd('midjourney')", html)
        self.assertIn("function addMidjourneyNode", source)
        self.assertIn("async function runMidjourneyNode", source)

    def test_windows_gpt_image_helper_is_bundled(self):
        vendor = os.path.join(ROOT, "CLI", "windows", "openai", "vendor")
        expected = {
            "gpt-image-2-skill-0.7.3.tgz",
            "gpt-image-2-skill-windows-arm64-msvc-0.7.3.tgz",
            "gpt-image-2-skill-windows-x64-msvc-0.7.3.tgz",
        }
        self.assertTrue(expected.issubset(set(os.listdir(vendor))))


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
        self.assertEqual(version, "2026.08.01")
        self.assertEqual(notes["version"], version)
        self.assertEqual(len(notes["items"]), 4)


if __name__ == "__main__":
    unittest.main()
