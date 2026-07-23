import os
import sys
import unittest

from pydantic import ValidationError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from main import IMAGE_GENERATION_MAX, OnlineImageRequest, build_image_param_fields  # noqa: E402


class ImageGenerationLimitTests(unittest.TestCase):
    def test_backend_accepts_three_images(self):
        request = OnlineImageRequest(prompt="测试", n=3)
        self.assertEqual(request.n, IMAGE_GENERATION_MAX)

    def test_backend_rejects_more_than_three_images(self):
        with self.assertRaises(ValidationError):
            OnlineImageRequest(prompt="测试", n=4)

    def test_dynamic_image_parameters_offer_at_most_three(self):
        fields = build_image_param_fields("api", {}, "")
        count_field = next(field for field in fields if field.get("key") == "n")
        self.assertEqual(count_field["options"], [1, 2, 3])

    def test_canvas_frontends_use_shared_limit_constant(self):
        for relative_path in ("static/js/canvas.js", "static/js/smart-canvas.js"):
            with self.subTest(path=relative_path):
                with open(os.path.join(ROOT, relative_path), "r", encoding="utf-8") as handle:
                    source = handle.read()
                self.assertIn("const IMAGE_GENERATION_MAX = 3;", source)
                self.assertNotIn("Math.min(8, Number(node.count", source)
                self.assertNotIn("[1,2,3,4,5,6,7,8]", source)


if __name__ == "__main__":
    unittest.main()
