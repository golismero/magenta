import unittest
from unittest.mock import patch

try:
    import pypandoc

    pypandoc.get_pandoc_version()
    PANDOC_AVAILABLE = True
except Exception:
    PANDOC_AVAILABLE = False

from libmagenta.pandoc import convert_from_markdown


@unittest.skipUnless(PANDOC_AVAILABLE, "pandoc not installed on this system")
class TestConvertFromMarkdown(unittest.TestCase):
    def test_basic_paragraph_to_textile(self):
        result = convert_from_markdown("Hello world.", "textile")
        self.assertIn("Hello world.", result)

    def test_gfm_table_to_textile_produces_nonempty_output(self):
        md = "| A | B |\n|---|---|\n| 1 | 2 |\n"
        result = convert_from_markdown(md, "textile")
        self.assertTrue(len(result) > 0)
        # Cell values should survive
        self.assertIn("1", result)
        self.assertIn("2", result)

    def test_code_fence_survives(self):
        md = "```\nprint('hi')\n```\n"
        result = convert_from_markdown(md, "textile")
        self.assertIn("print('hi')", result)

    def test_extra_args_actually_reach_pandoc(self):
        # --shift-heading-level-by=1 demotes h1 -> h2 in the output.
        # If our wrapper passes extra_args through, the result will use h2
        # instead of h1.
        md = "# A heading\n"
        result_default = convert_from_markdown(md, "textile")
        result_with_args = convert_from_markdown(
            md, "textile", extra_args=["--shift-heading-level-by=1"]
        )
        self.assertIn("h1", result_default)  # default keeps it at h1
        self.assertIn("h2", result_with_args)  # extra_args demoted it


class TestConvertFromMarkdownWithoutPandoc(unittest.TestCase):
    def test_missing_pandoc_raises_runtime_error_with_install_hint(self):
        with patch(
            "libmagenta.pandoc.pypandoc.get_pandoc_version",
            side_effect=OSError("pandoc not found"),
        ), self.assertRaises(RuntimeError) as ctx:
            convert_from_markdown("hello", "textile")
        msg = str(ctx.exception)
        self.assertIn("pandoc", msg.lower())
        self.assertIn("brew", msg)  # macOS install hint
        self.assertIn("apt", msg)  # Debian install hint

    def test_runtime_error_chains_original_exception(self):
        # The wrapper uses `raise RuntimeError(...) from exc` — verify the chain.
        original = OSError("nope")
        with patch(
            "libmagenta.pandoc.pypandoc.get_pandoc_version", side_effect=original
        ):
            try:
                convert_from_markdown("hi", "textile")
            except RuntimeError as exc:
                self.assertIs(exc.__cause__, original)
                return
        self.fail("expected RuntimeError")
