"""Thin pypandoc wrapper used by every pandoc-backed output format.

Returns pandoc output untouched. No cleanup, no entity-unescaping, no escape
stripping. Format-specific post-processing is the caller's job (see
libmagenta/dradis.py for the Dradis-flavored cleanup).
"""

import pypandoc

_INSTALL_HINT = (
    "pandoc is required for this output format but was not found on PATH.\n"
    "  macOS:  brew install pandoc\n"
    "  Debian: apt install pandoc\n"
    "  Fallback (bundles a private pandoc binary): pip install pypandoc-binary"
)


def convert_from_markdown(md_text, output_format, extra_args=None):
    """Convert GFM Markdown to the given pandoc output format.

    No post-processing is applied. Callers that want format-specific cleanup
    (escape stripping, entity decoding, HTML-table rewriting, etc.) must do
    that themselves.
    """
    try:
        pypandoc.get_pandoc_version()
    except Exception as exc:
        raise RuntimeError(_INSTALL_HINT) from exc
    args = ["--wrap=preserve"]
    if extra_args:
        args.extend(extra_args)
    return pypandoc.convert_text(md_text, output_format, format="gfm", extra_args=args)
