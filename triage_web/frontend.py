"""Single-page application frontend.

The whole UI — a Ghidra-style CTF binary analysis workbench — lives in the
sibling ``index.html`` (markup/JS) and ``style.css`` (styles), both served
verbatim as static content with no build step. ``HTML_PAGE``/``CSS_PAGE``
are read once at import.
"""

from pathlib import Path

HTML_PAGE: str = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
CSS_PAGE: str = (Path(__file__).parent / "style.css").read_text(encoding="utf-8")
