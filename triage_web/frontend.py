"""Single-page application frontend.

The whole UI — a Ghidra-style CTF binary analysis workbench — lives in the
sibling ``index.html`` and is served verbatim from the root endpoint.
``HTML_PAGE`` is read once at import.
"""

from pathlib import Path

HTML_PAGE: str = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
