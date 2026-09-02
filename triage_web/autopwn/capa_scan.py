"""Best-effort capa capability extraction for the auto-solver.

``capabilities(path)`` runs flare-capa against a binary and returns the set
of matched rule names and namespaces (lowercased). The strategy registry
uses those to reprioritise the plan — e.g. an ``anti-analysis`` /
``self-modifying`` match promotes the SMC unwrap, an ``arithmetic`` /
``checksum`` match promotes z3.

It is deliberately forgiving: capa not installed, rules missing, or the
analysis blowing up all just yield an empty set so the solve still runs on
the disassembly-only signals.

The vivisect analysis capa needs is slow (tens of seconds on a large
binary), so results are cached — in process and on disk under
``~/.triage/capa-cache/`` — keyed by the file's path, size and mtime. Pass
``on_start`` to be told when a real (uncached) scan is about to begin, e.g.
to stream a "capa running" progress event.

(The ``/api/capa`` route does its own, more detailed extraction for display;
the rule-dir discovery is intentionally the same list.)
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
from collections.abc import Callable

_MEM: dict[str, frozenset[str]] = {}
_CACHE_DIR = pathlib.Path(os.path.expanduser("~")) / ".triage" / "capa-cache"


def _cache_key(path: str) -> str | None:
    try:
        st = os.stat(path)
    except OSError:  # pragma: no cover - caller already validated the path
        return None
    raw = f"{os.path.abspath(path)}|{st.st_size}|{st.st_mtime_ns}"
    return hashlib.sha1(raw.encode()).hexdigest()  # noqa: S324 - cache key, not security


def _disk_load(key: str) -> frozenset[str] | None:
    try:
        data = json.loads((_CACHE_DIR / f"{key}.json").read_text(encoding="utf-8"))
        return frozenset(data["caps"])
    except (OSError, ValueError, KeyError):
        return None


def _disk_store(key: str, path: str, caps: frozenset[str]) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (_CACHE_DIR / f"{key}.json").write_text(
            json.dumps({"path": path, "caps": sorted(caps), "ts": round(time.time(), 1)}),
            encoding="utf-8",
        )
    except OSError:  # pragma: no cover - cache is best-effort
        pass


def _rules_dir() -> pathlib.Path | None:
    try:
        import capa.main
    except ImportError:  # pragma: no cover - capa is an optional extra
        return None
    repo_root = pathlib.Path(__file__).resolve().parent.parent.parent
    capa_root = pathlib.Path(capa.main.get_default_root())
    env_rules = os.environ.get("TRIAGE_CAPA_RULES")
    candidates = [
        pathlib.Path(env_rules) if env_rules else None,
        repo_root / "capa-rules",
        capa_root / "rules",
        capa_root.parent / "rules",
        pathlib.Path("/usr/share/capa/rules"),
        pathlib.Path(os.path.expanduser("~/.capa/rules")),
    ]
    return next((p for p in candidates if p and p.is_dir() and next(p.rglob("*.yml"), None)), None)


def _extract(path: str) -> frozenset[str]:
    try:
        import capa.capabilities.common
        import capa.loader as cloader
        import capa.main
        import capa.rules
    except ImportError:  # pragma: no cover - capa is an optional extra
        return frozenset()

    rules_dir = _rules_dir()
    if rules_dir is None:  # pragma: no cover - depends on the host
        return frozenset()

    try:
        rules = capa.rules.get_rules([rules_dir])
        sigpaths = capa.main.get_default_signatures()
        extractor = cloader.get_extractor(pathlib.Path(path), "auto", "auto", "vivisect", sigpaths)
        result = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)
        matches = result.matches if hasattr(result, "matches") else result
    except Exception:  # pragma: no cover - vivisect/capa internals, format quirks
        return frozenset()

    out: set[str] = set()
    for rule_name, hits in matches.items():
        out.add(str(rule_name).lower())
        ns = ""
        if hasattr(hits, "__iter__") and not isinstance(hits, dict):
            ns = getattr(next(iter(hits), None), "namespace", "")
        if ns:
            out.add(str(ns).lower())
    return frozenset(out)


def capabilities(path: str, *, on_start: Callable[[], None] | None = None) -> frozenset[str]:
    """Matched capa rule names + namespaces for ``path``, lowercased. Empty on
    any failure. Cached by (path, size, mtime); ``on_start`` fires only when a
    real scan is about to run (never on a cache hit)."""
    key = _cache_key(path)
    if key is not None:
        if key in _MEM:
            return _MEM[key]
        disk = _disk_load(key)
        if disk is not None:
            _MEM[key] = disk
            return disk

    if on_start is not None:
        on_start()
    caps = _extract(path)

    if key is not None:
        _MEM[key] = caps
        _disk_store(key, path, caps)
    return caps
