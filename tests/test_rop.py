"""Unit tests for triage_web.rop (ROPGadget, ROPEngine)."""

from __future__ import annotations

import triage_web.rop as rop_mod
from triage_web.loader import BinaryLoader
from triage_web.rop import ROPEngine, ROPGadget


def test_gadget_classification() -> None:
    g = ROPGadget(
        0x400000,
        [
            {"mnemonic": "pop", "op_str": "rdi"},
            {"mnemonic": "ret", "op_str": ""},
        ],
    )
    assert g.text == "pop rdi ; ret"
    assert "pop_rdi" in g.classes
    assert "ret" not in g.classes  # anchored ^ret$ doesn't match the whole gadget

    plain = ROPGadget(0x1, [{"mnemonic": "ret", "op_str": ""}])
    assert "ret" in plain.classes


def test_engine_scans_and_searches(crackme_path) -> None:
    ldr = BinaryLoader(str(crackme_path))
    try:
        rop = ROPEngine(ldr)
        count = rop.scan()
        assert count == len(rop.gadgets) > 0
        assert rop._scanned is True

        summary = rop.get_summary()
        assert summary["total"] == count
        assert isinstance(summary["classes"], dict)

        # semantic class filter + text query + a bad regex (swallowed)
        assert isinstance(rop.search(semantic_cls="ret"), list)
        rets = rop.search(query="ret")
        assert all("ret" in g["text"] for g in rets)
        assert rop.search(query="(unclosed") == rop.search(query="(unclosed")  # re.error -> no crash

        first = rop.search()[0]
        assert {"addr", "text", "classes"} <= first.keys()
    finally:
        ldr.close()


def test_scan_returns_zero_without_capstone(crackme_path, monkeypatch) -> None:
    monkeypatch.setattr(rop_mod, "HAS_CAPSTONE", False)
    ldr = BinaryLoader(str(crackme_path))
    try:
        assert ROPEngine(ldr).scan() == 0
    finally:
        ldr.close()


def test_scan_truncates_oversized_text_and_survives_disasm_errors(crackme_path, monkeypatch) -> None:
    monkeypatch.setattr(ROPEngine, "MAX_SCAN_BYTES", 100)  # < the 445-byte .text → force the code[:N] slice

    class _Boom:
        detail = True

        def disasm(self, *_a, **_k):
            raise ValueError("capstone blew up")

    ldr = BinaryLoader(str(crackme_path))
    try:
        rop = ROPEngine(ldr)
        monkeypatch.setattr(rop, "_get_md", lambda: _Boom())
        assert rop.scan() == 0  # every gadget attempt hit the except/continue
    finally:
        ldr.close()
