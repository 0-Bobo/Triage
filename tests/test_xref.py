"""Unit tests for triage_web.xref (XRefDB, BasicBlock)."""

from __future__ import annotations

from triage_web.xref import BasicBlock, XRefDB


def test_add_is_bidirectional_and_deduped() -> None:
    db = XRefDB()
    db.add(0x1000, 0x2000, "call")
    db.add(0x1000, 0x2000, "call")  # duplicate -> ignored

    assert db.get_callers(0x2000) == [(0x1000, "call")]
    assert db.get_callees(0x1000) == [(0x2000, "call")]


def test_unknown_address_returns_empty_list() -> None:
    db = XRefDB()
    assert db.get_callers(0xDEAD) == []
    assert db.get_callees(0xBEEF) == []


def test_build_from_insns_classifies_call_vs_jump() -> None:
    db = XRefDB()
    db.build_from_insns(
        [
            {"address": 0x400100, "mnemonic": "call", "op_str": "0x400500"},
            {"address": 0x400105, "mnemonic": "jne", "op_str": "0x400080"},
            {"address": 0x40010A, "mnemonic": "mov", "op_str": "eax, 1"},  # ignored
            {"address": 0x40010D, "mnemonic": "call", "op_str": "rax"},  # non-hex -> skipped
        ]
    )

    assert db.get_callers(0x400500) == [(0x400100, "call")]
    assert db.get_callers(0x400080) == [(0x400105, "jump")]
    assert db.get_callees(0x40010D) == []


def test_basic_block_defaults() -> None:
    bb = BasicBlock(0x401000)
    assert bb.addr == 0x401000
    assert bb.instructions == [] and bb.successors == [] and bb.predecessors == []
    assert bb.x == bb.y == bb.width == bb.height == 0
