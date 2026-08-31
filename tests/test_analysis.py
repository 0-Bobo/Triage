"""Unit tests for triage_web.analysis — the binary-analysis / exploit-intel
helpers, exercised directly against the sample ELF (no HTTP)."""

from __future__ import annotations

import pytest

from triage_web import analysis
from triage_web.engine import Disassembler
from triage_web.loader import BinaryLoader


def test_build_known_calls_resolves_local_symbols(loader: BinaryLoader) -> None:
    known = analysis.build_known_calls(loader)
    assert "main" in set(known.values())
    assert all(isinstance(k, int) for k in known)


def test_section_for_offset(loader: BinaryLoader) -> None:
    # offset 0 is the ELF header — not inside any section
    assert analysis.section_for_offset(loader, 0) == ("", None)

    text = next(s for s in loader.get_sections() if s["name"] == ".text")
    name, vaddr = analysis.section_for_offset(loader, text["offset"] + 4)
    assert name == ".text"
    assert vaddr == text["vaddr"] + 4


def test_build_string_map_returns_a_dict(loader: BinaryLoader) -> None:
    rodata = next((s for s in loader.get_sections() if s["name"] == ".rodata"), None)
    if rodata is None or rodata["size"] == 0:
        pytest.skip("sample has no .rodata")
    insn = {"op_str": f"eax, {hex(rodata['vaddr'])}"}
    assert isinstance(analysis.build_string_map(loader, [insn]), dict)


def test_code_example_falls_back() -> None:
    assert analysis.code_example("gets") == "gets(buf)"
    assert analysis.code_example("totally_unknown") == "totally_unknown(...)"


class _FakeLoader:
    """Minimal loader stand-in for the pure-function edge cases."""

    def __init__(self, sections=(), raw=b"", reads=None):
        self._sections = list(sections)
        self._raw = raw
        self._reads = reads or {}

    def get_sections(self):
        return self._sections

    def read_vaddr(self, addr, size):
        return self._reads.get(addr, b"")


def test_build_string_map_edge_cases() -> None:
    # no .rodata section -> {}
    assert analysis.build_string_map(_FakeLoader(sections=[]), [{"op_str": "eax, 0x1"}]) == {}

    rodata = {"name": ".rodata", "vaddr": 0x2000, "size": 0x100, "offset": 0x1000}
    ldr = _FakeLoader(sections=[rodata], reads={0x2000: b"hello\x00world"})
    smap = analysis.build_string_map(
        ldr,
        [
            {"op_str": "eax, notahex"},  # not 0x-prefixed -> skipped
            {"op_str": "eax, 0xZZ"},  # ValueError on int() -> skipped
            {"op_str": "eax, 0x9999"},  # outside [start, end) -> skipped
            {"op_str": "eax, 0x2000, 0x2000"},  # dup on second token -> seen
            {"op_str": "ecx, 0x2050"},  # in range but read_vaddr returns b"" -> skipped
        ],
    )
    assert smap == {0x2000: "'hello'"}


def test_find_win_functions_matches_names() -> None:
    class FakeLoader:
        def get_functions(self):
            return [("main", 0x1000), ("give_shell", 0x1200), ("helper", 0x1300)]

    hits = analysis.find_win_functions(FakeLoader())
    assert [h["name"] for h in hits] == ["give_shell"]
    assert hits[0]["address"] == "0x1200"


def test_scan_gadgets_tolerates_missing_engine() -> None:
    assert analysis.scan_gadgets(None) == {}


def test_find_binsh_variants() -> None:
    # needle present but in no section -> vaddr ""
    ldr = _FakeLoader(sections=[], raw=b"....../bin/sh\x00......")
    got = analysis.find_binsh(ldr)
    assert got["string"] == "/bin/sh" and got["vaddr"] == ""

    # needle present and inside a section -> resolved vaddr
    sec = {"name": ".rodata", "vaddr": 0x4000, "size": 0x100, "offset": 0x0}
    ldr2 = _FakeLoader(sections=[sec], raw=b"/bin/sh\x00")
    assert analysis.find_binsh(ldr2)["vaddr"] == "0x4000"

    # no needle at all -> None
    assert analysis.find_binsh(_FakeLoader(raw=b"nothing here")) is None


def test_overflow_sites_skips_functions_that_fail_to_analyse() -> None:
    class BadDisasm:
        def analyze_function(self, *_a, **_k):
            raise ValueError("bad bytes")

    class Ldr(_FakeLoader):
        def get_functions(self):
            return [("f", 0x1000), ("_end", 0x1400)]

        def read_vaddr(self, addr, size):
            return b"\x90" * size

    assert analysis.overflow_sites(Ldr(), BadDisasm(), {}, is64=True) == []


def test_win_functions_and_overflow_sites_on_a_real_binary(crackme_path) -> None:
    ldr = BinaryLoader(str(crackme_path))
    try:
        assert [w["name"] for w in analysis.find_win_functions(ldr)] == ["win"]

        d = Disassembler(ldr.arch, ldr.bits)
        sites = analysis.overflow_sites(ldr, d, analysis.build_known_calls(ldr), is64=True)
        # main() calls strcpy(buf, argv[1]) — an unbounded write
        assert any(s["function"] == "main" and "strcpy" in s["unsafe_calls"] for s in sites)
    finally:
        ldr.close()


def test_overflow_sites_flags_a_gets_caller() -> None:
    disasm = Disassembler()

    class FakeLoader:
        def get_functions(self):
            return [("vuln", 0x1000), ("_end", 0x1400)]

        def read_vaddr(self, addr, size):
            # only the vulnerable function has bytes to analyse
            return b"\x90" * size if addr == 0x1000 else b""

    disasm.analyze_function = lambda *a, **k: {
        "calls": [{"name": "gets@GLIBC_2.0"}],
        "stack_frame": 0x40,
        "stack_vars": [{"offset": -0x30, "used_by_funcs": ["gets@GLIBC_2.0"]}],
    }

    sites = analysis.overflow_sites(FakeLoader(), disasm, {}, is64=True)
    assert len(sites) == 1
    site = sites[0]
    assert site["function"] == "vuln"
    assert site["unsafe_calls"] == ["gets"]
    assert site["est_offset_to_ret"] == 0x30 + 8  # buffer offset + word


@pytest.mark.parametrize("kind", ["ret2win", "ret2libc", "syscall_rop", "shellcode", "fmt", "heap"])
def test_pwntools_skeleton_is_valid_python(kind: str) -> None:
    src = analysis.pwntools_skeleton(kind, {"filename": "chall", "offset": 72, "win": "win", "binsh": "0x40"})
    assert src.startswith("from pwn import *")
    compile(src, f"<skeleton:{kind}>", "exec")  # must be syntactically valid


def test_pwntools_skeleton_unknown_kind_is_empty() -> None:
    assert analysis.pwntools_skeleton("nope", {}) == ""
