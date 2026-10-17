"""Unit tests for triage_web.loader.BinaryLoader against the sample ELF."""

from __future__ import annotations

import math

import pytest

from triage_web.loader import BinaryLoader


def test_identifies_the_elf(loader: BinaryLoader) -> None:
    info = loader.get_info()
    assert info["format"] == "ELF"
    assert info["arch"] in ("x86", "x86_64")
    assert info["bits"] in (32, 64)
    assert info["entry_point"].startswith("0x")
    assert set(info["hashes"]) == {"MD5", "SHA1", "SHA256"}
    assert len(info["hashes"]["SHA256"]) == 64


def test_hashes_are_stable_and_cached(loader: BinaryLoader) -> None:
    first = loader.hashes()
    assert first == loader.hashes()  # exercises the cache path
    assert set(first) == {"MD5", "SHA1", "SHA256"}


def test_sections_and_functions_present(loader: BinaryLoader) -> None:
    names = {s["name"] for s in loader.get_sections()}
    assert ".text" in names

    funcs = dict(loader.get_functions())
    assert "main" in funcs
    assert all(isinstance(a, int) for a in funcs.values())


def test_protections_report_all_mitigations(loader: BinaryLoader) -> None:
    prot = loader.protections()
    for key in ("NX (No-Execute)", "PIE (ASLR)", "Stack Canary", "RELRO"):
        assert key in prot


def test_vaddr_offset_round_trip(loader: BinaryLoader) -> None:
    text = next(s for s in loader.get_sections() if s["name"] == ".text")
    assert loader.vaddr_to_offset(text["vaddr"]) == text["offset"]
    assert loader.vaddr_to_offset(0xDEAD_BEEF) == -1  # nothing mapped there


def test_read_helpers_clamp_and_bound(loader: BinaryLoader) -> None:
    assert loader.read_offset(0, 4) == b"\x7fELF"
    assert loader.read_offset(10**9, 16) == b""
    big = loader.read_offset(0, 10**9)  # clamped to EOF, not rejected
    assert 0 < len(big) == loader.file_size


def test_read_offset_rejects_non_positive_size(loader: BinaryLoader) -> None:
    """A negative size must not exploit Python's negative-slice-stop semantics."""
    assert loader.read_offset(10, -1000) == b""
    assert loader.read_offset(10, 0) == b""


def test_read_vaddr_rejects_non_positive_size(loader: BinaryLoader) -> None:
    text = next(s for s in loader.get_sections() if s["name"] == ".text")
    assert loader.read_vaddr(text["vaddr"], -1000) == b""
    assert loader.read_vaddr(text["vaddr"], 0) == b""
    assert len(loader.read_vaddr(text["vaddr"], 16)) == 16  # positive size still works


def test_compute_entropy_bounds() -> None:
    assert BinaryLoader.compute_entropy(b"") == 0.0
    assert BinaryLoader.compute_entropy(b"\x00" * 256) == pytest.approx(0.0)
    assert BinaryLoader.compute_entropy(bytes(range(256))) == pytest.approx(8.0, abs=1e-6)
    assert 0.0 <= BinaryLoader.compute_entropy(b"hello world") <= 8.0
    assert not math.isnan(BinaryLoader.compute_entropy(b"abc"))


def test_compute_entropy_matches_the_reference_per_byte_definition() -> None:
    """Guards the Counter-based frequency count against the original per-byte loop."""

    def reference_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum(p * math.log2(p) for f in freq if (p := f / n) > 0)

    for block in (b"aaabbbccd", b"\xff\x00\xff\x00\x01", bytes(range(256)) * 3, b"x"):
        assert BinaryLoader.compute_entropy(block) == pytest.approx(reference_entropy(block))


def test_detect_crypto_and_packer_run(loader: BinaryLoader) -> None:
    assert isinstance(loader.detect_crypto(), list)
    assert isinstance(loader.detect_packer(), list)


def test_detect_crypto_and_packer_cache_and_reset_on_clear(loader: BinaryLoader) -> None:
    first_crypto = loader.detect_crypto()
    assert loader.detect_crypto() is first_crypto  # cached, same object returned

    first_packer = loader.detect_packer()
    assert loader.detect_packer() is first_packer

    loader._clear_caches()
    assert loader.detect_crypto() is not first_crypto  # cache-clear forces recompute
    assert loader.detect_packer() is not first_packer


def test_strings_fallback_finds_ascii(loader: BinaryLoader) -> None:
    strings = loader.get_strings(min_len=4)
    assert isinstance(strings, list) and strings
    assert all(len(s) >= 4 for s in strings)


def test_get_strings_is_cached_and_reset_by_clear_caches(loader: BinaryLoader) -> None:
    """A second call must not re-scan; only the cache-clear path forces a re-scan."""
    first = loader.get_strings(min_len=4)
    assert loader.get_strings(min_len=4) is first  # served from the cache, same object

    loader._clear_caches()
    second = loader.get_strings(min_len=4)
    assert second is not first  # cache was reset, so this is a fresh scan
    assert second == first  # but the scan result is unchanged


def test_get_strings_filters_the_cached_scan_for_a_larger_min_len(loader: BinaryLoader) -> None:
    baseline = loader.get_strings(min_len=4)
    filtered = loader.get_strings(min_len=6)
    assert all(len(s) >= 6 for s in filtered)
    assert set(filtered) <= set(baseline)


# ── PE format branch ───────────────────────────────────────────────────


def test_pe_is_identified_and_parsed(pe_path) -> None:
    pe = BinaryLoader(str(pe_path))
    try:
        info = pe.get_info()
        assert info["format"] == "PE"
        assert info["bits"] == 64

        names = {s["name"] for s in pe.get_sections()}
        assert ".text" in names

        imports = {i["name"] for i in pe.get_imports()}
        assert any(i in imports for i in ("GetProcAddress", "LoadLibraryA"))

        prot = pe.protections()
        assert prot["NX (No-Execute)"] == "Enabled"
        assert prot["PIE (ASLR)"] == "Enabled"

        assert isinstance(pe.get_exports(), list)
        assert isinstance(pe.get_symbols(), list)
        funcs = pe.get_functions()
        assert funcs and all(isinstance(a, int) for _, a in funcs)
        code, base = pe._get_text_section()
        assert code and base > 0

        text = next(s for s in pe.get_sections() if s["name"] == ".text")
        assert pe.vaddr_to_offset(text["vaddr"]) >= 0
        assert len(pe.read_vaddr(text["vaddr"], 16)) == 16
    finally:
        pe.close()


def test_pe_vaddr_offset_stops_at_virtual_size(pe_path) -> None:
    """FileAlignment padding routinely makes a PE section's raw-on-disk size
    bigger than its VirtualSize (e.g. ``.data`` here: VirtualSize 0xc0 padded
    out to a SizeOfRawData of 0x200). A vaddr past VirtualSize but still
    inside SizeOfRawData must resolve as unmapped, not into that padding /
    the next section's raw bytes — matching what get_sections() reports as
    the section's actual size."""
    pe = BinaryLoader(str(pe_path))
    try:
        padded = next(s for s in pe._pe.sections if s.SizeOfRawData > s.Misc_VirtualSize > 0)
        base = pe._pe.OPTIONAL_HEADER.ImageBase
        sv = padded.VirtualAddress + base
        in_padding = sv + padded.Misc_VirtualSize + 1  # past VirtualSize, still < SizeOfRawData
        assert in_padding < sv + padded.SizeOfRawData
        assert pe.vaddr_to_offset(in_padding) == -1
        assert pe.read_vaddr(in_padding, 16) == b""
    finally:
        pe.close()


def test_pe_import_export_fallback_without_lief(pe_path) -> None:
    """With lief unavailable the pefile DIRECTORY_ENTRY_* paths take over."""
    pe = BinaryLoader(str(pe_path))
    try:
        pe._lief_bin = None
        pe._import_cache = pe._export_cache = pe._func_cache = None
        imports = {i["name"] for i in pe.get_imports()}
        assert any(i in imports for i in ("GetProcAddress", "LoadLibraryA"))
        assert isinstance(pe.get_exports(), list)
        assert pe.get_functions()
    finally:
        pe.close()


def test_crypto_and_packer_signatures_are_found_in_raw_bytes(tmp_path) -> None:
    """detect_crypto / detect_packer scan the raw image for known constants."""
    from triage_web.knowledge import CRYPTO_SIGNATURES

    aes_sbox = CRYPTO_SIGNATURES["AES S-box"]
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\x00" * 64 + aes_sbox + b"....._MEIPASS....pyi-")

    ldr = BinaryLoader(str(blob))
    try:
        crypto = dict(ldr.detect_crypto())
        assert "AES S-box" in crypto
        assert "PyInstaller" in ldr.detect_packer()
    finally:
        ldr.close()


def test_scan_for_functions_without_capstone(loader, monkeypatch) -> None:
    import triage_web.loader as loader_mod

    monkeypatch.setattr(loader_mod, "HAS_CAPSTONE", False)
    assert loader._scan_for_functions() == []


def test_crackme_has_real_symbols(crackme_path) -> None:
    ldr = BinaryLoader(str(crackme_path))
    try:
        funcs = dict(ldr.get_functions())
        assert {"main", "check", "win"} <= funcs.keys()
        assert ldr.protections()["Stack Canary"] == "Disabled"
    finally:
        ldr.close()


# ── protections() across the crafted fixtures ─────────────────────────


@pytest.mark.parametrize(
    ("sample", "key", "expected"),
    [
        ("vuln_rwx", "RWX Segments", "YES — shellcode possible"),
        ("vuln_canary", "Stack Canary", "Enabled"),
        ("vuln_fortify", "Fortify Source", "Enabled"),
        ("vuln_pie", "RELRO", "Full"),  # DF_BIND_NOW flag → Full, not Partial
        ("vuln_pie", "PIE (ASLR)", "Enabled"),
        ("vuln_execstack", "NX (No-Execute)", "Disabled"),
    ],
)
def test_protections_on_crafted_fixtures(vuln_samples, sample, key, expected) -> None:
    ldr = BinaryLoader(str(vuln_samples[sample]))
    try:
        assert ldr.protections()[key] == expected
    finally:
        ldr.close()


def test_partial_relro_when_lazy_binding(crackme_path) -> None:
    """RELRO present but lazy binding → 'Partial' (the `else` of the ternary)."""
    ldr = BinaryLoader(str(crackme_path))
    try:
        assert ldr.protections()["RELRO"] == "Partial"
    finally:
        ldr.close()


def test_protections_reads_the_legacy_bind_now_tag(crackme_path, monkeypatch) -> None:
    """Old toolchains emit a bare DT_BIND_NOW dynamic entry (no DT_FLAGS)."""
    ldr = BinaryLoader(str(crackme_path))
    try:
        real_sections = list(ldr._elf.iter_sections())

        class _Tag:
            entry = type("E", (), {"d_tag": "DT_BIND_NOW", "d_val": 0})()

        class _Dyn:
            def iter_tags(self):
                return [_Tag()]

        monkeypatch.setattr(ldr._elf, "iter_sections", lambda: [*real_sections, _Dyn()])
        assert ldr.protections()["RELRO"] == "Full"  # has_relro + legacy bind-now
    finally:
        ldr.close()


def test_get_imports_address_matches_the_stub_text_actually_calls(crackme_path) -> None:
    """On a CET/IBT binary (the toolchain default here), .text calls the
    .plt.sec stub, never the .plt entry - get_imports()'s address must be
    the one real call sites target, or every address-keyed PLT map built
    on top of it (autopwn's route/emulate strategies) silently never matches."""
    from triage_web.engine import Disassembler

    ldr = BinaryLoader(str(crackme_path))
    try:
        sections = {s["name"]: s for s in ldr.get_sections()}
        plt_sec = sections.get(".plt.sec")
        if plt_sec is None:
            pytest.skip("fixture has no .plt.sec on this toolchain")
        code, base = ldr._get_text_section()
        call_targets = set()
        for insn in Disassembler().disassemble(bytes(code), base):
            if insn["mnemonic"] == "call":
                try:
                    call_targets.add(int(insn["op_str"], 16))
                except ValueError:
                    pass
        imports = [i for i in ldr.get_imports() if i["address"]]
        assert imports
        assert any(i["address"] in call_targets for i in imports)
        assert all(plt_sec["vaddr"] <= i["address"] < plt_sec["vaddr"] + plt_sec["size"] for i in imports)
    finally:
        ldr.close()


def test_lief_import_library_attribute_error_is_swallowed(crackme_path, monkeypatch) -> None:
    ldr = BinaryLoader(str(crackme_path))
    try:

        class _Func:
            name = "puts"

            @property
            def library(self):
                raise RuntimeError("lief has no library info here")

        class _Lief:
            sections = []
            imported_functions = [_Func()]

        ldr._lief_bin = _Lief()
        ldr._import_cache = None
        names = {i["name"] for i in ldr.get_imports()}
        assert "puts" in names  # still recorded, with library=""
    finally:
        ldr.close()


# ── parse / close error handling ─────────────────────────────────────


def test_lief_parse_failure_is_non_fatal(crackme_path, monkeypatch) -> None:
    import triage_web.loader as m

    monkeypatch.setattr(m.lief, "parse", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("lief boom")))
    ldr = BinaryLoader(str(crackme_path))  # pyelftools still carries it
    try:
        assert ldr.get_info()["format"] == "ELF"
        assert ldr._lief_bin is None
    finally:
        ldr.close()


def test_pyelftools_parse_failure_is_non_fatal(crackme_path, monkeypatch) -> None:
    import triage_web.loader as m

    monkeypatch.setattr(m, "ELFFile", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("elf boom")))
    ldr = BinaryLoader(str(crackme_path))
    try:
        assert ldr._elf is None  # swallowed; loader still constructed
    finally:
        ldr.close()


def test_pefile_parse_failure_is_non_fatal(pe_path, monkeypatch) -> None:
    import triage_web.loader as m

    monkeypatch.setattr(m.pefile, "PE", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("pe boom")))
    ldr = BinaryLoader(str(pe_path))
    try:
        assert ldr._pe is None
    finally:
        ldr.close()


def test_pefile_close_failure_is_swallowed(pe_path, monkeypatch) -> None:
    ldr = BinaryLoader(str(pe_path))
    monkeypatch.setattr(ldr._pe, "close", lambda: (_ for _ in ()).throw(OSError("mmap stuck")))
    ldr.close()  # must not raise
    assert ldr._pe is None


# ── strings: subprocess success + total fallback failure ─────────────


def test_get_strings_uses_the_strings_binary_when_present(loader, monkeypatch) -> None:
    import subprocess

    import triage_web.loader as m

    class _R:
        returncode = 0
        stdout = "alpha\nbravo\ncharlie\n"

    monkeypatch.setattr(m.subprocess, "run", lambda *_a, **_k: _R())
    assert loader.get_strings(min_len=3) == ["alpha", "bravo", "charlie"]
    assert subprocess  # imported for the patch target's sake


def test_get_strings_returns_empty_when_every_path_fails(loader, monkeypatch) -> None:
    import re as _re

    import triage_web.loader as m

    monkeypatch.setattr(m.subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(OSError("no strings")))
    monkeypatch.setattr(m.re, "finditer", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("regex boom")))
    assert loader.get_strings() == []
    assert _re  # keep the import


# ── import/function paths without LIEF, and text-section fallbacks ────


def test_elf_imports_via_pyelftools_when_lief_absent(crackme_path) -> None:
    ldr = BinaryLoader(str(crackme_path))
    try:
        ldr._lief_bin = None
        ldr._import_cache = None
        names = {i["name"] for i in ldr.get_imports()}
        assert any(n.startswith("puts") or n.startswith("strcpy") for n in names)
    finally:
        ldr.close()


def test_get_text_section_falls_back_to_pt_load_without_section_headers(vuln_samples) -> None:
    """`nosections` has no section table → the PT_LOAD exec-segment branch."""
    ldr = BinaryLoader(str(vuln_samples["nosections"]))
    try:
        code, base = ldr._get_text_section()
        assert code and base > 0
    finally:
        ldr.close()


def test_get_text_section_raw_blob_fallback(tmp_path) -> None:
    blob = tmp_path / "raw.bin"
    blob.write_bytes(b"\x90" * 128)
    ldr = BinaryLoader(str(blob))
    try:
        code, base = ldr._get_text_section()
        assert base == 0 and len(code) == 128  # the bytes(self._raw), 0 fallback
    finally:
        ldr.close()


def test_scan_for_functions_returns_empty_for_empty_text(loader, monkeypatch) -> None:
    monkeypatch.setattr(loader, "_get_text_section", lambda: (b"", 0))
    assert loader._scan_for_functions() == []


def test_scan_for_functions_swallows_disasm_and_bad_call_targets(loader, monkeypatch) -> None:
    import triage_web.loader as m

    # no prologue bytes → the pattern scan finds nothing; disasm does the rest
    monkeypatch.setattr(loader, "_get_text_section", lambda: (b"\xcc" * 32, 0x1000))

    class _Insn:
        mnemonic = "call"
        op_str = "rax"  # not hex → the inner `except` at the call-target parse

    class _MD:
        def disasm(self, *_a, **_k):
            return [_Insn()]

    monkeypatch.setattr(m, "Cs", lambda *_a, **_k: _MD())
    assert loader._scan_for_functions() == []  # bad target ignored, no crash

    class _Boom:
        def disasm(self, *_a, **_k):
            raise ValueError("capstone gave up")

    monkeypatch.setattr(m, "Cs", lambda *_a, **_k: _Boom())
    assert loader._scan_for_functions() == []  # outer `except` swallows it


def test_entry_point_is_appended_for_a_stripped_binary(vuln_samples) -> None:
    """A stripped ELF yields few named funcs → the entry point is added."""
    ldr = BinaryLoader(str(vuln_samples["nostrings_stripped"]))
    try:
        funcs = dict(ldr.get_functions())
        assert "entry" in funcs
        assert funcs["entry"] == ldr.entry_point
    finally:
        ldr.close()


def test_pe_export_directory_paths(pe_path, monkeypatch) -> None:
    """Attach a synthetic export directory so the pefile export branches run."""
    ldr = BinaryLoader(str(pe_path))
    try:
        ldr._lief_bin = None
        ldr._export_cache = ldr._func_cache = None

        class _Sym:
            def __init__(self, name, addr, ordinal):
                self.name = name
                self.address = addr
                self.ordinal = ordinal

        class _Dir:
            symbols = [_Sym(b"DoThing", 0x1234, 1), _Sym(None, 0x5678, 7)]

        monkeypatch.setattr(ldr._pe, "DIRECTORY_ENTRY_EXPORT", _Dir(), raising=False)
        exps = {e["name"] for e in ldr.get_exports()}
        assert "DoThing" in exps
        assert any(e["name"] == "DoThing" for e in [{"name": n} for n, _ in ldr.get_functions()])
    finally:
        ldr.close()
