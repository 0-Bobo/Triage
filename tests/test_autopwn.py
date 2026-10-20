"""Tests for the automated CTF solver (``triage_web.autopwn``).

The strategy fixtures (``samples/memflag`` etc.) are tiny x86-64 ELFs built
by ``samples/src/build.sh``. Emulation runs everywhere (unicorn); angr and
the concrete ret2win run wherever a Linux process can be spawned (CI is
Linux; on Windows the runner bridges to WSL).
"""

from __future__ import annotations

import json
import platform
import re
import shlex

import pytest
from fastapi.testclient import TestClient

from triage_web import server
from triage_web.autopwn import recon, solve
from triage_web.autopwn.classify import classify
from triage_web.autopwn.runner import ProcResult, extract_flags, have_wsl, target_kind, to_wsl

_CAN_RUN_ELF = have_wsl() or platform.system() == "Linux"


# ── runner ───────────────────────────────────────────────────────────


def test_to_wsl_translates_and_passes_through():
    assert to_wsl(r"C:\code\demo\x") == "/mnt/c/code/demo/x"
    assert to_wsl("/already/posix") == "/already/posix"


def test_target_kind_from_magic(autopwn_samples, tmp_path):
    assert target_kind(autopwn_samples["memflag"]) == "elf"
    junk = tmp_path / "j.bin"
    junk.write_bytes(b"not a binary")
    assert target_kind(junk) == "unknown"
    assert target_kind(tmp_path / "missing") == "unknown"


@pytest.mark.parametrize(
    ("blob", "want"),
    [
        (b"here is flag{abc_123}!", "flag{abc_123}"),
        (b"FLAG-4092849uio2jfklsj4kl\n", "FLAG-4092849uio2jfklsj4kl"),
        (b"picoCTF{s0lved}", "picoCTF{s0lved}"),
        (b"nothing here", None),
    ],
)
def test_extract_flags(blob, want):
    got = extract_flags(blob)
    assert (got[0] if got else None) == want


def test_extract_flags_honours_a_custom_pattern():
    assert extract_flags(b"ACME-SECRET-9", r"ACME-[A-Z0-9-]+")[0] == "ACME-SECRET-9"


def test_procresult_helpers():
    r = ProcResult(0, b"out", b"err", False, 0.1, "cmd", flags=["flag{x}"])
    assert r.best_flag() == "flag{x}"
    assert "out" in r.text and "err" in r.text
    assert ProcResult(0, b"", b"", False, 0.0, "").best_flag() is None


# ── classifier ───────────────────────────────────────────────────────


def test_classify_memflag_prefers_emulation(autopwn_samples):
    plans = classify(str(autopwn_samples["memflag"]))
    assert plans[0].name == "emulate"
    assert {p.name for p in plans} <= {"emulate", "angr", "ret2win", "format_string"}


def test_classify_ret2win_target_lists_ret2win(autopwn_samples):
    names = [p.name for p in classify(str(autopwn_samples["ret2win"]))]
    assert "ret2win" in names


def test_classify_password_checker_lists_angr(autopwn_samples):
    names = [p.name for p in classify(str(autopwn_samples["keycheck"]))]
    assert "angr" in names


def test_classify_lists_format_string_for_a_printf_user(vuln_samples):
    # vuln_pie: strcpy + printf(buf) + win() + system  → all four leads
    names = [p.name for p in classify(str(vuln_samples["vuln_pie"]))]
    assert {"format_string", "ret2win"} <= set(names)


def test_classify_leads_with_smc_for_a_writable_executable_segment(vuln_samples):
    # vuln_rwx has one RWX PT_LOAD — the self-modifying-code shape
    plans = classify(str(vuln_samples["vuln_rwx"]))
    assert plans[0].name == "smc" and plans[0].score == 90


def _view(**over):
    from triage_web.autopwn.registry import StaticView

    base = {
        "path": "x",
        "fmt": "ELF",
        "arch": "x86_64",
        "bits": 64,
        "imports": frozenset(),
        "func_names": frozenset(),
        "strings_lc": "",
        "wins": (),
        "smc_reason": None,
    }
    return StaticView(**{**base, **over})


def test_registry_capa_capabilities_reprioritise_strategies():
    from triage_web.autopwn.registry import _score_smc, _score_z3, plan

    # capa unpacking hint promotes SMC even with a clean header + no RWE segment
    v = _view(capa=frozenset({"executable/pe/section/unpacked", "self-modifying code"}))
    assert _score_smc(v) == (62, _score_smc(v)[1])
    assert any("capa" in s.why for s in plan(v) if s.name == "smc")

    # capa arithmetic/checksum hint gives z3 a strong score when input is read
    v2 = _view(imports=frozenset({"fgets"}), capa=frozenset({"hash data using crc32"}))
    assert _score_z3(v2)[0] == 68

    # neither fires without capa and without the static signal
    assert _score_smc(_view()) is None


def test_z3_solves_a_constant_compare_guard(autopwn_samples):
    from triage_web.autopwn.strat_z3 import solve_z3

    r = solve_z3(str(autopwn_samples["keygate"]), run=False)
    assert r.ok and r.key_int == 0xDEADBEEF
    assert r.win == "win" and "process(" in r.script


def test_z3_solves_an_arithmetic_chain_guard(autopwn_samples):
    # Closes a gap an earlier audit found: the guard replay used to track a
    # single accumulator and only pick up an *immediate* operand per op, so
    # `x *= 3` compiled as a register-to-register double-and-add-back (no
    # immediate at all) silently vanished from the model, and z3 "solved"
    # for the wrong, shorter chain (0x1363 instead of the real 0x1337).
    from triage_web.autopwn.strat_z3 import solve_z3

    r = solve_z3(str(autopwn_samples["arith_check"]), timeout=10)
    assert r.ok and r.key_int == 0x1337 and r.flag == "flag{arith_z3_solved}"


@pytest.mark.slow
def test_brute_solves_a_short_digit_pin(autopwn_samples):
    # Closes a gap an earlier audit found: brute had solid unit-level
    # scoring/oracle tests but no real compiled binary proving the
    # short-digit-keyspace success path (mode 2) actually recovers a flag
    # end to end, as opposed to correctly declining on an unsuitable target
    # (already covered by the keycheck "no usable signal" case).
    from triage_web.autopwn.strat_brute import solve_brute

    r = solve_brute(str(autopwn_samples["brute_pin"]), timeout=90)
    assert r.ok and r.key == "42" and r.flag == "flag{brute_42}"


def test_brute_reports_cleanly_without_a_runtime(monkeypatch, autopwn_samples):
    from triage_web.autopwn import strat_brute

    monkeypatch.setattr(strat_brute, "have_wsl", lambda: False)
    monkeypatch.setattr(strat_brute.platform, "system", lambda: "Windows")
    r = strat_brute.solve_brute(str(autopwn_samples["keycheck"]))
    assert not r.ok and "no runtime" in r.reason


def test_recon_folds_in_capa_capabilities(monkeypatch, autopwn_samples):
    from triage_web.autopwn import capa_scan, recon

    def fake_caps(_p, *, on_start=None):
        if on_start:
            on_start()
        return frozenset({"anti-analysis", "self-modifying code"})

    monkeypatch.setattr(capa_scan, "capabilities", fake_caps)
    events: list[dict] = []
    rec = recon(str(autopwn_samples["memflag"]), use_capa=True, on_event=events.append)
    assert set(rec["capa"]) == {"anti-analysis", "self-modifying code"}
    assert events == [{"kind": "capa_running"}]  # progress signalled before the blocking scan
    # the capability match promotes the SMC unwrap even on a plain binary
    smc = [p for p in rec["plans"] if p["name"] == "smc"]
    assert smc and "capa" in smc[0]["why"]

    # default: no capa pass, no capa key, unchanged plan
    assert "capa" not in recon(str(autopwn_samples["memflag"]))


def test_solve_threads_capa_into_the_plan(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import capa_scan

    monkeypatch.setattr(capa_scan, "capabilities", lambda _p, **_k: frozenset({"encode data using xor"}))
    monkeypatch.setattr(ap, "_run_strategy", lambda name, *a, **k: ap.Attempt(name, False, 0.0, "skip"))
    res = ap.solve(str(autopwn_samples["keycheck"]), use_capa=True, budget_s=10)
    z3 = [p for p in res.recon["plans"] if p["name"] == "z3"]
    assert z3 and z3[0]["score"] == 68  # capa arithmetic hit outranks the plain heuristic


def test_capa_scan_caches_by_file_and_skips_on_start(monkeypatch, tmp_path):
    from triage_web.autopwn import capa_scan

    bin_path = tmp_path / "sample.bin"
    bin_path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    monkeypatch.setattr(capa_scan, "_CACHE_DIR", tmp_path / "cache")
    capa_scan._MEM.clear()

    calls = {"extract": 0, "start": 0}

    def _extract(_p):
        calls["extract"] += 1
        return frozenset({"foo"})

    def _start():
        calls["start"] += 1

    monkeypatch.setattr(capa_scan, "_extract", _extract)

    first = capa_scan.capabilities(str(bin_path), on_start=_start)
    assert first == frozenset({"foo"}) and calls == {"extract": 1, "start": 1}

    # in-process cache hit: no re-extract, no on_start
    assert capa_scan.capabilities(str(bin_path), on_start=_start) == frozenset({"foo"})
    assert calls == {"extract": 1, "start": 1}

    # disk cache hit after the process cache is dropped
    capa_scan._MEM.clear()
    assert capa_scan.capabilities(str(bin_path), on_start=_start) == frozenset({"foo"})
    assert calls == {"extract": 1, "start": 1}

    # a changed file (new mtime/size) is a fresh key → re-extract
    bin_path.write_bytes(b"\x7fELF" + b"\x01" * 128)
    capa_scan.capabilities(str(bin_path))
    assert calls["extract"] == 2


def test_registry_scorers_return_none_when_inapplicable():
    from triage_web.autopwn.registry import _score_brute, _score_emulate, _score_z3

    pe = _view(fmt="PE", imports=frozenset({"fgets"}))
    assert _score_emulate(pe) is None  # emulate is ELF-only
    assert _score_brute(pe) is None  # brute needs an ELF to run
    assert _score_z3(_view()) is None  # z3 needs input to solve for
    # reads input, no win, but non-x86 and no capa hint → z3 has nothing to model
    assert _score_z3(_view(arch="ARM", imports=frozenset({"fgets"}))) is None


# ── self-modifying-code strategy ─────────────────────────────────────


@pytest.mark.slow
def test_smc_solves_a_real_self_decoding_payload(autopwn_samples):
    # Closes a gap an earlier audit found: smc had solid unit-level
    # transform/repair tests against synthetic byte fixtures, but no real
    # compiled binary proving the full recon -> classify -> smc -> flag
    # pipeline against an actual RWE self-decoding segment.
    from triage_web.autopwn.strat_smc import solve_smc

    r = solve_smc(str(autopwn_samples["smc"]), timeout=30)
    assert r.ok and r.flag == "flag{smc_unwrapped}"


def test_smc_transform_family_recovers_the_reference_decoder(autopwn_samples):
    from triage_web.autopwn import strat_smc as smc
    from triage_web.loader import BinaryLoader

    ldr = BinaryLoader(str(autopwn_samples["keygate"]))
    try:
        clear = bytes(ldr._get_text_section()[0])[:512]  # a real x86-64 function body
    finally:
        ldr.close()
    encrypted = bytes(smc._ref_encode(b) for b in clear)
    name, tbl, score = smc._best_transform(encrypted, 64)
    assert name == "rol1;not;rol3"
    assert smc._apply(tbl, encrypted) == clear
    assert score > smc._score(encrypted, 64) + smc._MARGIN


def test_smc_repair_eident_is_idempotent():
    from triage_web.autopwn import strat_smc as smc

    raw = bytearray(b"\x7fELF" + b"\x02" * 12 + b"\x00" * 40)
    assert smc._repair_eident(raw) is True
    assert raw[4:16] == bytes([2, 1, 1, 0]) + b"\x00" * 8
    assert smc._repair_eident(raw) is False  # already sane → no-op


def test_smc_on_a_plain_binary_reports_no_unwrap(vuln_samples):
    from triage_web.autopwn import strat_smc as smc

    res = smc.solve_smc(str(vuln_samples["vuln_rwx"]))
    assert res.region is not None  # the RWX span was located
    assert not res.ok and res.transform == "identity"  # already-clear code: nothing to peel


def test_smc_discards_the_staged_tempfile_when_nothing_useful_resulted(vuln_samples):
    """solve_smc() always stages its target in a ``triage_smc_*`` temp file to
    work on. When the result doesn't hand that file back as ``decoded_path``
    (no transform found here), the staged copy has no further use and must
    not linger — every binary classified as an SMC candidate that turns out
    not to be one would otherwise leak a full copy of itself into the temp
    dir forever."""
    import glob
    import os
    import tempfile

    from triage_web.autopwn import strat_smc as smc

    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "triage_smc_*")))
    res = smc.solve_smc(str(vuln_samples["vuln_rwx"]))
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "triage_smc_*")))

    assert res.decoded_path is None  # nothing useful to hand back
    assert after == before  # ...so no new staged copy was left behind


def test_smc_drops_an_overlapping_pt_load():
    import struct

    from triage_web.autopwn import strat_smc as smc

    raw = bytearray(0x100)
    raw[:4] = b"\x7fELF"
    raw[4] = 2  # ELFCLASS64
    struct.pack_into("<Q", raw, 0x20, 0x40)  # e_phoff
    struct.pack_into("<H", raw, 0x36, 0x38)  # e_phentsize
    struct.pack_into("<H", raw, 0x38, 2)  # e_phnum

    def ph(base, vaddr, memsz):
        struct.pack_into("<II", raw, base, 1, 5)  # PT_LOAD, R+X
        struct.pack_into("<QQQQQQ", raw, base + 8, 0, vaddr, vaddr, memsz, memsz, 0x1000)

    ph(0x40, 0x400000, 0x2000)  # primary
    ph(0x78, 0x400500, 0x40)  # fully contained → should be dropped
    notes = smc._drop_contained_load(raw)
    assert notes and "0x400500" in notes[0]
    assert struct.unpack_from("<I", raw, 0x78)[0] == 0  # PT_NULL now
    assert struct.unpack_from("<I", raw, 0x40)[0] == 1  # primary untouched


def test_smc_neutralises_hand_rolled_fork_and_ptrace():
    from triage_web.autopwn import strat_smc as smc

    # push rbp; mov rbp,rsp; mov rax,0x39(fork); syscall; mov rax,0x65(ptrace); syscall; ret
    stub = bytes.fromhex("554889e5") + bytes.fromhex("48c7c039000000") + b"\x0f\x05"
    stub += bytes.fromhex("48c7c065000000") + b"\x0f\x05" + b"\xc3"
    raw = bytearray(b"\x00" * 0x100 + stub + b"\x00" * 16)
    notes = smc._neuter_antidebug(raw, 0x400000, (0x100, len(stub)))
    assert any("fork" in n for n in notes) and any("ptrace" in n for n in notes)
    # both `0f 05` syscalls rewritten to `31 c0` (xor eax, eax → returns 0)
    assert raw.count(b"\x0f\x05") == 0
    assert raw[0x100 + 11 : 0x100 + 13] == b"\x31\xc0"


def test_smc_strategy_dispatch(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_smc

    dec = "decoded-image.elf"
    monkeypatch.setattr(
        strat_smc,
        "solve_smc",
        lambda *a, **k: strat_smc.SmcResult(True, flag="flag{smc}", transform="rol1;not;rol3", decoded_path=dec),
    )
    att = ap._run_strategy("smc", str(autopwn_samples["memflag"]), None, 30)
    assert att.ok and att.flag == "flag{smc}"
    assert dec in att.detail and att.script == dec

    monkeypatch.setattr(strat_smc, "solve_smc", lambda *a, **k: strat_smc.SmcResult(False, reason="not an SMC target"))
    miss = ap._run_strategy("smc", str(autopwn_samples["memflag"]), None, 30)
    assert not miss.ok and miss.detail == "not an SMC target"


# ── emulation strategy ───────────────────────────────────────────────


def test_bytecmp_matches_c_strcmp_semantics():
    from triage_web.autopwn.strat_emulate import _bytecmp

    assert _bytecmp(b"abc", b"abc") == 0
    assert _bytecmp(b"abc", b"abd") < 0
    assert _bytecmp(b"abd", b"abc") > 0
    assert _bytecmp(b"ab", b"abc") < 0  # shorter string is a prefix -> "less"
    assert _bytecmp(b"abc", b"ab") > 0


def test_emulate_recovers_an_in_memory_flag(autopwn_samples):
    from triage_web.autopwn.strat_emulate import emulate_for_flag

    r = emulate_for_flag(str(autopwn_samples["memflag"]))
    assert r.ok and r.flag == "flag{MEMbuilt_42}"
    assert "flag{MEMbuilt_42}" in r.memory_hits


def test_emulate_rejects_non_x86(pe_path):
    from triage_web.autopwn.strat_emulate import emulate_for_flag

    r = emulate_for_flag(str(pe_path))
    assert not r.ok and "x86 ELF only" in r.reason


def test_emulate_does_not_find_a_rodata_flag_the_program_never_printed(autopwn_samples):
    # Regression: the memory scan used to read the whole mapped image,
    # including .rodata — present from before execution even starts — so
    # any flag-shaped string literal "won" regardless of whether the code
    # path that prints it (e.g. a win()-only puts()) ever actually ran.
    # keygate's flag lives in such a literal; a wrong/no key must not find
    # it.
    from triage_web.autopwn.strat_emulate import emulate_for_flag

    r = emulate_for_flag(str(autopwn_samples["keygate"]), stdin=b"0\n")
    assert not r.ok and r.flag is None
    assert "nope, wrong key" in r.stdout.decode()


def test_emulate_models_scanf_and_wins_with_the_real_key(autopwn_samples):
    # The positive counterpart: with the correct key, scanf (renamed
    # __isoc99_scanf by glibc) must actually parse it, let win() run for
    # real, and the flag then comes from captured stdout, not a hit scan.
    from triage_web.autopwn.strat_emulate import emulate_for_flag

    r = emulate_for_flag(str(autopwn_samples["keygate"]), stdin=b"deadbeef\n")
    assert r.ok and r.flag == "flag{keygate_static}"
    assert b"flag{keygate_static}" in r.stdout


def test_emulate_strcmp_strcspn_reject_a_wrong_password(autopwn_samples):
    # keycheck's check is fgets + strcspn (strip the trailing newline) +
    # strcmp. Both strcspn and strcmp were previously unmodeled: strcspn
    # defaulted to returning 0 (truncating the input to empty at byte 0),
    # and strcmp defaulted to returning 0 ("equal") regardless of its
    # arguments — either bug alone was enough to make a wrong password look
    # correct.
    from triage_web.autopwn.strat_emulate import emulate_for_flag

    r = emulate_for_flag(str(autopwn_samples["keycheck"]), stdin=b"definitely_wrong\n")
    assert not r.ok and r.flag is None


def test_emulate_strcmp_strcspn_accept_the_real_password(autopwn_samples):
    from triage_web.autopwn.strat_emulate import emulate_for_flag

    r = emulate_for_flag(str(autopwn_samples["keycheck"]), stdin=b"sup3rs3cr3t\n")
    assert r.ok and r.flag == "flag{keycheck_symbolic}"


# ── angr strategy ────────────────────────────────────────────────────


@pytest.mark.slow
def test_angr_recovers_the_password_and_flag(autopwn_samples):
    from triage_web.autopwn.strat_angr import solve_with_angr

    r = solve_with_angr(str(autopwn_samples["keycheck"]), input_len=24, step_budget=12000)
    assert r.ok
    assert r.stdin == b"sup3rs3cr3t"
    assert r.flag == "flag{keycheck_symbolic}"


def test_angr_reports_a_reason_when_it_cannot_load(tmp_path):
    from triage_web.autopwn.strat_angr import solve_with_angr

    bad = tmp_path / "bad.elf"
    bad.write_bytes(b"\x7fELF" + b"\x00" * 40)
    r = solve_with_angr(str(bad), step_budget=200)
    assert not r.ok and r.reason


@pytest.mark.slow
def test_angr_solves_an_argv_only_overflow_via_the_symbolic_argv_fallback(crackme_path):
    # Regression: elf64_crackme's overflow only runs via argv (strcpy(buf,
    # argv[1])), not stdin. _run_angr used to only ever try solve_with_angr's
    # stdin-only default, so it never reached the vulnerable path at all —
    # even though solve_with_angr already supported use_argv=True.
    import triage_web.autopwn as ap

    att = ap._run_strategy("angr", str(crackme_path), None, 90)
    assert att.ok and att.flag == "FLAG{ok}"
    assert "via symbolic argv" in att.detail


def test_run_angr_tries_symbolic_argv_only_after_stdin_fails(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_angr

    calls = []

    def fake(_path, *, use_argv=False, **_k):
        calls.append(use_argv)
        if use_argv:
            return strat_angr.AngrResult(True, stdin=b"X", flag="flag{argv}", stdout=b"ok\n")
        return strat_angr.AngrResult(False, reason="no success state reached")

    monkeypatch.setattr(strat_angr, "solve_with_angr", fake)
    att = ap._run_strategy("angr", str(autopwn_samples["memflag"]), None, 10)
    assert calls == [False, True]  # stdin tried first, argv only as a fallback
    assert att.ok and att.flag == "flag{argv}"
    assert "via symbolic argv" in att.detail


def test_run_angr_reports_both_attempts_failed(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_angr

    monkeypatch.setattr(
        strat_angr, "solve_with_angr", lambda *a, **k: strat_angr.AngrResult(False, reason="no success state")
    )
    att = ap._run_strategy("angr", str(autopwn_samples["memflag"]), None, 10)
    assert not att.ok
    assert "no success state" in att.detail
    assert "also tried symbolic argv" in att.detail


# ── keygen strategy ──────────────────────────────────────────────────


def test_keygen_recovers_a_constant_compare_and_runs_it(autopwn_samples):
    from triage_web.autopwn.strat_keygen import solve_keygen

    r = solve_keygen(str(autopwn_samples["keygate"]))
    assert r.ok
    assert r.key == "deadbeef"  # scanf("%x") → hex form
    assert r.key_int == 0xDEADBEEF
    assert r.win == "win"
    if _CAN_RUN_ELF:
        assert r.flag == "flag{keygate_static}"


def test_keygen_ignores_a_scanf_retval_check_and_picks_the_magic(autopwn_samples):
    from triage_web.autopwn.strat_keygen import solve_keygen

    r = solve_keygen(str(autopwn_samples["keygate"]))
    assert r.key_int == 0xDEADBEEF  # not the `scanf(...) == 1` constant


def test_keygen_no_win_function(autopwn_samples):
    from triage_web.autopwn.strat_keygen import solve_keygen

    r = solve_keygen(str(autopwn_samples["memflag"]))
    assert not r.ok and "no win-style function" in r.reason


def test_keygen_no_guard_when_win_is_a_plain_overflow(autopwn_samples):
    from triage_web.autopwn.strat_keygen import solve_keygen

    r = solve_keygen(str(autopwn_samples["ret2win"]))
    assert not r.ok and "no constant-compare guard" in r.reason


def test_classify_lists_keygen_for_a_keycheck_with_a_win(autopwn_samples):
    names = [p.name for p in classify(str(autopwn_samples["keygate"]))]
    assert "keygen" in names


def test_solve_uses_keygen_for_keygate(autopwn_samples):
    res = solve(str(autopwn_samples["keygate"]), budget_s=40)
    assert res.success
    assert res.flag == "flag{keygate_static}"
    assert res.attempts[0]["strategy"] == "keygen"


# ── uaf strategy (unit-level: recon helpers + guards) ────────────────


def test_uaf_rejects_targets_without_free_and_getenv(autopwn_samples):
    from triage_web.autopwn.strat_uaf import solve_uaf

    r = solve_uaf(str(autopwn_samples["ret2win"]))
    assert not r.ok and "dangling-callback shape" in r.reason


def test_uaf_recon_helpers():
    from triage_web.autopwn import strat_uaf as u

    raw = b"...LOGIN|...WATCH...CREATE|...BID...Sec-WebSocket-Key...on port 8765..."
    assert u._is_websocket(raw)
    assert u._server_port(raw, []) == 8765
    verbs = u._command_verbs(raw)
    assert verbs == {"login": "LOGIN|", "watch": "WATCH", "create": "CREATE|", "bid": "BID"}
    assert u._server_port(b"no banner", []) == 8765  # default
    assert not u._is_websocket(b"plain tcp")


def test_uaf_emitted_exploit_is_parameterised():
    from triage_web.autopwn.strat_uaf import _emit_exploit

    script = _emit_exploit("/bin/target", 0x402536, 0x28, 8765, True, {}, route="id")
    assert "FLAG_FUNC = 0x402536" in script
    assert "STRUCT    = 40" in script
    assert "ROUTE     = 'id'" in script
    assert "ws_handshake" in script and "TRIAGE_FD" in script
    compile(script, "<uaf>", "exec")
    # a pointer-routed callee can't be exploited blind - the script says so and bails
    ptr_script = _emit_exploit("/bin/target", 0x402536, 0x28, 8765, True, {}, route="ptr")
    assert "route=ptr" in ptr_script and "needs a separate leak" in ptr_script
    compile(ptr_script, "<uaf>", "exec")


_UAF_HOSTILE_PATH = "evil'\"; rm -rf ~; $(touch pwned).bin"


@pytest.mark.slow
def test_uaf_solves_a_real_dangling_callback_service(autopwn_samples):
    # Closes a gap an earlier audit found: uaf had solid unit-level
    # routing/classification tests against synthetic disassembly, but no
    # real compiled service proving the full recon -> UAF-plant -> BID ->
    # flag pipeline against an actual threaded TCP server.
    from triage_web.autopwn.strat_uaf import solve_uaf

    r = solve_uaf(str(autopwn_samples["uaf_service"]), timeout=40)
    assert r.ok and r.flag == "flag{triage_uaf_selftest}"


def test_uaf_server_shell_cmd_quotes_a_hostile_path(monkeypatch):
    from triage_web.autopwn import strat_uaf as u

    cmd = u._server_shell_cmd(_UAF_HOSTILE_PATH)
    words = shlex.split(cmd)
    assert u.run_path(_UAF_HOSTILE_PATH) in words
    assert words[0] == f"FLAG={u._SELFTEST_FLAG}"
    assert words[1:3] == ["exec", u.run_path(_UAF_HOSTILE_PATH)]


def test_uaf_classifies_how_the_callback_arg_is_used():
    import capstone as cs

    from triage_web.autopwn import strat_uaf as u

    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)

    def body(hexstr):
        return list(md.disasm(bytes.fromhex(hexstr), 0x1000))

    # mov rax, [rdi + 8]  -> arg1 dereferenced -> ptr
    assert u._classify_arg1_use(body("488b4708"), {}) == "ptr"
    # mov r13, rdi ; cmp r13, [rax + 0x530]  -> compared against a far struct field -> id
    assert u._classify_arg1_use(body("4989fd4c3ba830050000"), {}) == "id"
    # mov edi, edi ; call send@plt  -> arg1 handed to send() -> fd
    assert u._classify_arg1_use(body("89ffe800000000"), {0x1007: "send@GLIBC_2.2.5"}) == "fd"


# ── ret2win strategy ─────────────────────────────────────────────────


def test_ret2win_emits_a_script_and_finds_the_win_and_offset(autopwn_samples):
    from triage_web.autopwn.strat_ret2win import solve_ret2win

    r = solve_ret2win(str(autopwn_samples["ret2win"]), timeout=90)
    assert r.win == "win"
    assert r.offset == 40
    assert "process(" in r.script and "p64(WIN)" in r.script
    if _CAN_RUN_ELF:
        assert r.ok and r.flag == "flag{ret2win_reached}"


def test_ret2win_offset_heuristic_resolves_plt_names_on_a_statically_linked_sink(crackme_path):
    # Regression: _find_offset's overflow_sites() call used to pass an empty
    # known_calls dict, so PLT targets never resolved to names like "strcpy"
    # and the VULN_BOF match always missed, on any target that doesn't
    # already find a win address via angr's symbolic offset search.
    from triage_web.autopwn.strat_ret2win import solve_ret2win

    r = solve_ret2win(str(crackme_path), timeout=30)
    assert r.win == "win"
    assert r.offset == 40


def test_ret2win_script_survives_a_target_that_never_reads_stdin(crackme_path):
    # Regression: elf64_crackme's overflow only runs via argv (strcpy(buf,
    # argv[1])); it closes stdin almost immediately when run with no args, so
    # attempt()'s sendline() raised BrokenPipeError. The old `except EOFError`
    # didn't catch that (a different exception class), so the whole generated
    # script crashed with an unhandled traceback before reaching any later
    # attempt, including the argv-based fallback. It's fine if no flag is
    # found here (this address contains a NUL byte an argv string can't
    # carry), but the script must run clean, not crash.
    from triage_web.autopwn.strat_ret2win import solve_ret2win

    r = solve_ret2win(str(crackme_path), timeout=30)
    if _CAN_RUN_ELF:
        assert "Traceback" not in r.reason
        assert "BrokenPipeError" not in r.reason


def test_ret2win_gives_up_cleanly_without_a_win_function(autopwn_samples):
    from triage_web.autopwn.strat_ret2win import solve_ret2win

    r = solve_ret2win(str(autopwn_samples["memflag"]))
    assert not r.ok and "no win function" in r.reason


# ── format-string strategy ───────────────────────────────────────────


def test_fmt_generates_a_probe_script_for_a_non_running_target(pe_path):
    from triage_web.autopwn.strat_fmt import solve_format_string

    r = solve_format_string(str(pe_path))
    assert "%p." in r.script
    assert not r.ok


def test_fmt_local_probe_reaches_the_shared_runner_route(vuln_samples):
    """vuln_pie has no socket/bind/listen/accept imports, so solve_format_string
    takes the local-probe run_script() branch in strat_fmt.py — the same
    shared WSL/sandbox route autopwn's other live strategies use.

    Regression: vuln_pie's vuln() only runs when invoked with an argv
    (``if (argc > 1) vuln(argv[1])``). The generated probe script used to
    only ever try stdin, which closed before anything was sent, and the
    script's own sendline()/recvall() weren't wrapped for BrokenPipeError
    (only EOFError) — the whole script crashed with an unhandled
    traceback, never actually probing the format-string sink at all. The
    probe now also tries argv, and the exception handling is broad enough
    to survive a target that never reads stdin: it must produce a real
    leak (hex pointer values from %p), not a crash.
    """
    from triage_web.autopwn.strat_fmt import solve_format_string

    res = solve_format_string(str(vuln_samples["vuln_pie"]))
    if _CAN_RUN_ELF:
        assert "Traceback" not in res.leak and "BrokenPipeError" not in res.leak
        assert re.search(r"0x[0-9a-f]+", res.leak), f"expected a real %p leak, got: {res.leak!r}"
    else:
        assert res.script


def test_fmt_server_argv_uses_native_shell_on_linux(monkeypatch):
    from triage_web.autopwn import strat_fmt

    monkeypatch.setattr(strat_fmt.platform, "system", lambda: "Linux")
    argv = strat_fmt._server_argv("svc-bin", 9999)
    assert argv[0] == "/bin/bash" and "wsl" not in argv  # no shell-out to wsl on a Linux host

    monkeypatch.setattr(strat_fmt.platform, "system", lambda: "Windows")
    assert strat_fmt._server_argv("svc-bin", 9999)[0] == "wsl"


def test_fmt_server_argv_quotes_a_hostile_path_on_wsl(monkeypatch):
    from triage_web.autopwn import strat_fmt

    monkeypatch.setattr(strat_fmt.platform, "system", lambda: "Windows")
    argv = strat_fmt._server_argv(_UAF_HOSTILE_PATH, 9999)
    assert argv[:3] == ["wsl", "-e", "bash"]
    words = shlex.split(argv[-1])
    assert strat_fmt.to_wsl(_UAF_HOSTILE_PATH) in words


def test_fmt_probe_network_survives_a_missing_runtime(monkeypatch):
    from triage_web.autopwn import strat_fmt

    def _boom(*a, **k):
        raise FileNotFoundError("No such file or directory: 'wsl'")

    monkeypatch.setattr(strat_fmt.subprocess, "Popen", _boom)
    log: list[str] = []
    leak, flag = strat_fmt._probe_network("svc-bin", "127.0.0.1", 9999, log)
    assert (leak, flag) == ("", None)
    assert any("could not start the service" in m for m in log)


# ── orchestrator ─────────────────────────────────────────────────────


def test_solve_memflag_end_to_end(autopwn_samples):
    res = solve(str(autopwn_samples["memflag"]), budget_s=40)
    assert res.success and res.strategy == "emulate"
    assert res.flag == "flag{MEMbuilt_42}"
    assert res.attempts[0]["strategy"] == "emulate"


def test_solve_records_every_attempt_on_failure(tmp_path):
    bad = tmp_path / "x.elf"
    bad.write_bytes(b"\x7fELF" + b"\x00" * 60)
    res = solve(str(bad), only=["emulate"], budget_s=10)
    assert not res.success
    assert res.attempts and res.notes


def test_solve_only_filter_forces_an_unlisted_strategy(autopwn_samples):
    res = solve(str(autopwn_samples["keycheck"]), only=["ret2win"], budget_s=20)
    assert [a["strategy"] for a in res.attempts] == ["ret2win"]


def test_recon_shape(autopwn_samples):
    data = recon(str(autopwn_samples["ret2win"]))
    assert data["arch"] == "x86_64"
    assert data["format"] == "ELF"
    assert any(p["name"] == "ret2win" for p in data["plans"])
    assert "protections" in data


def test_solve_strategy_crash_is_contained(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap

    def boom(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(ap, "_run_strategy", boom)
    res = solve(str(autopwn_samples["memflag"]), budget_s=10)
    assert not res.success
    assert any("crashed" in a["detail"] for a in res.attempts)


def test_solve_no_flag_notes_name_every_attempted_strategy(monkeypatch, tmp_path):
    import triage_web.autopwn as ap

    monkeypatch.setenv("TRIAGE_RESULTS", str(tmp_path / "r.jsonl"))
    # a path that never loads: recon() swallows the error into {"error": ...},
    # so both forced strategies run (and crash) rather than classify() alone
    # scoring just the one that applies to a malformed-but-readable ELF.
    res = ap.solve(str(tmp_path / "does-not-exist"), only=["emulate", "ret2win"], budget_s=10)
    assert not res.success
    assert res.attempts
    for att in res.attempts:
        assert {"strategy", "ok", "detail", "confidence"} <= att.keys()
    assert "emulate" in res.notes and "ret2win" in res.notes


def test_solve_no_flag_notes_keep_a_short_finding_but_drop_a_long_one(monkeypatch, tmp_path, autopwn_samples):
    """A short recovered finding (this project's real "win" symbol) survives
    the 120-char notes slice; a pathologically long symbol/key repr can still
    push it past that slice. keygen/z3 truncation-survival for long key reprs
    is a known, accepted limitation OUT OF SCOPE for this phase — the
    truncation constants themselves are deliberately left untouched."""
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_ret2win

    monkeypatch.setenv("TRIAGE_RESULTS", str(tmp_path / "r.jsonl"))

    monkeypatch.setattr(
        strat_ret2win,
        "solve_ret2win",
        lambda *a, **k: strat_ret2win.Ret2WinResult(
            ok=False, win="win", win_addr=0x401234, offset=40, reason="exploit ran but produced no flag"
        ),
    )
    short_res = ap.solve(str(autopwn_samples["memflag"]), only=["ret2win"], budget_s=10)
    assert "win=win@0x401234 offset=40" in short_res.notes
    assert "win=win@0x401234 offset=40" in short_res.attempts[0]["detail"]

    monkeypatch.setattr(
        strat_ret2win,
        "solve_ret2win",
        lambda *a, **k: strat_ret2win.Ret2WinResult(
            ok=False, win="w" * 200, win_addr=0x401234, offset=40, reason="exploit ran but produced no flag"
        ),
    )
    long_res = ap.solve(str(autopwn_samples["memflag"]), only=["ret2win"], budget_s=10)
    assert "offset=40" not in long_res.notes  # pushed past the 120-char slice
    assert "offset=40" in long_res.attempts[0]["detail"]  # but preserved in full here


# ── CLI ──────────────────────────────────────────────────────────────


def test_cli_recon(capsys, autopwn_samples):
    from triage_web.autopwn.__main__ import main

    rc = main([str(autopwn_samples["memflag"]), "--recon"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "plan:" in out and "emulate" in out


def test_cli_solve_json(capsys, tmp_path, monkeypatch, autopwn_samples):
    import triage_web.autopwn.__main__ as cli

    # a real solve writes its writeup next to the target by default; redirect
    # it into tmp_path so this test doesn't drop a file into tracked samples/
    monkeypatch.setattr(cli, "default_writeup_path", lambda result: tmp_path / "out-writeup.md")

    rc = cli.main([str(autopwn_samples["memflag"]), "--json", "--budget", "40"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["success"] and payload["flag"] == "flag{MEMbuilt_42}"
    assert (tmp_path / "out-writeup.md").exists()
    assert "flag{MEMbuilt_42}" in (tmp_path / "out-writeup.md").read_text()


def test_cli_solve_prints_the_writeup_path_on_success(capsys, tmp_path, monkeypatch, autopwn_samples):
    import triage_web.autopwn.__main__ as cli

    monkeypatch.setattr(cli, "default_writeup_path", lambda result: tmp_path / "out-writeup.md")
    rc = cli.main([str(autopwn_samples["memflag"]), "--budget", "40"])
    out = capsys.readouterr().out
    assert rc == 0
    assert f"writeup: {tmp_path / 'out-writeup.md'}" in out


def test_cli_reports_failure_detail(capsys, tmp_path):
    from triage_web.autopwn.__main__ import main

    bad = tmp_path / "n.elf"
    bad.write_bytes(b"\x7fELF" + b"\x00" * 40)
    rc = main([str(bad), "--only", "emulate"])
    assert rc == 1
    assert "no flag" in capsys.readouterr().out


def test_cli_no_flag_lists_attempted_strategies(monkeypatch, capsys, tmp_path):
    from triage_web.autopwn.__main__ import main

    monkeypatch.setenv("TRIAGE_RESULTS", str(tmp_path / "r.jsonl"))
    bad = tmp_path / "n.elf"
    bad.write_bytes(b"\x7fELF" + b"\x00" * 40)
    rc = main([str(bad), "--only", "emulate"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "no flag" in out
    assert "emulate" in out


# ── API ──────────────────────────────────────────────────────────────


def test_api_autopwn_solve_forwards_strategy_and_budget(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap

    captured = {}

    def fake_solve(path, *, only, budget_s, flag_pattern, use_capa=False):
        captured.update(path=path, only=only, budget_s=budget_s, use_capa=use_capa)
        return ap.SolveResult(path, True, "flag{routed}", "emulate", 0.1, proof="p")

    monkeypatch.setattr(ap, "solve", fake_solve)
    c = TestClient(server.app)
    c.post("/api/load", data={"path": str(autopwn_samples["memflag"])})
    body = c.post("/api/autopwn", params={"strategies": "emulate,angr", "budget_s": 5}).json()
    assert body["flag"] == "flag{routed}"
    assert captured["only"] == ["emulate", "angr"]
    assert captured["budget_s"] == 10.0  # clamped to the 10s floor


def test_api_autopwn_no_flag_result_lists_attempts_and_notes(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap

    def fake_solve(path, *, only, budget_s, flag_pattern, use_capa=False):
        return ap.SolveResult(
            path,
            False,
            None,
            None,
            3.4,
            attempts=[
                {
                    "strategy": "ret2win",
                    "ok": False,
                    "seconds": 0.3,
                    "detail": "win=win@0x401234 offset=72 (exploit ran but produced no flag)",
                    "flag": None,
                    "script": "",
                    "confidence": "",
                }
            ],
            notes="ret2win: win=win@0x401234 offset=72 (exploit ran but produced no flag)",
        )

    monkeypatch.setattr(ap, "solve", fake_solve)
    c = TestClient(server.app)
    c.post("/api/load", data={"path": str(autopwn_samples["memflag"])})
    body = c.post("/api/autopwn").json()
    assert body["success"] is False
    assert body["attempts"][0]["strategy"] == "ret2win"
    assert "offset=72" in body["attempts"][0]["detail"]
    assert "ret2win" in body["notes"]


# ── runner branch coverage (platform-mocked, no real processes) ───────


class _FakeCompleted:
    def __init__(self, rc=0, out=b"flag{sub}", err=b""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def test_popen_paths(monkeypatch):
    from triage_web.autopwn import runner

    ok = runner._popen(["x"], b"", 1.0)
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: _FakeCompleted())
    ok = runner._popen(["echo"], b"", 1.0)
    assert ok.returncode == 0 and ok.flags == ["flag{sub}"]

    def timeout(*a, **k):
        raise runner.subprocess.TimeoutExpired(cmd="x", timeout=1, output=b"partial", stderr=b"")

    monkeypatch.setattr(runner.subprocess, "run", timeout)
    t = runner._popen(["x"], b"", 1.0)
    assert t.timed_out and t.stdout == b"partial"

    def missing(*a, **k):
        raise FileNotFoundError("no wsl")

    monkeypatch.setattr(runner.subprocess, "run", missing)
    m = runner._popen(["wsl"], b"", 1.0)
    assert not m.runnable


def test_run_target_elf_on_linux(monkeypatch, autopwn_samples):
    from triage_web.autopwn import runner

    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner, "_popen", lambda cmd, stdin, to: ProcResult(0, b"L", b"", False, 0.0, cmd[0]))
    r = runner.run_target(autopwn_samples["memflag"], argv=("a b",), env={"K": "v"})
    assert r.stdout == b"L"


def test_run_target_elf_via_wsl(monkeypatch, autopwn_samples):
    from triage_web.autopwn import runner

    monkeypatch.setattr(runner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda s, i, t: ProcResult(0, b"W", b"", False, 0.0, "wsl"))
    assert runner.run_target(autopwn_samples["memflag"]).stdout == b"W"


def test_run_target_no_runtime_and_pe_and_unknown(monkeypatch, autopwn_samples, pe_path, tmp_path):
    from triage_web.autopwn import runner

    monkeypatch.setattr(runner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(runner, "have_wsl", lambda: False)
    assert not runner.run_target(autopwn_samples["memflag"]).runnable

    monkeypatch.setattr(runner, "_popen", lambda c, i, t: ProcResult(0, b"PE", b"", False, 0.0, "pe"))
    assert runner.run_target(pe_path).stdout == b"PE"

    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner.shutil, "which", lambda _n: "/usr/bin/wine")
    assert runner.run_target(pe_path).stdout == b"PE"
    monkeypatch.setattr(runner.shutil, "which", lambda _n: None)
    assert not runner.run_target(pe_path).runnable

    junk = tmp_path / "j"
    junk.write_bytes(b"????")
    assert not runner.run_target(junk).runnable


def test_run_script_paths(monkeypatch):
    from triage_web.autopwn import runner

    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner.shutil, "which", lambda _n: "/usr/bin/python3")
    monkeypatch.setattr(runner, "_popen", lambda c, i, t: ProcResult(0, b"ran", b"", False, 0.0, c[0]))
    assert runner.run_script("print(1)").stdout == b"ran"

    monkeypatch.setattr(runner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(runner, "have_wsl", lambda: False)
    assert not runner.run_script("x").runnable

    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda s, i, t: ProcResult(0, b"wsl-ran", b"", False, 0.0, "wsl"))
    assert runner.run_script("x", python="/p").stdout == b"wsl-ran"


def test_sh_probe_returns_empty_when_the_probe_shell_cannot_spawn(monkeypatch):
    from triage_web.autopwn import runner

    def boom(*_a, **_k):
        raise OSError("cannot spawn probe shell")

    monkeypatch.setattr(runner.subprocess, "run", boom)
    # a unique prefix -> its own cache slot, so this neither hits nor poisons
    # the real ("/bin/bash", "-c") / ("wsl", …) entries other tests populate
    assert runner._sh_probe(["__cov_probe_only__"]) == set()


def test_wsl_bash_forwards_to_popen(monkeypatch):
    from triage_web.autopwn import runner

    calls = []

    def fake_popen(cmd, stdin, to):
        calls.append((cmd, stdin, to))
        return ProcResult(0, b"ok", b"", False, 0.0, "wsl")

    monkeypatch.setattr(runner, "_popen", fake_popen)
    r = runner._wsl_bash("echo hi", b"in", 7.0)
    assert calls == [(["wsl", "-e", "bash", "-lc", "echo hi"], b"in", 7.0)]
    assert r.stdout == b"ok"


def test_sandbox_wrap_picks_the_strongest_layer(monkeypatch):
    from triage_web.autopwn import runner

    monkeypatch.setattr(runner, "_SANDBOX_MODE", "auto")
    monkeypatch.setattr(runner, "_sh_probe", lambda _p: {"bwrap"})
    cmd, note = runner._sandbox_wrap("echo hi", "/work", net=False, bash_prefix=["/bin/bash", "-c"])
    assert cmd.startswith("bwrap --unshare-all") and "bwrap" in note

    monkeypatch.setattr(runner, "_sh_probe", lambda _p: {"bwrap", "unshare"})
    cmd, note = runner._sandbox_wrap("echo hi", "/work", net=True, bash_prefix=["/bin/bash", "-c"])
    assert cmd.startswith("unshare -rn") and "ip link set lo up" in cmd and "loopback-only" in note

    monkeypatch.setattr(runner, "_sh_probe", lambda _p: set())
    cmd, note = runner._sandbox_wrap("echo hi", "/work", net=False, bash_prefix=["/bin/bash", "-c"])
    assert cmd == "echo hi" and "UNSANDBOXED" in note

    monkeypatch.setattr(runner, "_SANDBOX_MODE", "off")
    cmd, note = runner._sandbox_wrap("echo hi", "/work", net=False, bash_prefix=["/bin/bash", "-c"])
    assert cmd == "echo hi" and "disabled" in note

    monkeypatch.setattr(runner, "_SANDBOX_MODE", "strict")
    cmd, note = runner._sandbox_wrap("echo hi", "/work", net=False, bash_prefix=["/bin/bash", "-c"])
    assert cmd == "" and "refused" in note


def test_strict_sandbox_refuses_to_run_unsandboxed(monkeypatch, autopwn_samples):
    from triage_web.autopwn import runner

    monkeypatch.setattr(runner, "_SANDBOX_MODE", "strict")
    monkeypatch.setattr(runner, "_sh_probe", lambda _p: set())

    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    r = runner.run_target(autopwn_samples["memflag"])
    assert not r.runnable and "refused" in r.note

    monkeypatch.setattr(runner.shutil, "which", lambda _n: "/usr/bin/python3")
    r = runner.run_script("print(1)")
    assert not r.runnable and "refused" in r.note

    monkeypatch.setattr(runner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    r = runner.run_target(autopwn_samples["memflag"])
    assert not r.runnable and "refused" in r.note
    r = runner.run_script("print(1)")
    assert not r.runnable and "refused" in r.note


def test_sh_quote_and_run_path(monkeypatch):
    from triage_web.autopwn import runner

    assert runner._sh_quote("safe_name") == "safe_name"
    assert runner._sh_quote("has space") == "'has space'"
    assert runner._sh_quote("tick's") == "'tick'\\''s'"
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    assert not runner.run_path("x").startswith("/mnt/")  # native path on Linux
    # run_path's WSL branch calls Path(...).resolve(), which only yields a
    # drive-letter path on a real Windows host — so only assert it there.
    if platform.system() == "Windows":
        monkeypatch.setattr(runner.platform, "system", lambda: "Windows")
        monkeypatch.setattr(runner, "have_wsl", lambda: True)
        assert runner.run_path(r"C:\a\b").startswith("/mnt/c/")


# ── orchestrator dispatch (strategies mocked) ────────────────────────


def test_run_strategy_dispatches_each_backend(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_angr, strat_emulate, strat_fmt, strat_keygen, strat_ret2win, strat_uaf

    p = str(autopwn_samples["memflag"])
    monkeypatch.setattr(strat_emulate, "emulate_for_flag", lambda *a, **k: strat_emulate.EmulateResult(True, "flag{e}"))
    monkeypatch.setattr(strat_angr, "solve_with_angr", lambda *a, **k: strat_angr.AngrResult(True, b"in", "flag{a}"))
    r2w = strat_ret2win.Ret2WinResult(True, "flag{r}", "win", 1, 8, "s")
    monkeypatch.setattr(strat_ret2win, "solve_ret2win", lambda *a, **k: r2w)
    monkeypatch.setattr(
        strat_fmt, "solve_format_string", lambda *a, **k: strat_fmt.FmtResult(True, "flag{f}", script="s")
    )
    kg = strat_keygen.KeygenResult(True, key="cafe", win="win", win_addr=1, flag="flag{k}")
    monkeypatch.setattr(strat_keygen, "solve_keygen", lambda *a, **k: kg)
    uf = strat_uaf.UafResult(True, flag="flag{u}", flag_func=0x402536, struct_size=0x28, script="s")
    monkeypatch.setattr(strat_uaf, "solve_uaf", lambda *a, **k: uf)
    from triage_web.autopwn import strat_brute, strat_z3

    monkeypatch.setattr(
        strat_z3, "solve_z3", lambda *a, **k: strat_z3.Z3Result(True, flag="flag{z}", key="c0de", win="win")
    )
    monkeypatch.setattr(
        strat_brute, "solve_brute", lambda *a, **k: strat_brute.BruteResult(True, flag="flag{b}", key="ab")
    )

    assert ap._run_strategy("emulate", p, None, 10).flag == "flag{e}"
    assert ap._run_strategy("angr", p, None, 10).flag == "flag{a}"
    assert ap._run_strategy("keygen", p, None, 10).flag == "flag{k}"
    assert ap._run_strategy("uaf", p, None, 10).flag == "flag{u}"
    assert ap._run_strategy("ret2win", p, None, 10).flag == "flag{r}"
    assert ap._run_strategy("format_string", p, None, 10).flag == "flag{f}"
    assert ap._run_strategy("z3", p, None, 10).flag == "flag{z}"
    assert ap._run_strategy("brute", p, None, 10).flag == "flag{b}"
    assert not ap._run_strategy("bogus", p, None, 10).ok


# ── registry: compose the recovered finding with the no-flag reason ─
# (TRACE-02 — the real bug: a recovered win/key/struct finding was
# silently discarded by `reason or <finding>` on every genuine no-flag run)


def test_run_ret2win_composes_recovered_finding_with_the_no_flag_reason(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_ret2win

    monkeypatch.setattr(
        strat_ret2win,
        "solve_ret2win",
        lambda *a, **k: strat_ret2win.Ret2WinResult(
            ok=False, win="win", win_addr=0x401234, offset=72, script="s", reason="exploit ran but produced no flag"
        ),
    )
    att = ap._run_strategy("ret2win", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert att.flag is None
    assert "win=win@0x401234 offset=72" in att.detail
    assert "exploit ran but produced no flag" in att.detail
    assert "win=win@0x401234 offset=72" in att.detail[:120]  # finding front-loaded


def test_run_ret2win_falls_back_to_reason_when_nothing_recovered(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_ret2win

    monkeypatch.setattr(
        strat_ret2win,
        "solve_ret2win",
        lambda *a, **k: strat_ret2win.Ret2WinResult(ok=False, reason='no win function / system("/bin/sh") site found'),
    )
    att = ap._run_strategy("ret2win", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert att.detail == 'no win function / system("/bin/sh") site found'
    assert "win=" not in att.detail and "offset=" not in att.detail  # nothing fabricated


def test_run_ret2win_composes_win_without_offset_when_only_win_is_recovered(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_ret2win

    monkeypatch.setattr(
        strat_ret2win,
        "solve_ret2win",
        lambda *a, **k: strat_ret2win.Ret2WinResult(
            ok=False, win="win", win_addr=0x401234, offset=None, reason="could not determine the overflow offset"
        ),
    )
    att = ap._run_strategy("ret2win", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert "win=win@0x401234" in att.detail
    assert "offset=" not in att.detail
    assert "could not determine the overflow offset" in att.detail


def test_ret2win_real_fixture_recovers_a_short_front_loaded_finding(autopwn_samples):
    import triage_web.autopwn as ap

    att = ap._run_strategy("ret2win", str(autopwn_samples["ret2win"]), None, 60)
    assert "win=win" in att.detail
    assert "offset=40" in att.detail
    assert "offset=40" in att.detail[:120]


def test_run_keygen_composes_the_recovered_key_with_the_no_flag_reason(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_keygen

    monkeypatch.setattr(
        strat_keygen,
        "solve_keygen",
        lambda *a, **k: strat_keygen.KeygenResult(
            ok=True,
            key="deadbeef",
            key_int=0xDEADBEEF,
            win="win",
            win_addr=0x401234,
            flag=None,
            reason="recovered the key but could not obtain the flag here — run the target with it",
        ),
    )
    att = ap._run_strategy("keygen", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert "key='deadbeef'" in att.detail
    assert "recovered the key" in att.detail


def test_run_z3_composes_the_recovered_key_with_the_no_flag_reason(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_z3

    monkeypatch.setattr(
        strat_z3,
        "solve_z3",
        lambda *a, **k: strat_z3.Z3Result(
            ok=True,
            key="c0de",
            key_int=0xC0DE,
            win="win",
            flag=None,
            script="s",
            reason="recovered a satisfying key but no flag here — run the target with it",
        ),
    )
    att = ap._run_strategy("z3", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert "key='c0de'" in att.detail
    assert "recovered a satisfying key" in att.detail


def test_run_uaf_composes_the_recovered_struct_info_with_the_no_flag_reason(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_uaf

    monkeypatch.setattr(
        strat_uaf,
        "solve_uaf",
        lambda *a, **k: strat_uaf.UafResult(
            ok=False,
            flag_func=0x1234,
            struct_size=0x40,
            port=8080,
            websocket=False,
            route="fd",
            script="s",
            reason="generated the exploit and ran it against a local instance but got no flag back",
        ),
    )
    att = ap._run_strategy("uaf", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert "0x1234" in att.detail and "dangling callback" in att.detail
    assert "a file descriptor" in att.detail
    assert "generated the exploit" in att.detail


def test_run_uaf_falls_back_to_reason_when_nothing_recovered(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_uaf

    monkeypatch.setattr(
        strat_uaf,
        "solve_uaf",
        lambda *a, **k: strat_uaf.UafResult(ok=False, reason="no free()+getenv() — not the dangling-callback shape"),
    )
    att = ap._run_strategy("uaf", str(autopwn_samples["memflag"]), None, 30)
    assert att.detail == "no free()+getenv() — not the dangling-callback shape"
    assert "dangling callback" not in att.detail


def test_run_uaf_composes_without_struct_size_when_only_flag_func_is_recovered(monkeypatch, autopwn_samples):
    """struct_size is independently None-able even when flag_func is found
    (_modal_malloc_size() can see no small-malloc call); formatting it
    unconditionally with :#x would raise TypeError on this real shape."""
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_uaf

    monkeypatch.setattr(
        strat_uaf,
        "solve_uaf",
        lambda *a, **k: strat_uaf.UafResult(
            ok=False,
            flag_func=0x5000,
            struct_size=None,
            port=None,
            websocket=False,
            route="unknown",
            reason="generated the exploit and ran it against a local instance but got no flag back",
        ),
    )
    att = ap._run_strategy("uaf", str(autopwn_samples["memflag"]), None, 30)  # must not raise
    assert not att.ok
    assert "0x5000" in att.detail and "dangling callback" in att.detail
    assert "generated the exploit" in att.detail
    assert "struct size" not in att.detail


def test_run_brute_composes_the_recovered_prefix_with_the_no_flag_reason(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_brute

    monkeypatch.setattr(
        strat_brute,
        "solve_brute",
        lambda *a, **k: strat_brute.BruteResult(
            ok=False,
            key="abc",
            tries=4096,
            reason="recovered a likely prefix 'abc' but the checker never confirmed a full key",
        ),
    )
    att = ap._run_strategy("brute", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert "key='abc'" in att.detail
    assert "recovered a likely prefix" in att.detail


def test_run_emulate_composes_the_captured_stdout_with_the_no_flag_reason(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_emulate

    monkeypatch.setattr(
        strat_emulate,
        "emulate_for_flag",
        lambda *a, **k: strat_emulate.EmulateResult(
            ok=False,
            stdout=b"checking key...\nwrong key\n",
            reason="no flag in output or memory after emulation",
        ),
    )
    att = ap._run_strategy("emulate", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert "stdout=" in att.detail and "checking key" in att.detail
    assert "no flag in output or memory after emulation" in att.detail


def test_run_emulate_says_the_flag_came_from_memory_not_stdout(monkeypatch, autopwn_samples):
    # Regression: a flag built into a buffer but never printed used to show
    # the (unrelated) captured stdout in the writeup/proof, with no mention
    # that the flag actually came from a post-run memory scan.
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_emulate

    monkeypatch.setattr(
        strat_emulate,
        "emulate_for_flag",
        lambda *a, **k: strat_emulate.EmulateResult(
            ok=True,
            flag="flag{MEMbuilt_42}",
            stdout=b"nothing to see here\n",
            memory_hits=["flag{MEMbuilt_42}"],
        ),
    )
    att = ap._run_strategy("emulate", str(autopwn_samples["memflag"]), None, 30)
    assert att.ok and att.flag == "flag{MEMbuilt_42}"
    assert "recovered from emulated memory" in att.detail
    assert "never printed to stdout" in att.detail
    assert "nothing to see here" in att.detail  # still shown, for context


def test_run_emulate_shows_stdout_when_the_flag_was_actually_printed(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_emulate

    monkeypatch.setattr(
        strat_emulate,
        "emulate_for_flag",
        lambda *a, **k: strat_emulate.EmulateResult(
            ok=True,
            flag="flag{printed}",
            stdout=b"key: nope, wrong key\nflag{printed}\n",
        ),
    )
    att = ap._run_strategy("emulate", str(autopwn_samples["memflag"]), None, 30)
    assert att.ok and att.flag == "flag{printed}"
    assert "recovered from emulated memory" not in att.detail
    assert "stdout=" in att.detail and "flag{printed}" in att.detail


def test_run_emulate_falls_back_to_reason_when_no_stdout_was_captured(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_emulate

    monkeypatch.setattr(
        strat_emulate,
        "emulate_for_flag",
        lambda *a, **k: strat_emulate.EmulateResult(ok=False, reason="unicorn not installed"),
    )
    att = ap._run_strategy("emulate", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert att.detail == "unicorn not installed"
    assert "stdout=" not in att.detail  # nothing fabricated


def test_run_format_string_composes_the_recovered_leak_with_the_no_flag_reason(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_fmt

    monkeypatch.setattr(
        strat_fmt,
        "solve_format_string",
        lambda *a, **k: strat_fmt.FmtResult(
            ok=False,
            leak="7ffee1 400123 7f8a9c",
            reason="started the service and probed %p offsets but saw no flag in the stack leak",
        ),
    )
    att = ap._run_strategy("format_string", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert "leak=" in att.detail and "7ffee1" in att.detail
    assert "probed %p offsets" in att.detail


def test_run_format_string_falls_back_to_reason_when_nothing_was_leaked(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap
    from triage_web.autopwn import strat_fmt

    monkeypatch.setattr(
        strat_fmt,
        "solve_format_string",
        lambda *a, **k: strat_fmt.FmtResult(ok=False, reason="no printf-family call site found"),
    )
    att = ap._run_strategy("format_string", str(autopwn_samples["memflag"]), None, 30)
    assert not att.ok
    assert att.detail == "no printf-family call site found"
    assert "leak=" not in att.detail  # nothing fabricated


def test_solveresult_summary_both_ways():
    from triage_web.autopwn import SolveResult

    good = SolveResult("p", True, "flag{x}", "emulate", 1.2)
    bad = SolveResult("p", False, None, None, 3.4, notes="everything failed")
    assert good.summary().startswith("[+]") and "flag{x}" in good.summary()
    assert bad.summary().startswith("[-]") and "everything failed" in bad.summary()


def test_generate_writeup_renders_a_successful_script_based_solve():
    from triage_web.autopwn.writeup import generate_writeup

    result = {
        "path": "/ctf/samples/ret2win",
        "success": True,
        "flag": "flag{ret2win}",
        "strategy": "ret2win",
        "seconds": 1.4,
        "proof": "from pwn import *\np = process('./ret2win')\np.sendline(b'A' * 40)\n",
        "attempts": [
            {"strategy": "ret2win", "ok": True, "detail": "win=win@0x401176", "flag": "flag{ret2win}"},
        ],
        "notes": "",
        "recon": {
            "arch": "x86_64",
            "bits": 64,
            "format": "ELF",
            "protections": {"nx": "enabled", "pie": "disabled"},
            "plans": [{"name": "ret2win", "score": 80, "why": "win-style function + overflow sink"}],
        },
    }
    md = generate_writeup(result)
    assert md.startswith("# ret2win: autopwn writeup\n")
    assert "`flag{ret2win}`" in md
    assert "Winning strategy: `ret2win`" in md
    assert "x86_64 64-bit ELF" in md
    assert "nx enabled" in md
    assert "win-style function + overflow sink" in md
    assert "```python" in md and "p.sendline" in md
    assert "| ret2win | flag |" in md
    assert "Vulnerability class: stack buffer overflow (ret2win)" in md


def test_generate_writeup_omits_vuln_class_for_an_unknown_strategy():
    from triage_web.autopwn.writeup import generate_writeup

    result = {
        "path": "/ctf/samples/mystery",
        "success": True,
        "flag": "flag{x}",
        "strategy": "some_future_strategy",
        "seconds": 0.1,
        "proof": "",
        "attempts": [],
        "recon": {},
    }
    md = generate_writeup(result)
    assert "Vulnerability class" not in md


def test_generate_writeup_explains_how_the_flag_was_found_without_a_script():
    # keygen/emulate/brute solve by analyzing or simulating the binary, not by
    # attacking a live process — there's no exploit script to show, so this
    # should read as an explanation, not the old "## Recovered parameters"
    # single-line code-block dump (which looked identical for every
    # no-script strategy regardless of what it actually did).
    from triage_web.autopwn.writeup import generate_writeup

    result = {
        "path": "/ctf/samples/keygate",
        "success": True,
        "flag": "flag{keygate}",
        "strategy": "keygen",
        "seconds": 0.3,
        "proof": "key='deadbeef' -> win @ 0x401176",
        "attempts": [],
        "recon": {},
    }
    md = generate_writeup(result)
    assert "## How the flag was found" in md
    assert "## Exploit" not in md
    assert "```python" not in md
    assert "key='deadbeef'" in md


def test_generate_writeup_describes_the_decoded_image_for_smc():
    from triage_web.autopwn.writeup import generate_writeup

    result = {
        "path": "/ctf/samples/packed",
        "success": True,
        "flag": "flag{unwrapped}",
        "strategy": "smc",
        "seconds": 0.5,
        "proof": "/ctf/triage_smc_abcdef.elf",
        "attempts": [],
        "recon": {},
    }
    md = generate_writeup(result)
    assert "## Decoded image" in md
    assert "## Exploit" not in md
    assert "statically decoded" in md
    assert "/ctf/triage_smc_abcdef.elf" in md


def test_generate_writeup_renders_a_no_flag_run():
    from triage_web.autopwn.writeup import generate_writeup

    result = {
        "path": "/ctf/samples/unsolved",
        "success": False,
        "flag": None,
        "strategy": None,
        "seconds": 12.0,
        "proof": "",
        "attempts": [{"strategy": "angr", "ok": False, "detail": "no success state reached", "flag": None}],
        "notes": "angr: no success state reached",
        "recon": {},
    }
    md = generate_writeup(result)
    assert "Solved: no" in md
    assert "`flag{" not in md
    assert "## Exploit" not in md
    assert "| angr | no flag |" in md
    assert "angr: no success state reached" in md


def test_default_writeup_path_sits_next_to_the_target():
    from triage_web.autopwn.writeup import default_writeup_path

    p = default_writeup_path({"path": "/ctf/samples/ret2win"})
    assert p.name == "ret2win-writeup.md"
    assert p.parent.name == "samples"


def test_solve_time_budget_skips_later_strategies(monkeypatch, autopwn_samples):
    import triage_web.autopwn as ap

    monkeypatch.setattr(ap, "_run_strategy", lambda *a, **k: ap.Attempt("x", False, 0.0, "no"))
    monkeypatch.setattr(ap.time, "monotonic", _clock([0, 0, 999, 999, 999, 999]))
    res = ap.solve(str(autopwn_samples["memflag"]), budget_s=1)
    assert any("time budget" in a["detail"] for a in res.attempts)


def test_solve_streams_progress_events(autopwn_samples):
    import triage_web.autopwn as ap

    events: list[dict] = []
    res = ap.solve(str(autopwn_samples["memflag"]), only=["emulate"], budget_s=30, on_event=events.append)

    kinds = [e["kind"] for e in events]
    assert kinds[0] == "recon" and kinds[1] == "plan"
    assert "strategy_start" in kinds and "strategy_done" in kinds
    assert kinds[-1] == "done"
    done = events[-1]["result"]
    assert done["success"] == res.success and done["flag"] == res.flag
    start = next(e for e in events if e["kind"] == "strategy_start")
    assert start["name"] == "emulate" and start["total"] == 1


def test_solve_without_on_event_is_unchanged(autopwn_samples):
    import triage_web.autopwn as ap

    # the callback is optional and must not affect the result
    a = ap.solve(str(autopwn_samples["memflag"]), only=["emulate"], budget_s=30)
    b = ap.solve(str(autopwn_samples["memflag"]), only=["emulate"], budget_s=30, on_event=lambda _e: None)
    assert (a.success, a.flag, a.strategy) == (b.success, b.flag, b.strategy)


def test_solve_carries_recon_and_writes_telemetry(monkeypatch, tmp_path, autopwn_samples):
    import triage_web.autopwn as ap

    log = tmp_path / "results.jsonl"
    monkeypatch.setenv("TRIAGE_RESULTS", str(log))
    res = ap.solve(str(autopwn_samples["memflag"]), only=["emulate"], budget_s=30)
    assert res.recon.get("arch") == "x86_64"  # full static picture rides along
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert rows[-1]["path"].endswith("memflag")
    assert rows[-1]["success"] is True and rows[-1]["strategy"] == "emulate"
    assert rows[-1]["arch"] == "x86_64"


def test_solve_handles_an_unloadable_binary(monkeypatch, tmp_path, autopwn_samples):
    import triage_web.autopwn as ap

    monkeypatch.setenv("TRIAGE_RESULTS", str(tmp_path / "r.jsonl"))

    def _boom(_path, **_kw):
        raise ValueError("mangled section header")

    monkeypatch.setattr(ap, "recon", _boom)
    monkeypatch.setattr(ap, "_run_strategy", lambda *a, **k: ap.Attempt("emulate", False, 0.0, "nope"))
    res = ap.solve(str(autopwn_samples["memflag"]), only=["emulate"], budget_s=10)
    assert not res.success
    assert res.recon["error"].startswith("ValueError:")  # recon failed but solve still returned cleanly


def test_solve_returns_cleanly_when_the_binary_cannot_be_loaded(monkeypatch, tmp_path):
    import triage_web.autopwn as ap

    monkeypatch.setenv("TRIAGE_RESULTS", str(tmp_path / "r.jsonl"))
    # A path that never loads: recon() swallows the error, and solve() must not
    # re-raise it by re-running classify() on the same dead binary.
    res = ap.solve(str(tmp_path / "does-not-exist"), budget_s=5)
    assert not res.success and res.attempts == []
    assert res.recon["error"].startswith("FileNotFoundError:")

    forced = ap.solve(str(tmp_path / "does-not-exist"), only=["emulate"], budget_s=5)
    assert not forced.success and [a["strategy"] for a in forced.attempts] == ["emulate"]


def test_record_swallows_a_write_failure(monkeypatch, tmp_path):
    import triage_web.autopwn as ap

    blocker = tmp_path / "not-a-dir"
    blocker.write_bytes(b"x")  # mkdir(parents=True) under a file → NotADirectoryError (OSError)
    monkeypatch.setenv("TRIAGE_RESULTS", str(blocker / "sub" / "results.jsonl"))
    ap._record(ap.SolveResult("p", False, None, None, 0.1))  # must not raise


def test_summary_failure_line_names_the_notes():
    from triage_web.autopwn import SolveResult

    r = SolveResult("bin", False, None, None, 2.0, notes="angr: no path", attempts=[{"strategy": "angr"}])
    s = r.summary()
    assert s.startswith("[-]") and "angr: no path" in s and "recon" in s


def _clock(values):
    it = iter(values)
    last = [0]

    def _now():
        try:
            last[0] = next(it)
        except StopIteration:
            pass
        return last[0]

    return _now


def test_api_autopwn_recon_requires_a_binary(monkeypatch):
    from triage_web.server import Session

    monkeypatch.setattr(server, "_session", Session())
    assert TestClient(server.app).get("/api/autopwn/recon").status_code == 400
    assert TestClient(server.app).post("/api/autopwn").status_code == 400


def test_api_autopwn_recon_and_solve(autopwn_samples):
    c = TestClient(server.app)
    assert c.post("/api/load", data={"path": str(autopwn_samples["memflag"])}).status_code == 200

    rec = c.get("/api/autopwn/recon").json()
    assert rec["arch"] == "x86_64" and rec["plans"]

    body = c.post("/api/autopwn", params={"strategies": "emulate", "budget_s": 40}).json()
    assert body["success"] and body["flag"] == "flag{MEMbuilt_42}"
    assert body["strategy"] == "emulate"
    assert body["attempts"][0]["strategy"] == "emulate"

    writeup = c.post("/api/autopwn/writeup", json=body).json()["markdown"]
    assert "flag{MEMbuilt_42}" in writeup
    assert "Winning strategy: `emulate`" in writeup


def test_api_autopwn_writeup_is_pure_formatting_no_binary_needed():
    c = TestClient(server.app)
    result = {
        "path": "/x/unsolved",
        "success": False,
        "flag": None,
        "strategy": None,
        "seconds": 1.0,
        "proof": "",
        "attempts": [],
        "notes": "every strategy exhausted",
        "recon": {},
    }
    md = c.post("/api/autopwn/writeup", json=result).json()["markdown"]
    assert "Solved: no" in md
    assert "every strategy exhausted" in md


def test_api_autopwn_stream_emits_sse_progress(autopwn_samples):
    c = TestClient(server.app)
    assert c.post("/api/load", data={"path": str(autopwn_samples["memflag"])}).status_code == 200

    with c.stream("GET", "/api/autopwn/stream", params={"strategies": "emulate", "budget_s": 40}) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        events = [json.loads(line[len("data: ") :]) for line in r.iter_lines() if line.startswith("data: ")]

    kinds = [e["kind"] for e in events]
    assert kinds[0] == "recon" and "strategy_done" in kinds and kinds[-1] == "done"
    assert events[-1]["result"]["flag"] == "flag{MEMbuilt_42}"


def test_api_autopwn_stream_no_flag_carries_the_per_strategy_trace(monkeypatch, tmp_path, autopwn_samples):
    """Drive the real orchestrator (no monkeypatching of solve) through a
    genuine no-flag run and confirm the SSE stream carries the per-strategy
    trace plus a populated notes string on the terminal event (TRACE-01)."""
    monkeypatch.setenv("TRIAGE_RESULTS", str(tmp_path / "r.jsonl"))
    c = TestClient(server.app)
    assert c.post("/api/load", data={"path": str(autopwn_samples["memflag"])}).status_code == 200

    with c.stream("GET", "/api/autopwn/stream", params={"strategies": "ret2win", "budget_s": 40}) as r:
        assert r.status_code == 200
        events = [json.loads(line[len("data: ") :]) for line in r.iter_lines() if line.startswith("data: ")]

    done_events = [e for e in events if e["kind"] == "strategy_done" and e["name"] == "ret2win"]
    assert len(done_events) == 1
    assert done_events[0]["ok"] is False
    assert done_events[0]["detail"]

    terminal = events[-1]
    assert terminal["kind"] == "done"
    result = terminal["result"]
    assert result["success"] is False
    assert result["attempts"]
    assert result["notes"]


def test_api_autopwn_stream_reports_an_orchestrator_crash(monkeypatch, autopwn_samples):
    c = TestClient(server.app)
    assert c.post("/api/load", data={"path": str(autopwn_samples["memflag"])}).status_code == 200

    def _boom(*a, **k):
        raise RuntimeError("orchestrator exploded")

    monkeypatch.setattr("triage_web.autopwn.solve", _boom)
    with c.stream("GET", "/api/autopwn/stream") as r:
        events = [json.loads(line[6:]) for line in r.iter_lines() if line.startswith("data: ")]
    assert events and events[-1]["kind"] == "error" and "orchestrator exploded" in events[-1]["message"]
