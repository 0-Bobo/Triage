"""Shared fixtures for the test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from triage_web.loader import BinaryLoader

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="session")
def sample_path() -> Path:
    """A stripped 64-bit ELF (the original sample)."""
    return SAMPLES / "test_func_pe"


@pytest.fixture(scope="session")
def crackme_path() -> Path:
    """A non-PIE 64-bit ELF with `win`/`check`/`main` symbols and a
    runtime-built ``FLAG{ok}`` (source in samples/src/elf_crackme.c)."""
    return SAMPLES / "elf64_crackme"


@pytest.fixture(scope="session")
def pe_path() -> Path:
    """A 64-bit PE (source in samples/src/pe_hello.c)."""
    return SAMPLES / "pe64_hello.exe"


@pytest.fixture(scope="session")
def vuln_samples() -> dict[str, Path]:
    """Purpose-built ELF fixtures for the exploit-path builder.

    Sources in samples/src/*.c; rebuilt with samples/src/build.sh:
      vuln_pie       PIE, NX on, no canary, has win() + printf() + strcpy()
      vuln_canary    no-PIE, -fstack-protector-all, win() + strcpy()
      vuln_execstack NX off (-z execstack), strcpy() + open()/read()/write()
      vuln_fortify   -O2 -D_FORTIFY_SOURCE=2 (emits __*_chk symbols)
      vuln_rwx       static, one RWX PT_LOAD segment (-Wl,-N)
      nostrings      `int main(){return 0;}` — no unsafe imports
      nostrings_stripped  nostrings + `strip --strip-all`
      nosections     vuln_rwx with the section table removed
    """
    names = (
        "vuln_pie",
        "vuln_canary",
        "vuln_execstack",
        "vuln_fortify",
        "vuln_rwx",
        "nostrings",
        "nostrings_stripped",
        "nosections",
    )
    return {n: SAMPLES / n for n in names}


@pytest.fixture(scope="session")
def autopwn_samples() -> dict[str, Path]:
    """Deterministic targets for the auto-solver (sources in samples/src):
    memflag    x86-64 ELF, builds `flag{MEMbuilt_42}` in a heap buffer, prints nothing
    ret2win    x86-64 ELF, `read()` overflow + win() that puts a flag
    keycheck   x86-64 ELF, fgets + strcmp against "sup3rs3cr3t", prints the flag on match
    keygate    x86-64 ELF, `scanf("%x")` guarded by `k == 0xdeadbeef` → win()
    brute_pin  x86-64 ELF, `scanf("%d")` guarded by `pin == 42` → prints the flag
    smc        x86-64 ELF, raw asm; XOR-0x5a-decodes a payload in an RWE segment at _start
               and jumps into it, which prints the flag via a raw syscall
    uaf_service x86-64 ELF, threaded TCP service; a watcher's malloc'd record (with a
               callback fn ptr) is freed on disconnect but left in a global table, then
               reused and overwritten by a later connection's CREATE, planting an
               attacker-chosen callback+arg that leaks $FLAG to it on the next BID
    arith_check x86-64 ELF, `scanf("%x")` into x, then x^=0x1337; x+=42; x*=3;
               compared against 0x7e before win() - an arithmetic chain, not a
               single constant compare, so it needs z3's dataflow replay
    """
    names = ("memflag", "ret2win", "keycheck", "keygate", "brute_pin", "smc", "uaf_service", "arith_check")
    return {n: SAMPLES / n for n in names}


@pytest.fixture
def loader(sample_path: Path) -> BinaryLoader:
    """A fresh BinaryLoader over the sample ELF, closed on teardown."""
    ldr = BinaryLoader(str(sample_path))
    yield ldr
    ldr.close()
