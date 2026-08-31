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


@pytest.fixture
def loader(sample_path: Path) -> BinaryLoader:
    """A fresh BinaryLoader over the sample ELF, closed on teardown."""
    ldr = BinaryLoader(str(sample_path))
    yield ldr
    ldr.close()
