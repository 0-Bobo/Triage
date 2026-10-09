"""Binary loading, parsing, and analysis — supports ELF and PE formats."""

import hashlib
import logging
import math
import os
import re
import subprocess
from collections import Counter, OrderedDict

from .config import prot_color
from .knowledge import CRYPTO_SIGNATURES, STRING_SIGS

log = logging.getLogger("triage-web")

# ── Optional format parsers ──────────────────────────────────────
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    HAS_PYELFTOOLS = True
except ImportError:
    HAS_PYELFTOOLS = False

try:
    import pefile

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import lief

    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class BinaryLoader:
    """Loads and analyses a binary (ELF or PE) for CTF triage."""

    FMT_ELF = "ELF"
    FMT_PE = "PE"

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.fmt = "Unknown"
        self.arch = "x86_64"
        self.bits = 64
        self.entry_point = 0
        self.file_size = os.path.getsize(path)

        with open(path, "rb") as f:
            self._raw = bytearray(f.read())

        self._elf = self._elf_fh = self._pe = self._lief_bin = None
        self._vaddr_to_offset_cache: dict[int, int] = {}
        self._entropy_cache = None
        self._text_cache = None
        self._hash_cache = None
        self._func_cache = None
        self._section_cache = None
        self._segment_cache = None
        self._import_cache = None
        self._export_cache = None
        self._symbol_cache = None
        self._strings_cache = None
        self._crypto_cache = None
        self._packer_cache = None

        self._detect_format()
        self._load()

    # ── Format detection ────────────────────────────────────────
    def _detect_format(self):
        raw = bytes(self._raw[:4])
        if raw == b"\x7fELF":
            self.fmt = self.FMT_ELF
        elif self._raw[:2] == b"MZ":
            self.fmt = self.FMT_PE

    def _load(self):
        if HAS_LIEF:
            try:
                self._lief_bin = lief.parse(self.path)
            except Exception:
                log.debug("LIEF parse failed for %s", self.path)

        if self.fmt == self.FMT_ELF and HAS_PYELFTOOLS:
            try:
                self._elf_fh = open(self.path, "rb")
                self._elf = ELFFile(self._elf_fh)
                self.entry_point = self._elf.header["e_entry"]
                ei_class = self._elf.header["e_ident"]["EI_CLASS"]
                self.bits = 64 if ei_class == "ELFCLASS64" else 32
                machine_map = {
                    "EM_X86_64": "x86_64",
                    "EM_386": "x86",
                    "EM_ARM": "ARM",
                    "EM_AARCH64": "AArch64",
                    "EM_SPARC": "SPARC",
                    "EM_SPARC32PLUS": "SPARC",
                    "EM_SPARCV9": "SPARC64",
                    "EM_MIPS": "MIPS",
                    "EM_PPC": "PPC",
                    "EM_PPC64": "PPC64",
                    "EM_RISCV": "RISC-V",
                }
                machine = self._elf.header["e_machine"]
                # honest fallback for anything unmapped — never silently claim x86
                self.arch = machine_map.get(machine, str(machine).removeprefix("EM_").lower() or "unknown")
            except Exception as e:
                log.debug("pyelftools parse failed: %s", e)

        elif self.fmt == self.FMT_PE and HAS_PEFILE:
            try:
                self._pe = pefile.PE(self.path)
                self.entry_point = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint + self._pe.OPTIONAL_HEADER.ImageBase
                self.bits = 64 if self._pe.OPTIONAL_HEADER.Magic == 0x20B else 32
                self.arch = "x86_64" if self.bits == 64 else "x86"
            except Exception as e:
                log.debug("pefile parse failed: %s", e)

    def close(self):
        self._clear_caches()
        if self._elf_fh:
            self._elf_fh.close()
        if self._pe is not None:
            try:
                self._pe.close()  # pefile mmaps the file
            except Exception as e:
                log.debug("pefile close failed: %s", e)
        self._elf = self._elf_fh = self._pe = self._lief_bin = None

    # ── Hashing ─────────────────────────────────────────────────
    def hashes(self) -> dict[str, str]:
        if self._hash_cache is not None:
            return self._hash_cache
        # self._raw is a bytearray; hashlib accepts it directly via the buffer
        # protocol, so no need to copy the whole file into a bytes object first
        self._hash_cache = {
            "MD5": hashlib.md5(self._raw).hexdigest(),
            "SHA1": hashlib.sha1(self._raw).hexdigest(),
            "SHA256": hashlib.sha256(self._raw).hexdigest(),
        }
        return self._hash_cache

    # ── Security protections ────────────────────────────────────
    def protections(self) -> OrderedDict:
        flags = OrderedDict(
            [
                ("NX (No-Execute)", "Unknown"),
                ("PIE (ASLR)", "Unknown"),
                ("RELRO", "None"),
                ("Stack Canary", "Unknown"),
                ("Fortify Source", "Unknown"),
                ("RWX Segments", "No"),
            ]
        )

        if self.fmt == self.FMT_ELF and self._elf:
            has_relro = has_bind_now = False
            for seg in self._elf.iter_segments():
                pt = seg["p_type"]
                pf = seg["p_flags"]
                if pt == "PT_GNU_STACK":
                    flags["NX (No-Execute)"] = "Disabled" if (pf & 1) else "Enabled"
                if pt == "PT_GNU_RELRO":
                    has_relro = True
                if pt == "PT_LOAD" and (pf & 7) == 7:
                    flags["RWX Segments"] = "YES — shellcode possible"

            flags["PIE (ASLR)"] = "Enabled" if self._elf.header["e_type"] == "ET_DYN" else "Disabled"

            canary_set = {"__stack_chk_fail", "__stack_chk_guard"}
            for sec in self._elf.iter_sections():
                if hasattr(sec, "iter_tags"):
                    for tag in sec.iter_tags():
                        # legacy tag, plus the DF_BIND_NOW / DF_1_NOW flag bits
                        # that modern GNU ld emits in place of it
                        if tag.entry.d_tag == "DT_BIND_NOW":
                            has_bind_now = True
                        elif tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):
                            has_bind_now = True
                        elif tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):
                            has_bind_now = True
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if sym.name in canary_set:
                            flags["Stack Canary"] = "Enabled"
                        # any _FORTIFY_SOURCE checked wrapper: __printf_chk,
                        # __memcpy_chk, __snprintf_chk, __strcpy_chk, …
                        if sym.name.startswith("__") and sym.name.endswith("_chk"):
                            flags["Fortify Source"] = "Enabled"
            if has_relro:
                flags["RELRO"] = "Full" if has_bind_now else "Partial"

        elif self.fmt == self.FMT_PE and self._pe:
            dc = self._pe.OPTIONAL_HEADER.DllCharacteristics
            flags["NX (No-Execute)"] = "Enabled" if dc & 0x0100 else "Disabled"
            flags["PIE (ASLR)"] = "Enabled" if dc & 0x0040 else "Disabled"

        for k in ("Stack Canary", "Fortify Source"):
            if flags[k] == "Unknown":
                flags[k] = "Disabled"
        return flags

    # ── Strings ─────────────────────────────────────────────────
    def get_strings(self, min_len=4) -> list[str]:
        # The default (and every caller-supplied length >= 4) is served from a
        # cache of the min-length-4 scan: since printable runs are delimited
        # by non-printable bytes regardless of the length threshold, filtering
        # that scan for len(s) >= min_len is bit-identical to re-scanning at
        # min_len. Shorter thresholds fall outside what the cache holds, so
        # they re-scan directly (a rare, near-degenerate input either way).
        if min_len < 4:
            return self._scan_strings(min_len)
        if self._strings_cache is None:
            self._strings_cache = self._scan_strings(4)
        if min_len == 4:
            return self._strings_cache
        return [s for s in self._strings_cache if len(s) >= min_len]

    def _scan_strings(self, min_len: int) -> list[str]:
        try:
            r = subprocess.run(
                ["strings", "-n", str(min_len), self.path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if r.returncode == 0:
                return r.stdout.splitlines()
        except Exception:
            log.debug("strings subprocess failed for %s", self.path)

        # Fallback: decode latin1 and regex
        try:
            decoded = self._raw.decode("latin1")
            return [s.group() for s in re.finditer(rf"[ -~]{{{min_len},}}", decoded)]
        except Exception:
            return []

    # ── Sections ─────────────────────────────────────────────────
    def get_sections(self) -> list[dict]:
        if self._section_cache is not None:
            return self._section_cache
        secs = []
        if self.fmt == self.FMT_ELF and self._elf:
            for s in self._elf.iter_sections():
                secs.append(
                    {
                        "name": s.name or "(null)",
                        "vaddr": s["sh_addr"],
                        "size": s["sh_size"],
                        "flags": s["sh_flags"],
                        "type": s["sh_type"],
                        "offset": s["sh_offset"],
                    }
                )
        elif self.fmt == self.FMT_PE and self._pe:
            base = self._pe.OPTIONAL_HEADER.ImageBase
            for s in self._pe.sections:
                secs.append(
                    {
                        "name": s.Name.decode(errors="replace").rstrip("\x00"),
                        "vaddr": s.VirtualAddress + base,
                        "size": s.Misc_VirtualSize,
                        "flags": s.Characteristics,
                        "type": "",
                        "offset": s.PointerToRawData,
                    }
                )
        self._section_cache = secs
        return secs

    # ── Segments ────────────────────────────────────────────────
    def get_segments(self) -> list[dict]:
        if self._segment_cache is not None:
            return self._segment_cache
        segs = []
        _pt_names = {
            0: "PT_NULL",
            1: "PT_LOAD",
            2: "PT_DYNAMIC",
            3: "PT_INTERP",
            4: "PT_NOTE",
            5: "PT_SHLIB",
            6: "PT_PHDR",
            7: "PT_TLS",
            0x6474E550: "PT_GNU_EH_FRAME",
            0x6474E551: "PT_GNU_STACK",
            0x6474E552: "PT_GNU_RELRO",
            0x6474E553: "PT_GNU_PROPERTY",
        }
        if self.fmt == self.FMT_ELF and self._elf:
            for seg in self._elf.iter_segments():
                pf = seg["p_flags"]
                perm = ("R" if pf & 4 else "-") + ("W" if pf & 2 else "-") + ("X" if pf & 1 else "-")
                pt = seg["p_type"]
                pt_name = _pt_names.get(pt, f"PT_0x{pt:x}") if isinstance(pt, int) else str(pt)
                segs.append(
                    {
                        "type": pt_name,
                        "vaddr": seg["p_vaddr"],
                        "memsz": seg["p_memsz"],
                        "filesz": seg["p_filesz"],
                        "flags": perm,
                    }
                )
        self._segment_cache = segs
        return segs

    # ── Imports ─────────────────────────────────────────────────
    def get_imports(self) -> list[dict]:
        if self._import_cache is not None:
            return self._import_cache
        imps = []
        if self._lief_bin:
            # Build PLT address map: LIEF pltgot_relocations are in PLT order
            plt_relocs = list(getattr(self._lief_bin, "pltgot_relocations", []))
            plt_base = None
            for sec in getattr(self._lief_bin, "sections", []):
                if sec.name == ".plt":
                    plt_base = sec.virtual_address
                    break
            for func in self._lief_bin.imported_functions:
                lib = ""
                try:
                    lib = func.library.name if hasattr(func, "library") and func.library else ""
                except Exception:
                    log.debug("LIEF library attr failed for %s", func.name)
                address = 0
                name = func.name
                # Strip versioned suffix (e.g. malloc@@GLIBC_2.0 → malloc)
                base_name = name.split("@@")[0] if "@@" in name else name
                if plt_base:
                    # First PLT entry (index 0) is the resolver; imports start at index 1
                    for ri, r in enumerate(plt_relocs):
                        rs = r.symbol.name if r.symbol else ""
                        if rs and (rs == name or rs == base_name or rs.split("@@")[0] == base_name):
                            address = plt_base + 0x10 + ri * 0x10
                            break
                imps.append({"name": name, "library": lib, "address": address})
        elif self.fmt == self.FMT_ELF and self._elf:
            for sec in self._elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if sym["st_info"]["type"] == "STT_FUNC" and sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                            imps.append({"name": sym.name, "library": "", "address": 0})
        elif self.fmt == self.FMT_PE and self._pe and hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                lib = entry.dll.decode(errors="replace")
                for i in entry.imports:
                    name = i.name.decode(errors="replace") if i.name else f"ord({i.ordinal})"
                    imps.append({"name": name, "library": lib, "address": 0})
        self._import_cache = imps
        return imps

    # ── Exports ─────────────────────────────────────────────────
    def get_exports(self) -> list[dict]:
        if self._export_cache is not None:
            return self._export_cache
        exps = []
        if self._lief_bin:
            for e in self._lief_bin.exported_functions:
                exps.append({"name": e.name, "address": e.address})
        elif self.fmt == self.FMT_PE and self._pe and hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            base = self._pe.OPTIONAL_HEADER.ImageBase
            for e in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = e.name.decode(errors="replace") if e.name else f"ord({e.ordinal})"
                exps.append({"name": name, "address": e.address + base})
        self._export_cache = exps
        return exps

    # ── Symbols ─────────────────────────────────────────────────
    def get_symbols(self) -> list[dict]:
        if self._symbol_cache is not None:
            return self._symbol_cache
        syms = []
        if self.fmt == self.FMT_ELF and self._elf:
            for sec in self._elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for s in sec.iter_symbols():
                        if s.name:
                            syms.append(
                                {
                                    "name": s.name,
                                    "address": s["st_value"],
                                    "type": s["st_info"]["type"],
                                    "binding": s["st_info"]["bind"],
                                    "size": s["st_size"],
                                }
                            )
        self._symbol_cache = syms
        return syms

    # ── Functions ────────────────────────────────────────────────
    def get_functions(self) -> list[tuple[str, int]]:
        if self._func_cache is not None:
            return self._func_cache
        funcs = []
        named = {}

        if self.fmt == self.FMT_ELF and self._elf:
            for sec in self._elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"]:
                            n = sym.name or f"sub_{sym['st_value']:x}"
                            named[sym["st_value"]] = n
                            funcs.append((n, sym["st_value"]))

        elif self.fmt == self.FMT_PE and self._pe:
            if hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
                for e in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    n = e.name.decode(errors="replace") if e.name else f"sub_{e.address:x}"
                    va = e.address + self._pe.OPTIONAL_HEADER.ImageBase
                    named[va] = n
                    funcs.append((n, va))

        if len(named) < 3 and HAS_CAPSTONE:
            for addr in self._scan_for_functions():
                if addr not in named:
                    named[addr] = f"sub_{addr:x}"
                    funcs.append((f"sub_{addr:x}", addr))

        ep = self.entry_point
        if ep and ep not in named:
            named[ep] = "entry"
            funcs.append(("entry", ep))

        seen, uniq = set(), []
        for n, a in funcs:
            if a not in seen:
                seen.add(a)
                uniq.append((n, a))
        uniq.sort(key=lambda x: x[1])
        self._func_cache = uniq
        return uniq

    def _scan_for_functions(self) -> list[int]:
        if not HAS_CAPSTONE:
            return []
        code, base = self._get_text_section()
        if not code:
            return []
        addrs = set()
        for pat in (b"\x55\x48\x89\xe5", b"\x55\x89\xe5", b"\x48\x83\xec"):
            idx = 0
            while True:
                idx = code.find(pat, idx)
                if idx < 0:
                    break
                addrs.add(base + idx)
                idx += 1
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64 if self.bits == 64 else CS_MODE_32)
            for i in md.disasm(code[: min(len(code), 512 * 1024)], base):
                if i.mnemonic.lower() in ("call", "callq") and i.op_str:
                    try:
                        t = int(i.op_str.strip(), 16)
                        if base <= t < base + len(code):
                            addrs.add(t)
                    except Exception:
                        log.debug("call target parse failed in _scan_for_functions")
        except Exception:
            log.debug("capstone scan failed in _scan_for_functions")
        return sorted(addrs)

    def _get_text_section(self) -> tuple[bytes, int]:
        if self._text_cache is not None:
            return self._text_cache
        if self.fmt == self.FMT_ELF and self._elf:
            # Prefer .text; fall back to .plt or text
            for sec in self._elf.iter_sections():
                if sec.name == ".text" or sec.name == "text":
                    d = sec.data()
                    if d:
                        self._text_cache = (d, sec["sh_addr"])
                        return self._text_cache
            for seg in self._elf.iter_segments():
                if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 1):
                    self._text_cache = (seg.data(), seg["p_vaddr"])
                    return self._text_cache
        elif self.fmt == self.FMT_PE and self._pe:
            for sec in self._pe.sections:
                if sec.Characteristics & 0x20000000:
                    base = self._pe.OPTIONAL_HEADER.ImageBase
                    self._text_cache = (sec.get_data(), base + sec.VirtualAddress)
                    return self._text_cache
        self._text_cache = (bytes(self._raw), 0)
        return self._text_cache

    # ── Address translation ─────────────────────────────────────
    def vaddr_to_offset(self, vaddr: int) -> int:
        """Map a virtual address to a raw file offset (-1 if unmapped).

        Memoised per instance — a module-level lru_cache would keep every
        BinaryLoader alive for the life of the process.
        """
        cached = self._vaddr_to_offset_cache.get(vaddr)
        if cached is not None:
            return cached
        offset = self._compute_vaddr_to_offset(vaddr)
        self._vaddr_to_offset_cache[vaddr] = offset
        return offset

    def _compute_vaddr_to_offset(self, vaddr: int) -> int:
        if self.fmt == self.FMT_ELF and self._elf:
            for seg in self._elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    sv = seg["p_vaddr"]
                    end = sv + seg["p_filesz"]
                    if sv <= vaddr < end:
                        return seg["p_offset"] + (vaddr - sv)
        elif self.fmt == self.FMT_PE and self._pe:
            base = self._pe.OPTIONAL_HEADER.ImageBase
            for sec in self._pe.sections:
                sv = sec.VirtualAddress + base
                if sv <= vaddr < sv + sec.SizeOfRawData:
                    return sec.PointerToRawData + (vaddr - sv)
        return -1

    def read_vaddr(self, vaddr: int, size: int) -> bytes:
        if size <= 0:
            return b""
        off = self.vaddr_to_offset(vaddr)
        if off < 0:
            return b""
        # Clamp to what's actually in the file rather than failing the whole read
        return bytes(self._raw[off : off + size])

    def read_offset(self, offset: int, size: int) -> bytes:
        """Read `size` bytes starting at a raw file offset (clamped to EOF)."""
        if size <= 0 or offset < 0 or offset >= len(self._raw):
            return b""
        return bytes(self._raw[offset : offset + size])

    # ── Entropy ─────────────────────────────────────────────────
    @staticmethod
    def compute_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        n = len(data)
        # Counter's frequency count runs in C, unlike a per-byte Python loop
        # over a 256-slot table; only byte values that actually occur end up
        # as keys, which is equivalent to skipping the zero-frequency slots
        # the old loop's `if p > 0` guard filtered out.
        return -sum(p * math.log2(p) for count in Counter(data).values() if (p := count / n) > 0)

    # ── Crypto detection ─────────────────────────────────────────
    def detect_crypto(self) -> list[tuple[str, int]]:
        if self._crypto_cache is not None:
            return self._crypto_cache
        results = []
        # self._raw is already a bytearray — .find() works directly on it, no
        # need for a transient full-file bytes() copy
        for name, sig in CRYPTO_SIGNATURES.items():
            idx = self._raw.find(sig)
            if idx >= 0:
                results.append((name, idx))
        self._crypto_cache = results
        return results

    # ── Packer detection ─────────────────────────────────────────
    def detect_packer(self) -> list[str]:
        if self._packer_cache is not None:
            return self._packer_cache
        hits = []
        for packer, sigs in STRING_SIGS.items():
            if any(sig.encode() in self._raw for sig in sigs):
                hits.append(packer)
        self._packer_cache = hits
        return hits

    # ── Summary info ─────────────────────────────────────────────
    def get_info(self) -> dict:
        h = self.hashes()
        prot = self.protections()
        return {
            "path": self.path,
            "filename": os.path.basename(self.path),
            "size": self.file_size,
            "format": self.fmt,
            "arch": self.arch,
            "bits": self.bits,
            "entry_point": hex(self.entry_point),
            "hashes": h,
            "protections": {k: {"value": v, "color": prot_color(v)} for k, v in prot.items()},
            "function_count": len(self.get_functions()),
            "import_count": len(self.get_imports()),
            "export_count": len(self.get_exports()),
            "symbol_count": len(self.get_symbols()),
            "section_count": len(self.get_sections()),
            "crypto": [{"name": n, "offset": hex(o)} for n, o in self.detect_crypto()],
            "packers": self.detect_packer(),
        }

    # ── Cache management ────────────────────────────────────────
    def _clear_caches(self):
        self._vaddr_to_offset_cache.clear()
        self._entropy_cache = None
        self._text_cache = None
        self._hash_cache = None
        self._func_cache = None
        self._section_cache = None
        self._segment_cache = None
        self._import_cache = None
        self._export_cache = None
        self._symbol_cache = None
        self._strings_cache = None
        self._crypto_cache = None
        self._packer_cache = None
