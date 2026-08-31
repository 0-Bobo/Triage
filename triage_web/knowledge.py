"""Static knowledge bases: vulnerability patterns, MITRE data, exploit techniques,
crypto signatures, packer signatures, and MITRE ATT&CK mappings."""

# ── Vulnerability Patterns ─────────────────────────────────────────
VULN_PATTERNS = {
    "gets": ("CRITICAL", "Unbounded stack write", "Use fgets(buf, sz, stdin)"),
    "strcpy": ("HIGH", "Unbounded string copy", "Use strncpy or strlcpy"),
    "strcat": ("HIGH", "Unbounded string concat", "Use strncat"),
    "sprintf": ("HIGH", "Unbounded format write", "Use snprintf"),
    "scanf": ("HIGH", "Unbounded input", "Use %255s width limiter"),
    "vsprintf": ("HIGH", "Unbounded format write", "Use vsnprintf"),
    "printf": ("MEDIUM", "Potential format string", "Ensure no user-controlled format arg"),
    "system": ("HIGH", "Shell injection risk", "Avoid; use execve with fixed args"),
    "popen": ("HIGH", "Shell injection risk", "Sanitize all arguments"),
    "exec": ("HIGH", "Code execution", "Validate all arguments strictly"),
    "malloc": ("LOW", "Heap allocation", "Check for use-after-free / double-free"),
    "free": ("LOW", "Heap deallocation", "Ensure no double-free or UAF"),
    "memcpy": ("MEDIUM", "Unbounded memory copy", "Always validate size parameter"),
    "memmove": ("MEDIUM", "Memory overlap", "Verify size and pointers"),
    "strtok": ("LOW", "Not thread-safe", "Use strtok_r"),
    "rand": ("LOW", "Weak RNG", "Use getrandom() or /dev/urandom"),
    "srand": ("LOW", "Predictable seed", "Seed from high-entropy source"),
    "setuid": ("MEDIUM", "Privilege escalation path", "Check return value"),
    "chmod": ("MEDIUM", "File permission change", "Validate path and mode"),
    "unlink": ("MEDIUM", "File deletion", "TOCTOU risk — use unlinkat"),
    "read": ("LOW", "Check return value", "Partial reads possible"),
    "write": ("LOW", "Check return value", "Partial writes possible"),
    "open": ("LOW", "File access", "Check for path traversal"),
    "dlopen": ("MEDIUM", "Dynamic library load", "Validate path; hijacking risk"),
    "signal": ("LOW", "Async signal handler", "Ensure async-signal-safe functions"),
    "longjmp": ("MEDIUM", "Non-local jump", "Stack state may be inconsistent"),
    "alloca": ("MEDIUM", "Stack allocation — no bounds check", "Use malloc for large sizes"),
}

# ── MITRE ATT&CK mappings for individual vulnerable functions ─────
MITRE_VULN_MAP = {
    "gets": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": "gets() reads unbounded input into a fixed-size stack buffer. Attacker overwrites saved RBP + RIP. With NX disabled: place shellcode on stack. With NX+no canary: ROP chain. With canary: leak via adjacent read primitive first.",
    },
    "strcpy": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": 'strcpy(dst, src) copies until null byte with no bound check. Stack pivot via ROP: find a "leave; ret" gadget to pivot stack to controlled buffer. Use ret2csu or ret2plt for complex chains.',
    },
    "strcat": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": "strcat() appends without length check. If the destination already contains data, the concat can overflow past the buffer end. Often exploitable with partial overwrites.",
    },
    "sprintf": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": "sprintf(buf, fmt, ...) with large output overflows buf. Also check format string control — if attacker controls the format argument, %n gives write-what-where.",
    },
    "scanf": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": 'scanf("%s", buf) reads unbounded input, classic stack overflow. Use width specifier "%255s" to prevent, but many binaries omit it.',
    },
    "vsprintf": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": "vsprintf() is the va_list variant — still unbounded. Use vsnprintf() instead. Exploitation same as sprintf OOB write.",
    },
    "printf": {
        "tactic": "TA0004",
        "tid": "T1068",
        "exploit_path": "Format string bug if attacker controls the format string. Stage 1: %p chain to leak canary/PIE/stack. Stage 2: %n writes to overwrite GOT entry (e.g., printf@got -> system@plt). If RELRO full, overwrite __libc_argv or stack return address.",
    },
    "system": {
        "tactic": "TA0002",
        "tid": "T1204",
        "exploit_path": 'system() with attacker-controlled argument = command injection. Find a controlled string (user input, file read) and chain to it via RDI gadget. ret2libc: find "pop rdi; ret" gadget, load address of "/bin/sh", call system@plt.',
    },
    "popen": {
        "tactic": "TA0002",
        "tid": "T1204",
        "exploit_path": "popen(cmd, mode) spawns /bin/sh -c cmd. If attacker controls the cmd string, full shell injection. Same ret2libc strategy as system(), but need both a command string and the popen PLT entry.",
    },
    "exec": {
        "tactic": "TA0002",
        "tid": "T1204",
        "exploit_path": "execve() family — if attacker controls argv, arbitrary code execution. Common CTF: ret2exec to spawn shell with controlled args.",
    },
    "malloc": {
        "tactic": "TA0004",
        "tid": "T1203",
        "exploit_path": "Heap exploitation: tcache poisoning (modify tcache->next to point to __free_hook), fastbin dup (double-free fastbin to same address), unsafe unlink (craft fake chunk to overwrite a pointer). Modern: house of force, house of orange, house of einherjar.",
    },
    "free": {
        "tactic": "TA0004",
        "tid": "T1203",
        "exploit_path": "Double-free: free same chunk twice, tcache dup, fastbin dup. tcache: free() sets tcache->next = chunk, so second free() on same chunk creates a cycle. Alloc twice to get overlapping allocations — write to arbitrary address.",
    },
    "memcpy": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": "memcpy(dst, src, n) with attacker-controlled n causes heap/stack OOB write. Heap overflow: corrupt adjacent chunk metadata or overwrite function pointer in next chunk.",
    },
    "read": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": "read(fd, buf, n) with partial read — attacker may send less than n bytes, leading to subsequent logic using uninitialized stack data. Check error handling and return values.",
    },
    "setuid": {
        "tactic": "TA0004",
        "tid": "T1068",
        "exploit_path": "setuid(0) without dropping privs — if the process retains capabilities, an attacker who gains code execution can escalate to full root via privilege-preserving execve().",
    },
    "dlopen": {
        "tactic": "TA0005",
        "tid": "T1574",
        "exploit_path": "dlopen() with relative path: LD_PRELOAD-style hijack. If path is attacker-writable, inject malicious .so. If path comes from user input, directory traversal to load arbitrary shared object.",
    },
    "longjmp": {
        "tactic": "TA0004",
        "tid": "T1203",
        "exploit_path": "longjmp(env, val) after stack corruption — env buffer may have been overwritten, causing jump to attacker-controlled address. Equivalent to arbitrary control flow hijack.",
    },
    "alloca": {
        "tactic": "TA0004",
        "tid": "T1212",
        "exploit_path": "alloca(n) with attacker-controlled n causes stack pointer arithmetic overflow or stack exhaustion. Integer overflow in n can make alloca allocate a tiny buffer, then subsequent writes overflow.",
    },
}

# ── Exploit Technique Descriptions ────────────────────────────────
EXPLOIT_TECHNIQUES = [
    {
        "technique": "Stack Buffer Overflow (gets/strcpy/scanf)",
        "detail": "Overwrite saved RIP on stack. Primary primitive: unbounded write to stack buffer. "
        'Required gadgets: "pop rdi; ret" (ret2libc), "leave; ret" (stack pivot). '
        "Bypass canary via format string leak first. Bypass PIE via partial overwrite or info leak. "
        "With NX off, place shellcode at known stack address. With NX on, chain ROP gadgets to call mprotect() or ret2libc/system.",
        "mitre_id": "T1212",
        "tactic": "TA0004",
    },
    {
        "technique": "Format String (printf/sprintf)",
        "detail": "Arbitrary read via %p/%x/%s — leak canary, PIE base, stack addresses, libc addresses. "
        "Arbitrary write via %n — write controlled value at any writable address. "
        "Full RELRO bypass: overwrite __malloc_hook, __free_hook, or _IO_list_all instead of GOT. "
        "Modern bypass: overwrite __stack_chk_fail (catches failed canaries) or __libc_argv.",
        "mitre_id": "T1068",
        "tactic": "TA0004",
    },
    {
        "technique": "ret2libc / ret2system",
        "detail": 'Controlled RDI to "/bin/sh" string, then call system@plt. '
        'Step 1: find "pop rdi; ret" gadget in binary or libc. '
        "Step 2: locate /bin/sh string in libc (offset known from libc base). "
        "Step 3: find system() address from libc (offset from leaked address). "
        'Chain: [pop_rdi_ret] [binsh_addr] [system_addr]. If no system, use execve(ptr to "/bin/sh", 0, 0).',
        "mitre_id": "T1204",
        "tactic": "TA0002",
    },
    {
        "technique": "Heap Exploitation (malloc/free)",
        "detail": "tcache poisoning: free chunk into tcache, overwrite its next pointer → next alloc returns arbitrary address. "
        "Fastbin dup: double-free fastbin chunk, allocate twice to same address. "
        "Unsafe unlink: craft fake chunk in controlled region, unlink() overwrites ptr with ptr-0x18 → write primitive. "
        "House of force (older libc): overwrite top chunk size, request huge allocation to return arbitrary address. "
        "Modern heap: __free_hook overwrite → system() on next free() with controlled argument.",
        "mitre_id": "T1203",
        "tactic": "TA0004",
    },
    {
        "technique": "Shellcode Injection (NX disabled)",
        "detail": "Place shellcode on stack or in .bss/data, then jump to it. "
        "Use msfvenom -p linux/x64/exec CMD=/bin/sh or pwntools shellcraft.sh(). "
        "Find JMP RSP gadget in binary (0xff 0xe4) for stack-based shellcode. "
        "If ASLR interferes, use NOP sled (0x90 repeated) before shellcode. "
        "Alternative: mprotect() to make heap executable via ROP, then jump there.",
        "mitre_id": "T1059.006",
        "tactic": "TA0002",
    },
    {
        "technique": "Integer Overflow / Off-by-One",
        "detail": "Off-by-one (common in loop boundary off-by-errors): overwrite LSB of adjacent chunk size or saved RBP. "
        "Null byte off-by-one: poison adjacent chunk prev_in_use bit. "
        "Integer overflow: large allocation wraps to small buffer, subsequent write overflows heap. "
        "Signedness bugs: negative size passes len check (len > 0) but causes out-of-bounds read in memcpy.",
        "mitre_id": "T1212",
        "tactic": "TA0004",
    },
    {
        "technique": "Use-After-Free / Type Confusion",
        "detail": "UAF: free chunk still referenced via dangling pointer → allocate same size to get controlled data at the old object. "
        "Overwrite function pointer in freed object → hijack control flow on next method call. "
        "Type confusion: cast object to unrelated type → interpret field as different type → forge pointer or bypass check. "
        "Common in C++ virtual dispatch: overwrite vtable pointer to attacker-controlled table.",
        "mitre_id": "T1203",
        "tactic": "TA0004",
    },
]

# ── Crypto Signatures ─────────────────────────────────────────────
CRYPTO_SIGNATURES = {
    "AES S-box": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]),
    "AES inv S-box": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38]),
    "SHA-256 K0": bytes([0x98, 0x2F, 0x8A, 0x42]),
    "MD5 magic": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
    "RC4 KSA": b"KSA",
    "zlib": bytes([0x78, 0x9C]),
    "gzip": bytes([0x1F, 0x8B]),
    "bzip2": bytes([0x42, 0x5A, 0x68]),
}

# ── Packer / Runtime String Signatures ────────────────────────────
STRING_SIGS = {
    "PyInstaller": ["_MEIPASS", "pyi-", "PKG-0000"],
    "Golang": ["runtime.main", "go.buildid"],
    "UPX": ["UPX!", "This file is packed with the UPX executable packer"],
    ".NET": ["mscoree.dll", "_CorExeMain"],
    "Nim": ["NimMain", "nim_program_result"],
    "Rust": ["rust_begin_unwind", "__rust_alloc"],
}

# ── MITRE ATT&CK broad mapping ────────────────────────────────────
MITRE_MAP = {
    "execution": ("TA0002", "T1106", "Native API — direct syscall execution"),
    "process": ("TA0002", "T1059", "Command and Scripting Interpreter"),
    "anti-analysis": ("TA0005", "T1027", "Obfuscated Files or Information"),
    "anti-behavioral": ("TA0005", "T1027.002", "Software Packing / obfuscation"),
    "anti-static": ("TA0005", "T1027.001", "Binary Padding / stripped symbols"),
    "persistence": ("TA0003", "T1547", "Boot or Logon Autostart Execution"),
    "defense-evasion": ("TA0005", "T1055", "Process Injection"),
    "privilege-escalation": ("TA0004", "T1068", "Exploitation for Privilege Escalation"),
    "credential-access": ("TA0006", "T1003", "OS Credential Dumping"),
    "discovery": ("TA0007", "T1082", "System Information Discovery"),
    "lateral-movement": ("TA0008", "T1021", "Remote Services"),
    "collection": ("TA0009", "T1005", "Data from Local System"),
    "exfiltration": ("TA0010", "T1041", "Exfiltration Over C2 Channel"),
    "command-and-control": ("TA0011", "T1071", "Application Layer Protocol"),
    "impact": ("TA0040", "T1486", "Data Encrypted for Impact"),
    "cryptography": ("TA0040", "T1027.013", "Encrypted/Encoded File (custom crypto)"),
    "file-system": ("TA0007", "T1083", "File and Directory Discovery"),
    "network": ("TA0011", "T1095", "Non-Application Layer Protocol"),
    "heap": ("TA0005", "T1055.012", "Process Hollowing / heap spray"),
    "injection": ("TA0005", "T1055", "Process Injection"),
    "obfuscation": ("TA0005", "T1027", "Obfuscated Code"),
    "packer": ("TA0005", "T1027.002", "Software Packing"),
    "socket": ("TA0011", "T1095", "Non-Application Layer Protocol"),
    "dns": ("TA0011", "T1071.004", "DNS Application Layer Protocol"),
    "http": ("TA0011", "T1071.001", "Web Protocols"),
    "registry": ("TA0003", "T1547.001", "Registry Run Keys / Startup Folder"),
    "service": ("TA0003", "T1543", "Create or Modify System Process"),
    "shellcode": ("TA0005", "T1059.006", "Shellcode / native execution"),
    "rop": ("TA0005", "T1203", "Exploitation for Client Execution (ROP)"),
    "format-string": ("TA0004", "T1203", "Exploitation — Format String"),
    "buffer-overflow": ("TA0004", "T1203", "Exploitation — Stack Buffer Overflow"),
    "use-after-free": ("TA0004", "T1203", "Exploitation — Use After Free"),
    "heap-overflow": ("TA0004", "T1203", "Exploitation — Heap Overflow"),
    "lib": ("TA0005", "T1129", "Shared Modules"),
    "compiler": ("TA0005", "T1027", "Compiler/runtime artifacts"),
    "string": ("TA0005", "T1027.005", "Indicator Removal / string obfuscation"),
    "allocate": ("TA0005", "T1055.001", "DLL Injection / dynamic allocation"),
    "send": ("TA0011", "T1041", "Exfiltration Over C2 Channel"),
    "recv": ("TA0011", "T1071", "Application Layer Protocol — recv"),
}
