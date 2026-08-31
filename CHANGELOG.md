# Changelog

## [Unreleased] — Pseudo-C Decompiler

### Added
- `decompile_function()` — full pseudo-C decompilation engine in `engine.py`
- `/api/disasm/decompile` HTTP endpoint in `server.py`
- Code panel UI with toggle buttons in `frontend.py`
- Syntax highlighting for pseudo-C keywords in `showCodeFunction()`
- `_get_call_args()` — dual-path argument collector (register ABI + stack-based) for call instructions
- `_update_reg_state()` — register value tracking through instructions with stack variable resolution
- `_find_ret_value()` — detects return value from eax/rax register at function exit
- `_insn_to_c()` — translates individual instructions to C-like expressions
- `_match_strlen_idiom()` — detects `repne scasb; not ecx; dec ecx` pattern → `strlen()`
- `_reg_val()` — register alias resolution (eax ↔ rax, ebx ↔ rbx, etc.) for capstone naming
- `_clear_caller_regs()` — ABI-compliant register clobbering after function calls
- Version suffix stripping (`@GLIBC_2.0`, `@@GLIBC_2.0`) from call names
- Stack variable type inference (`_guess_var_type()`)
- Prologue skipping (push rbp, mov rbp rsp, push rdi, stack alignment)
- `leave`/`nop`/`endbr64`/`endbr32` suppression in C output
- `result_of` set-once heuristic to prevent variable name overwrite from later reads

### Fixed
- **All `[base+offset]` regexes** (9 locations): switched `re.match` → `re.search` with `\s*` whitespace flexibility to handle capstone's `[rsp + 0x2c]` format
- **_get_call_args()** `is_64` branching: rewritten to try both register ABI and stack-based collection regardless of `is_64` flag
- **_get_call_args()**: reverse-order stack arg collection limited to 6 instructions with call boundary detection — prevents stale args from spilling across calls
- **_get_call_args()**: added `rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9` to push filter list to prevent prologue register saves from being treated as stack args
- **_update_reg_state()**: added base-register check before resolving `[rax + N]` to `stack_vars` (prevents `[rax+4]` from being matched to a `rsp+4` stack variable)
- **Prologue detection**: handles `push rdi` (stack alignment), `and esp, -16` (alignment), fixed operator-precedence bug in conditional chain
- **`is_local` check**: now includes `rsp`/`sp` for 64-bit register name output from capstone
- **Register alias propagation**: `_reg_val()` lookup tries both `eax` and `rax`/`ecx` and `rcx`/etc. to handle capstone's mixed 32/64-bit register naming
- **Variable naming**: `mov eax, [rsp+N]` correctly resolves to `heap_ptr` (not `puts@_res`) via `_update_reg_state`
- **_find_ret_value()** — checks both `eax` and `rax` (capstone naming inconsistency)
- **Main loop**: converted `for` → `while` loop to support multi-instruction idiom skipping (strlen pattern)
- **`_insn_to_c()`**: pointer dereferences (`*rax`, `rax[4]`) no longer wrongly map to offset-matched stack variables — base register must be `rsp`/`esp`/`rbp`/`ebp`
- **Function boundary detection**: main loop now `break`s after `ret` instruction to prevent adjacent function code from leaking into output
- **Prologue skip**: added `endbr64`/`endbr32` to recognized prologue instructions so `sub rsp, N` isn't emitted as `rsp -= N;`
- **_get_call_args() register ABI scan**: changed from forward to backward iteration, with call boundary detection — prevents register arg data from spilling across function calls
- **_get_call_args() register ABI scan**: added 32-bit register name mapping (`edi`→`rdi`, `esi`→`rsi`, `edx`→`rdx`) so both `mov edi, N` and `mov rdi, N` set up the correct arg register
- **`call_arg_ranges` first pass**: mov instructions are only marked when destination is an argument register (`rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9` or 32-bit variants) — prevents constant loads to scratch registers like `movabs rcx, 0x...` from being hidden as arg setup
- **`_clear_caller_regs()`**: now clears all 32-bit register variants (`esi`, `edi`, `r8d`, etc.) that capstone may use, not just 64-bit names — fixes ghost arg values leaking across calls
- **`_insn_to_c()` and `_update_reg_state()`**: added `movabs` alongside `mov` — `movabs rcx, 0x...` now renders as `reg = value;` instead of `/* movabs ... */`
- **Return value inlining**: after `call malloc`, if the next instruction stores `eax`/`rax` to a known stack variable, emits `heap_ptr = malloc(...);` instead of `malloc(...);` + `heap_ptr = rax;` — works for both 64-bit register ABI and 32-bit stack-based args

### Known Limitations
- Function name defaults to `func_XXXXXXXX` (needs `loader.get_functions()` integration)
- No `repne cmpsb` → `memcmp()` idiom detection yet
- Register ABI scan resolves `mov rdi, rax` to `heap_ptr` when rax holds a tracked value, but intermediate register-to-register moves are still shown (e.g. `heap_ptr = rax;` instead of `heap_ptr = malloc(24);`)
- No string literal resolution for immediate constants (e.g. `0x3430392d47414c46` shown instead of `"FLAG-904"`)
- No instruction-level comments in C output (e.g. no `// heap_ptr = malloc(24)` annotations)
