# Engineering notes

[`ARCHITECTURE.md`](ARCHITECTURE.md) is the map: what lives where. This is the other half: why
the pieces that matter are built the way they are, including the paths that
were tried and dropped. Six subsystems, each picked because it involved a
real decision with a real alternative, not because it was the biggest file.

## 1. Two decompilers, one of them shipped

Turning a disassembly listing into readable pseudo-C is the hard problem
this tool solves twice, on purpose.

**What ships** (`engine.py::decompile_function`) is a single linear pass
over Capstone's instruction list. Each instruction is matched against a
small set of string/regex patterns on its mnemonic and operand text
(`_insn_to_c`), register state is tracked in a plain dict, and a lightweight
`SSAMemory` cache remembers the last value stored to a given stack slot so a
later reload can reuse the original expression instead of re-reading a raw
register name. It is not real SSA despite the name; it is store-forwarding
over a dict, which is all the shipped decompiler needs.

**What doesn't ship** is a second, structurally different pipeline built
from the same primitives Ghidra uses internally:

- `pcode.py` lifts Capstone instructions into a generic p-code IR (opcodes
  1-74, mirroring Ghidra's `CPUI_*` enumeration) so every later pass works
  on one representation regardless of source architecture.
- `cfg.py` partitions that IR into basic blocks and computes dominance.
  The docstring says Lengauer-Tarjan; the actual implementation is the
  simpler Cooper-Harvey-Kennedy iterative fixed-point algorithm, O(n²)
  worst case. That's a deliberate downgrade from the paper it's named
  after: real Lengauer-Tarjan needs DFS numbering, semidominators, and a
  union-find with path compression to hit near-linear time, and CTF
  binaries are small enough that the O(n²) version is never the
  bottleneck. The simpler algorithm is also something a reviewer can
  verify by hand in one sitting; the real one isn't.
- `ssa_engine.py` places phi nodes at dominance frontiers and renames
  variables via a dominator-tree walk, the textbook Cytron et al. (1991)
  construction, not a shortcut.
- `decompile_actions.py` runs a Ghidra-shaped action pipeline in phases:
  dead-code elimination and constant/copy propagation first, then
  control-flow cleanup, then type recovery, then naming, each action
  optionally repeating to a fixed point.
- `cfg.py`'s `CFGStructurer` pattern-matches the now-simplified graph back
  into if/else, while, and switch shapes instead of leaving raw gotos.
- `emit_c.py` walks the structured blocks and prints C, with an explicit
  operator-precedence table (so it parenthesizes only when actually
  needed) and a De Morgan negation table so an if-with-no-else renders as
  `if (cond)` instead of `if (!!cond)` or an inverted mess.

Both pipelines exist in the same file tree, and there's even a method,
`decompile_with_pcode_demo`, that runs the target through both and prints
them side by side for comparison. The string-matching decompiler ships
because it's good enough for CTF-sized functions and has a test suite that
holds it at 100% coverage. The p-code pipeline is architecturally the more
correct of the two (it reasons about control flow structurally, not by
pattern-matching text), but it isn't wired into any HTTP route, and the
`strat_*`/pcode modules are excluded from the coverage gate on purpose. It
stays on the bench rather than becoming the default, because swapping a
decompiler that already works for one that's "more correct" but less
battle-tested is exactly the kind of change this project's own
contributing rules say to avoid without a regression suite to match.

One honest gap: `decompile_with_pcode`'s own exception handler discards
whatever C the generator had already emitted before a mid-structuring
crash, returning only `// p-code error: <e>`. That's a real bug in the
unwired path's error handling, left unaddressed because the pipeline it's
in has no live caller to hit it.

## 2. Catching the disassembler's own blind spot

A linear disassembler reads bytes left to right and trusts that the next
byte it sees is the start of the next real instruction. A classic
anti-reversing trick breaks that assumption on purpose: `eb 01` (an
unconditional short jump) or `74 01`/`75 01` (a conditional one) followed by
one junk byte, where the jump's target lands exactly one byte past that
junk byte. A disassembler that doesn't take the jump decodes the junk byte
as if it were a real instruction and desyncs every instruction after it.

`_disassemble_skip_junk` handles this by checking, after every instruction
it decodes, whether that instruction was exactly a two-byte short jump
whose opcode is in the `0x70-0x7f` or `0xeb` range with a one-to-six-byte
gap to its target. If so, it jumps straight to the real target and skips
the junk byte entirely, whether or not the jump is conditional (the
fall-through path still lands past the junk either way). Anything that
doesn't decode at all gets stepped over one byte at a time until the
stream resyncs, instead of giving up on the rest of the function.

## 3. autopwn: a ranked plan with a budget, not a decision tree

Nine exploitation strategies exist (`smc`, `keygen`, `emulate`, `z3`,
`ret2win`, `uaf`, `format_string`, `angr`, `brute`), and most binaries only
match a handful of them. The registry (`autopwn/registry.py`) builds one
`StaticView` per binary (imports, function names, strings, detected win
functions, capa capability tags) and runs it through nine independent
scorer functions, each returning `(priority, rationale)` or `None`. `plan()`
keeps whatever scored and sorts by priority; the orchestrator runs them in
that order against a shared time budget, and every attempt's recovered
detail is kept even when the run itself doesn't produce a flag.

That shape over a hardcoded decision tree is a specific choice: a tree
commits to a branch early and can't revise as more evidence (a capa hit
after the fact) comes in, and growing a tree means editing a shared
if/elif chain shared by every binary shape. Each scorer here is small,
independent, and testable on its own; adding a tenth strategy is "write
`strat_foo.py`, append one `Strategy(...)` to a list" with no edit to
anything else. `smc`'s scorer shows the cross-check this buys: a static
heuristic hit (a trashed ELF header, a writable+executable segment) scores
90 on its own; a capa-only hit with no static signal scores 62, high enough
to try but clearly below the "this is obviously it" case. Neither signal
fully gates the other.

The heavy backends (`angr`, `z3`, `unicorn`, `pwntools`) are imported
inside each strategy's own `_run_*` function, never at module load, so
asking for a recon-only plan or opening the Status panel never pays the
cost of importing five optional packages it isn't going to use.

## 4. The sandbox: verify the tool works, don't trust that it's installed

Every target binary and every generated exploit script this tool runs is
untrusted by definition: a CTF binary is adversarial by construction, and a
generated script embeds parameters pulled out of that same binary. `runner.py`
wraps both in whichever isolation tool is actually available, preferring
`bwrap` (full namespace unshare, read-only root, private `/tmp`, no network
by default) over `unshare` (a new user+network namespace, lighter but less
isolated) when both are present.

The isolation probe doesn't just check whether `bwrap`/`unshare` exist on
`PATH`. It runs each one as a real, minimal invocation and keeps only the
ones that actually exit 0, because a locked-down host (a CI runner, some
container setups) can ship `unshare` while forbidding the unprivileged user
namespaces it needs, and `command -v unshare` would say yes right before the
real run fails. That probe result is cached once per process rather than
re-run on every target.

Two network policies cover two different needs: `net=False` is the default,
a fully offline sandbox for strategies that just need to run a static
self-check (`emulate`, `keygen`, `ret2win`'s self-test). `net=True` brings up
loopback only, for the handful of strategies (`uaf`, `format_string`) whose
self-test is a client and server that have to talk to each other but never
need a route off the host. `TRIAGE_SANDBOX=off`/`=strict` exist as an
explicit escape hatch for hosts with neither tool, and any run that
happens unsandboxed is recorded in `ProcResult.note` rather than happening
silently.

## 5. Routing around a platform gap instead of requiring one platform

Half of autopwn's backends don't work cleanly on native Windows: `angr`,
`z3`, and `unicorn` are awkward to install there, and `pwntools`'
`process()`/`gdb.debug()` need a real Linux process and simply don't run on
Windows at all. The fix isn't "run this whole app from WSL"; it's routing
individual engines to WSL automatically while the server itself still runs
on Windows.

The Status panel reports each engine as `native`, `wsl`, or `missing`, a
three-way split rather than a plain installed/missing, because `angr`/`z3`/
`unicorn` are genuinely different depending on where they're imported: they
can run **inside this server's own process** (autopwn's in-process
`ret2win`/`z3`/`emulate` strategies), or **only inside a WSL-side venv** for
scripts `runner.run_script()` hands off separately. Only the first case
actually helps autopwn itself; a WSL-only install of those three still
leaves those in-process strategies unable to run, which is exactly the kind
of gap a flat installed/missing status would hide. `pwntools`/`triton` have
no in-process use at all, so for them `wsl` really does mean fully covered.

The probe that backs this (`wsl_env.py::detect()`) shells into WSL and tries
to import up to five packages there, which costs real time (up to 15
seconds cold), so it's memoized per server process with an explicit
`?refresh=1` escape hatch rather than re-run on every Status-panel open.
Inside that probe, `angr` is checked last on purpose: it's the heaviest
import, so if the probe's own timeout fires mid-import, every token printed
before it is still captured and still correct, instead of losing results
for packages that had already finished importing cleanly.

The provisioning script (`wsl/setup_pwn_env.sh`) only installs `pwntools`
and `triton-library` into `~/pwn-venv`, not `angr`/`z3`/`unicorn`: those
three need a native Windows install regardless, for the in-process reason
above, so there was never a reason to make the setup script carry them
too. That split wasn't documented anywhere a new clone could see it until
now; the script itself was quietly excluded from the public repo by an
overly broad `.gitignore` rule that lumped it in with personal dev
tooling, so the feature it supports had no setup path for anyone but the
original machine it was written on.

## 6. A bug that looked fixed, five times, before it actually was

A strategy reporting "no flag" can still have recovered something real on
the way: a win address, a decrypted key, a struct layout. The code that
combined those two facts was `reason or finding`, and Python's `or` always
takes the left side when it's truthy. Every real solver sets a non-empty
`reason` on every real no-flag branch, including the branches that had just
recovered something useful. So the recovered finding was discarded on every
real run, not as an edge case: as the common case.

It surfaced sideways, not from a bug report. A plan reviewer, checking an
otherwise simple "lock existing behavior" plan, noticed that a planned UI
confidence chip had no code path that could ever set the values it claimed
to show. Chasing why led straight to the discard logic underneath. Fixing
it for `ret2win` surfaced the identical shape in `keygen` and `z3`
immediately; a wider sweep for the same pattern then found `uaf` and
`brute` too. Fixing `uaf` introduced a new bug in the fix itself: one
recovered field (struct size) is independently nullable from another (the
flag function address), and the first attempt gated both behind one joint
check, which would have raised `TypeError` formatting `None` as hex on the
exact no-flag path the fix was supposed to cover. The same joint-guard
mistake, once named, turned out to already be sitting in the `ret2win` fix
from the pass before. It took six review passes before those five
functions were actually correct, not just plausible.

A later, separate audit, run specifically to check for the same pattern
anywhere it hadn't already been fixed, found it again, live, in two more
functions in the same file: `emulate` and `format_string`. The first fix
pass had been scoped to "the functions the reviewer happened to flag," not
"every function shaped like this," so the two the reviewer hadn't looked at
still had the bug a release later. A plain grep for `reason or f"` across
the file would have caught all seven the first time.

The lesson that stuck: when a bug is a pattern, not an instance, fix it by
searching for the pattern across the codebase before calling it done, not
by fixing the specific case a report or a review happened to name.
