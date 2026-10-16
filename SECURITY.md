# Security Policy

## Threat model: read this before you run it anywhere but your own machine

Triage is built for one person, running it locally, against a binary they
chose to analyze. It is **not** a multi-tenant service, and it does not try
to be safe against anyone but the analyst sitting at the keyboard. Concretely:

- `/api/load` will open any local path the server process can read,
  including a `path=` form field pointing anywhere on disk, not just an
  uploaded file.
- `/api/solver/execute` runs the generated (or edited) exploit script as a
  real Python subprocess with the server's own privileges. This is the
  point of the tool: it is not a sandbox escape, it is the documented
  feature.
- There is no authentication, no session concept beyond "the one binary
  currently loaded," and no rate limiting.

The server binds to `127.0.0.1` by default specifically because of the
above. Widening `--host` past loopback (e.g. to share with a CTF team on a
trusted LAN) now requires an explicit `--i-understand-the-network-risk`
flag alongside it; the server refuses to start on a non-loopback host
without it. Even with that flag: only do this on a network you actually
trust. Anyone who can reach the port can read any file the server process
can read and run arbitrary code as that process.

## Reporting a vulnerability

If you find a security issue that's specific to Triage itself, something
beyond the threat model above (e.g. a way to break out of the sandboxing
`autopwn` applies to a *target* binary's execution, a bypass of the
`--host` confirmation gate, a path-traversal that reaches outside the
intended staging directory), please report it privately rather than
opening a public issue first:

- Open a [GitHub Security Advisory](https://github.com/0-Bobo/Triage/security/advisories/new)
  for this repository, **or**
- Email the maintainer via the contact on the
  [GitHub profile](https://github.com/0-Bobo) listed on this repo.

Please include a reproduction case and the version/commit you tested
against. There's no bug bounty here, this is a hobby-scale, single-author
tool, but reports are genuinely welcome and will be credited in the fix's
changelog entry unless you'd rather stay anonymous.

## What's explicitly *not* a vulnerability report

- "Triage can read files from disk" / "Triage can run arbitrary code" when
  used as documented, on `127.0.0.1`, by the person who started it. That's
  the threat model above, not a bug.
- A generated exploit script failing to pop a shell on a target binary.
  `autopwn`/the solver generators are a recon + first-move accelerator,
  not a guaranteed exploit, see `ARCHITECTURE.md`.
- A dependency (angr, pwntools, capstone, flare-capa, ...) having its own
  known CVE. Report those upstream; `pip-audit` already tracks them here
  (see `.github/workflows/ci.yml`).
