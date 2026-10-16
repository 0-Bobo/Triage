"""``python -m triage_web.autopwn <binary> [<binary> ...]``

Recon + first-move accelerator. For each target it prints the static picture
(format / arch / protections / ranked strategy plan) and then runs the
strategies in priority order, stopping at the first flag. A failed solve is
still useful output: the recon and the per-strategy notes tell you what to
try by hand. ``--recon`` stops after the classification.
"""

from __future__ import annotations

import argparse
import json
import sys

from triage_web.autopwn import recon, solve
from triage_web.autopwn.writeup import default_writeup_path, generate_writeup


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m triage_web.autopwn", description=__doc__)
    ap.add_argument("targets", nargs="+", help="binary file(s) to solve")
    ap.add_argument("--only", help="comma-separated strategies to run (emulate,angr,ret2win,format_string)")
    ap.add_argument("--budget", type=float, default=180.0, help="seconds per target (default 180)")
    ap.add_argument("--pattern", help="extra flag regex, e.g. 'ACME\\{.*?\\}'")
    ap.add_argument("--recon", action="store_true", help="stop after the static recon; don't run strategies")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    only = [s.strip() for s in args.only.split(",")] if args.only else None
    rc = 1
    out: list[dict] = []
    for target in args.targets:
        if args.recon:
            data = recon(target)
            out.append(data)
            if not args.json:
                _print_recon(data)
            continue
        res = solve(target, only=only, budget_s=args.budget, flag_pattern=args.pattern)
        result_dict = _result_dict(res)
        out.append(result_dict)
        if not args.json:
            print(res.summary())
            if not res.success:
                if isinstance(res.recon, dict) and "plans" in res.recon:
                    print("  --- recon (your starting point) ---")
                    _print_recon(res.recon)
                for att in res.attempts:
                    conf = f"[{att['confidence']}] " if att["confidence"] else ""
                    print(f"      {att['strategy']:<14} {conf}{att['detail'][:160]}")
        if res.success:
            rc = 0
            writeup_path = default_writeup_path(result_dict)
            writeup_path.write_text(generate_writeup(result_dict), encoding="utf-8")
            if not args.json:
                print(f"  writeup: {writeup_path}")

    if args.json:
        json.dump(out if len(out) > 1 else out[0], sys.stdout, indent=2, default=str)
        print()
    return rc


def _print_recon(data: dict) -> None:
    print(f"{data['path']}: {data['arch']} {data['bits']}-bit {data['format']}")
    print(f"  protections: {data['protections']}")
    print(f"  imports: {', '.join(data['imports'][:24])}")
    print("  plan:")
    for p in data["plans"]:
        print(f"    {p['score']:>3}  {p['name']:<14} {p['why']}")


def _result_dict(res) -> dict:
    return {
        "path": res.path,
        "success": res.success,
        "flag": res.flag,
        "strategy": res.strategy,
        "seconds": res.seconds,
        "attempts": res.attempts,
        "proof": res.proof,
        "notes": res.notes,
        "recon": res.recon,
    }


if __name__ == "__main__":
    raise SystemExit(main())
