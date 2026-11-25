"""netchange CLI.

  netchange lab up | down | status
  netchange verify                              # check the committed network against every invariant
  netchange request "allow https from the branch to web1" [--yes] [--save] [--dry-run]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .configs import load_state, save_state
from .lab import Lab
from .topology import load_topology
from .verify import Verifier, load_invariants

ROOT = Path(__file__).resolve().parents[2]
NET = ROOT / "network"


def _env():
    topo = load_topology(NET)
    return topo, load_state(NET, topo), load_invariants(NET)


def cmd_lab(args) -> int:
    topo, state, _ = _env()
    lab = Lab(topo, ROOT / "build" / "lab")
    if args.action == "up":
        lab.deploy(state)
        ok, dt = lab.wait_converged(timeout=120)
        print(f"lab up; OSPF converged={ok} in {dt:.0f}s")
    elif args.action == "down":
        lab.destroy()
        print("lab destroyed")
    else:
        print("running" if lab.running() else "not running")
        if lab.running():
            for r, (full, want) in lab.ospf_full().items():
                print(f"  {r:7s} OSPF neighbours {full}/{want}")
    return 0


def cmd_verify(args) -> int:
    topo, state, inv = _env()
    verdict = Verifier(topo, inv).verify(state)
    for c in verdict.checks:
        print(f"{'PASS' if c.passed else 'FAIL'}  {c.kind:8s} {c.id}  {c.counterexample}")
    return 0 if verdict.passed else 1


def cmd_request(args) -> int:
    from .llm import LLM, IntentParser, LLMGenerator
    from .pipeline import Pipeline, PipelineConfig

    topo, state, inv = _env()
    llm = LLM()
    parser = IntentParser(llm, topo)
    gen = LLMGenerator(llm, topo, (NET / "invariants.yml").read_text())
    lab = None if args.dry_run else Lab(topo, ROOT / "build" / "lab")
    if lab is not None and not lab.running():
        print("lab is not running: `netchange lab up` first, or use --dry-run", file=sys.stderr)
        return 2
    cfg = PipelineConfig(apply=not args.dry_run, approval="auto" if args.yes else "interactive")

    def approve(rec, cand) -> bool:
        print(f"\nProposed change (risk: {rec.risk}):\n{rec.final_diff}")
        return input("Apply to the lab? [y/N] ").strip().lower() == "y"

    pipe = Pipeline(topo, inv, Verifier(topo, inv), lab, cfg, parser=parser, generator=gen,
                    audit_dir=ROOT / "runs")
    rec = pipe.run(args.text, state, approve=approve)
    print(f"\nintent : {rec.intent and rec.intent.get('reason')}")
    for a in rec.attempts:
        status = "accepted" if a.accepted else f"rejected ({len(a.failures)} failing checks)"
        print(f"attempt {a.n}: {status}  {a.explanation}")
        for f in a.failures[:5]:
            print(f"   - {f['id']}: {f['counterexample'] or f['detail']}")
    print(f"outcome: {rec.outcome}  {rec.reason}")
    print(f"timings: {rec.timings}   llm: {rec.llm}")
    if rec.outcome == "applied" and args.save:
        save_state(NET, pipe.last_candidate)  # the verified, applied candidate becomes the source of truth
        print("saved to network/ - review with `git diff network/`")
    return 0 if rec.outcome in ("applied", "noop", "approved_not_applied") else 1


def main() -> None:
    ap = argparse.ArgumentParser(prog="netchange")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lab")
    p.add_argument("action", choices=["up", "down", "status"])
    p.set_defaults(fn=cmd_lab)
    p = sub.add_parser("verify")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("request")
    p.add_argument("text")
    p.add_argument("--yes", action="store_true", help="skip the approval prompt")
    p.add_argument("--save", action="store_true", help="write the applied change back to network/")
    p.add_argument("--dry-run", action="store_true", help="verify only, do not touch the lab")
    p.set_defaults(fn=cmd_request)
    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
