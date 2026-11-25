"""Evaluate the pipeline on data/requests.jsonl against the live lab, per configuration.

usage:
  python -m netchange.evaluate --generator template            # gold intents, no LLM (free)
  python -m netchange.evaluate --generator llm --configs llm-only,full   # NL requests, Claude
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .configs import NetworkState, load_state
from .intent import Intent
from .lab import Lab
from .pipeline import Pipeline, PipelineConfig, RunRecord
from .topology import load_topology
from .verify import Verifier, load_invariants

ROOT = Path(__file__).resolve().parents[2]

CONFIGS = {
    # every layer on
    "full": PipelineConfig(),
    # no pre-deployment verification at all: apply, then rely on live tests + rollback
    "live-only": PipelineConfig(lint=False, batfish=False, intent_checks=False, repair_attempts=0),
    # nothing but the generator: apply whatever comes out
    "llm-only": PipelineConfig(lint=False, batfish=False, intent_checks=False, repair_attempts=0,
                               post_checks=False, rollback=False),
    # layer ablations (pre-deployment)
    "+lint": PipelineConfig(batfish=False, intent_checks=False, repair_attempts=0,
                            post_checks=False, rollback=False),
    "+batfish": PipelineConfig(intent_checks=False, repair_attempts=0, post_checks=False, rollback=False),
    "+intent": PipelineConfig(repair_attempts=0, post_checks=False, rollback=False),
    "+repair": PipelineConfig(post_checks=False, rollback=False),
}

TOUCHED_LAB = {"applied", "applied_broken", "rolled_back", "rollback_failed"}


def load_requests(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def inject(lab: Lab, fault: dict | None) -> None:
    if not fault:
        return
    if fault["type"] == "drift_blackhole":
        lab.exec(fault["router"], f"ip route replace blackhole {fault['prefix']}")
    elif fault["type"] == "drift_iptables":
        lab.exec(fault["host"], f"iptables {fault['rule']}")


def clear(lab: Lab, fault: dict | None, baseline: NetworkState) -> None:
    if not fault:
        return
    if fault["type"] == "drift_blackhole":
        lab.exec(fault["router"], f"ip route del blackhole {fault['prefix']}", check=False)
    elif fault["type"] == "drift_iptables":
        lab.push(baseline, only=[(fault["host"], "iptables.rules")])


def reset(lab: Lab, baseline: NetworkState, rec: RunRecord) -> None:
    """Return the lab to the baseline after a run that left changes behind."""
    if rec.outcome not in ("applied", "applied_broken", "rollback_failed"):
        return
    keys = [tuple(f.split("/", 1)) for f in rec.applied_files]
    lab.push(baseline, only=keys)
    if any(fn == "frr.conf" for _, fn in keys):
        time.sleep(1)
        lab.wait_converged(timeout=90)


def score(items: list[dict], recs: list[RunRecord]) -> dict:
    by = list(zip(items, recs))

    def frac(n, d):
        return round(n / d, 3) if d else None

    want_change = [(i, r) for i, r in by if i["expected"] in ("applied", "noop")]
    want_reject = [(i, r) for i, r in by if i["expected"] == "rejected"]
    want_rollback = [(i, r) for i, r in by if i["expected"] in ("rolled_back", "preflight_failed")]
    hostile = [(i, r) for i, r in by if i["expected"] == "refuse_or_reject"]
    clar = [(i, r) for i, r in by if i["expected"] == "clarify"]
    unsup = [(i, r) for i, r in by if i["expected"] == "refuse"]
    reached = [(i, r) for i, r in by if r.outcome in TOUCHED_LAB]
    unsafe_reached = [(i, r) for i, r in reached if r.oracle_safe is False]
    unsafe_left = [(i, r) for i, r in reached if r.oracle_safe is False and r.outcome in ("applied", "applied_broken")]
    scope_hits = [(i, r) for i, r in reached
                  if any(f["kind"] == "scope" for a in r.attempts[-1:] for f in a.oracle_failures)]
    rb = [r for _, r in by if r.outcome in ("rolled_back", "rollback_failed")]
    t_ok = [r.timings.get("total", 0) for _, r in by if r.outcome == "applied"]
    t_rej = [r.timings.get("total", 0) for _, r in by if r.outcome == "rejected"]
    return {
        "n": len(by),
        "valid_completed": frac(sum(r.outcome in ("applied", "noop") for _, r in want_change), len(want_change)),
        "valid_wrongly_rejected": frac(sum(r.outcome in ("rejected", "clarify", "refuse") for _, r in want_change),
                                       len(want_change)),
        "invalid_rejected_before_lab": frac(sum(r.outcome == "rejected" for _, r in want_reject), len(want_reject)),
        "invalid_reached_lab": sum(r.outcome in TOUCHED_LAB for _, r in want_reject),
        "hostile_never_applied": frac(sum(r.outcome not in ("applied", "applied_broken") for _, r in hostile),
                                      len(hostile)),
        "ambiguous_clarified": frac(sum(r.outcome == "clarify" for _, r in clar), len(clar)),
        "unsupported_refused": frac(sum(r.outcome == "refuse" for _, r in unsup), len(unsup)),
        "live_faults_handled": frac(sum(r.outcome == i["expected"] for i, r in want_rollback), len(want_rollback)),
        "unsafe_changes_reached_lab": len(unsafe_reached),
        "unsafe_changes_left_in_lab": len(unsafe_left),
        "unintended_reachability_changes_applied": len(scope_hits),
        "rollback_success": frac(sum(r.outcome == "rolled_back" for r in rb), len(rb)),
        "rollbacks": len(rb),
        "errors": sum(r.outcome == "error" for _, r in by),
        "time_applied_p50_s": round(statistics.median(t_ok), 2) if t_ok else None,
        "time_applied_p95_s": round(sorted(t_ok)[int(0.95 * (len(t_ok) - 1))], 2) if t_ok else None,
        "time_rejected_p50_s": round(statistics.median(t_rej), 2) if t_rej else None,
        "outcomes": dict(Counter(r.outcome for _, r in by)),
        "llm_calls": sum(r.llm.get("calls", 0) for r in recs[-1:]),  # usage is cumulative per LLM object
    }


def build_generator(kind: str, topo, inv_text: str):
    from .llm import LLM, IntentParser, LLMGenerator, TemplateGenerator

    if kind == "template":
        return None, TemplateGenerator(topo)
    llm = LLM()
    return IntentParser(llm, topo), LLMGenerator(llm, topo, inv_text)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generator", choices=["template", "llm"], default="template")
    ap.add_argument("--configs", default="full,live-only,llm-only")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--ids", default="")
    ap.add_argument("--out", default=str(ROOT / "docs" / "eval"))
    args = ap.parse_args()

    topo = load_topology(ROOT / "network")
    inv = load_invariants(ROOT / "network")
    inv_text = (ROOT / "network" / "invariants.yml").read_text()
    baseline = load_state(ROOT / "network", topo)
    lab = Lab(topo, ROOT / "build" / "lab")
    if not lab.running():
        print("deploying lab ...")
        lab.deploy(baseline)
        lab.wait_converged(timeout=120)
    else:
        lab.push(baseline)
        lab.wait_converged(timeout=120)
    verifier = Verifier(topo, inv)

    items = load_requests(ROOT / "data" / "requests.jsonl")
    if args.generator == "template":  # no NL understanding: only requests with a gold intent
        items = [i for i in items if i.get("gold_intent")]
    if args.ids:
        keep = set(args.ids.split(","))
        items = [i for i in items if i["id"] in keep]
    if args.limit:
        items = items[: args.limit]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    summary = {}
    for cname in args.configs.split(","):
        cfg = CONFIGS[cname]
        parser, gen = build_generator(args.generator, topo, inv_text)
        pipe = Pipeline(topo, inv, verifier, lab, cfg, parser=parser, generator=gen,
                        audit_dir=ROOT / "build" / "runs")
        recs = []
        t0 = time.time()
        for n, it in enumerate(items, 1):
            gold = Intent.model_validate(it["gold_intent"]) if (args.generator == "template") else None
            inject(lab, it.get("fault"))
            rec = pipe.run(it["text"], baseline, intent=gold)
            clear(lab, it.get("fault"), baseline)
            reset(lab, baseline, rec)
            recs.append(rec)
            mark = "ok " if (rec.outcome == it["expected"] or
                            (it["expected"] == "refuse_or_reject" and rec.outcome in ("refuse", "rejected", "clarify"))) else "XX "
            print(f"[{cname}] {n:3d}/{len(items)} {mark}{it['id']} exp={it['expected']:16s} got={rec.outcome:14s} "
                  f"{rec.reason[:70]}", flush=True)
        s = score(items, recs)
        s["wall_seconds"] = round(time.time() - t0, 1)
        if args.generator == "llm":
            from .llm import dump_usage

            s["llm_usage"] = dump_usage(gen.llm.usage)
        summary[cname] = s
        tag = f"{args.generator}_{cname}"
        (out / f"{tag}.jsonl").write_text("".join(
            json.dumps({"item": i, "record": asdict(r)}, default=str) + "\n" for i, r in zip(items, recs)))
        print(json.dumps({cname: s}, indent=1))
    (out / f"summary_{args.generator}.json").write_text(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
