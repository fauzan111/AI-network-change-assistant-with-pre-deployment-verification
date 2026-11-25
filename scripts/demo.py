"""Run three real requests through the pipeline on the live lab and print a readable transcript.

1. a valid change            -> verified, applied, live-tested
2. a policy violation        -> rejected before the lab, with the counterexample flow
3. a verified change + drift -> applied, fails live, rolled back

Intents are given structured and configs come from the reference compiler (no LLM);
the verification, lab, probes and rollback are all real. Transcript is written to build/demo.txt for the GIF renderer.
usage: python scripts/demo.py   (lab + Batfish running)
"""

from __future__ import annotations

import logging
from pathlib import Path

from netchange.configs import load_state
from netchange.intent import Intent
from netchange.lab import Lab
from netchange.llm import TemplateGenerator
from netchange.pipeline import Pipeline, PipelineConfig
from netchange.topology import load_topology
from netchange.verify import Verifier, load_invariants

logging.getLogger("pybatfish").setLevel(logging.ERROR)
ROOT = Path(__file__).resolve().parents[1]
LINES: list[str] = []


def say(s: str = "") -> None:
    print(s, flush=True)
    LINES.append(s)


def show(rec) -> None:
    it = rec.intent or {}
    say(f"  intent   {it.get('kind')}  {it.get('src_zone') or it.get('router')} -> "
        f"{it.get('dst_host') or it.get('interface')}  {it.get('protocol') or ''}{('/' + str(it['port'])) if it.get('port') else ''}")
    for a in rec.attempts:
        for ln in a.diff.splitlines():
            if ln.startswith(("+-A", "--A", "+ ip", "- ip")):
                say(f"  config   {ln}")
        if a.accepted:
            say(f"  batfish  PASS  all {a.n_checks} checks (parse, OSPF, loops, policy, intent, scope)")
        for f in a.failures[:2]:
            say(f"  batfish  FAIL  {f['id']}")
            if f["counterexample"]:
                say(f"           {f['counterexample'][:88]}")
    if "preflight" in rec.timings:
        say(f"  live     pre-flight ok ({rec.timings['preflight']:.1f}s)")
    for p in rec.probes:
        if p.get("stage") == "post":
            say(f"  live     FAIL  {p['src']} -> {p['dst']} {p['ports']}: expected {p['expect']}, got {p['got']}")
    if rec.outcome == "applied":
        say(f"  live     PASS  all probes (apply {rec.timings.get('apply', 0):.1f}s)")
    if rec.outcome == "rolled_back":
        say(f"  rollback restored, probes match pre-flight ({rec.timings.get('rollback', 0):.1f}s)")
    say(f"  RESULT   {rec.outcome.upper()}   total {rec.timings['total']:.1f}s")
    say()


def main() -> None:
    topo = load_topology(ROOT / "network")
    state = load_state(ROOT / "network", topo)
    inv = load_invariants(ROOT / "network")
    lab = Lab(topo, ROOT / "build" / "lab")
    lab.push(state)
    lab.wait_converged(90)
    pipe = Pipeline(topo, inv, Verifier(topo, inv), lab, PipelineConfig(),
                    generator=TemplateGenerator(topo), audit_dir=ROOT / "build" / "runs")

    def ask(text: str, intent: Intent):
        say(f"> request: \"{text}\"")
        rec = pipe.run(text, state, intent=intent)
        show(rec)
        if rec.outcome == "applied":  # back to baseline for the next scene
            lab.push(state)
        return rec

    ask("allow https from the branch office to web1",
        Intent(status="ok", kind="allow_service", src_zone="branch-users", dst_host="web1", protocol="tcp", port=443))
    ask("let guest wifi reach web1 over https",
        Intent(status="ok", kind="allow_service", src_zone="guest-wifi", dst_host="web1", protocol="tcp", port=443))
    say("# someone adds a blackhole route on the branch router by hand (the model doesn't know)")
    lab.exec("branch", "ip route replace blackhole 10.3.10.0/24")
    ask("allow https from the branch office to web1",
        Intent(status="ok", kind="allow_service", src_zone="branch-users", dst_host="web1", protocol="tcp", port=443))
    lab.exec("branch", "ip route del blackhole 10.3.10.0/24", check=False)
    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build" / "demo.txt").write_text("\n".join(LINES) + "\n")


if __name__ == "__main__":
    main()
