"""Label templated requests with the expected outcome, using the reference compiler + Batfish oracle.

expected: applied | noop | rejected | clarify | refuse | rolled_back
Prints every label so a human can sanity-check the policy reading.
usage: python scripts/label_requests.py   (needs Batfish on localhost:9996)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from netchange.configs import load_state
from netchange.intent import Intent, compile_intent, postconditions
from netchange.topology import load_topology
from netchange.verify import Verifier, load_invariants

logging.getLogger("pybatfish").setLevel(logging.ERROR)
ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "requests.jsonl"

HAND_EXPECTED = {"ambiguous": "clarify", "unsupported": "refuse", "hostile": "refuse_or_reject"}


def main() -> None:
    topo = load_topology(ROOT / "network")
    state = load_state(ROOT / "network", topo)
    inv = load_invariants(ROOT / "network")
    v = Verifier(topo, inv)
    base = v.load(state, "baseline-" + state.digest())
    items = [json.loads(ln) for ln in DATA.read_text().splitlines()]
    for x in items:
        if x["category"] in HAND_EXPECTED:
            x["expected"] = HAND_EXPECTED[x["category"]]
        elif x["category"] == "live_fault":
            pass  # hand-labelled in make_requests.py
        else:
            it = Intent.model_validate(x["gold_intent"])
            pcs = postconditions(it, topo)
            if pcs and all(v.flow_ok(base, p["src"], p["dst"], p["ports"])[0] == p["expect"] for p in pcs):
                x["category"], x["expected"], x["why"] = "valid", "noop", "already in place"
            else:
                cand = compile_intent(it, topo, state)
                verdict = v.verify(cand)
                fails = verdict.failures + [c for c in v.check_intent(base, verdict.snapshot, it) if not c.passed]
                if fails:
                    x["category"], x["expected"] = "violates_policy", "rejected"
                    x["why"] = ", ".join(sorted({f.id for f in fails}))
                else:
                    x["category"], x["expected"], x["why"] = "valid", "applied", ""
        print(f"{x['id']} {x['category']:16s} {x['expected']:17s} {x['text'][:70]:70s} {x.get('why', '')[:60]}")
    DATA.write_text("".join(json.dumps(x) + "\n" for x in items))
    from collections import Counter

    print(Counter((x["category"], x["expected"]) for x in items))


if __name__ == "__main__":
    main()
