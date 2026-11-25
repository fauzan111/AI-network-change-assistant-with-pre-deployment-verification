"""The change pipeline: request -> intent -> candidate -> checks (+repair) -> approval -> apply -> test -> rollback.

Each verification layer can be switched off (PipelineConfig) so the evaluation can measure
what every layer catches. Regardless of which layers are *enforced*, the full verifier verdict
is always *recorded* as an oracle label, so an unsafe change that slips through an ablated
pipeline is still counted as unsafe.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .configs import FRR, IPT, NetworkState
from .intent import Intent, postconditions, validate_intent
from .iptables_lint import lint
from .lab import Lab, Probe
from .llm import feedback_text
from .probes import invariant_probes
from .topology import Topology
from .verify import CheckResult, Verifier


@dataclass
class PipelineConfig:
    lint: bool = True  # verifier-safe dialect for firewall files
    batfish: bool = True  # parse + invariants on the Batfish model
    intent_checks: bool = True  # post-conditions + out-of-scope differential reachability
    repair_attempts: int = 2  # extra LLM attempts with verifier feedback
    apply: bool = True  # push approved changes to the lab
    post_checks: bool = True  # live probes after applying
    rollback: bool = True  # restore the previous config if live checks fail
    approval: str = "auto"  # auto | interactive | block-high-risk

    def label(self) -> str:
        on = [n for n in ("lint", "batfish", "intent_checks", "post_checks", "rollback") if getattr(self, n)]
        return "+".join(on) + f"/repair{self.repair_attempts}"


@dataclass
class Attempt:
    n: int
    explanation: str = ""
    diff: str = ""
    lint_issues: list[str] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)  # enforced checks that failed
    oracle_failures: list[dict] = field(default_factory=list)  # all checks that failed (recorded)
    accepted: bool = False
    n_checks: int = 0  # verifier checks evaluated on this candidate
    error: str = ""
    seconds: float = 0.0


@dataclass
class RunRecord:
    id: str
    request: str
    config: str
    generator: str
    intent: dict | None = None
    outcome: str = ""  # applied | noop | rejected | clarify | refuse | preflight_failed | rolled_back | rollback_failed | applied_broken | approved_not_applied | error
    reason: str = ""
    attempts: list[Attempt] = field(default_factory=list)
    risk: str = ""
    approved: bool | None = None
    applied_files: list[str] = field(default_factory=list)
    final_diff: str = ""
    oracle_safe: bool | None = None  # full verifier verdict on the final candidate (label)
    probes: list[dict] = field(default_factory=list)
    rollback_ok: bool | None = None
    timings: dict = field(default_factory=dict)
    llm: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


def risk_of(changed: list[tuple[str, str]]) -> str:
    """Simple change-risk policy: routing changes and multi-device changes need more care."""
    if any(fn == FRR for _, fn in changed) or len(changed) > 2:
        return "high"
    return "low"


def _ospf_costs(frr_text: str) -> set[tuple[str, str]]:
    """(interface, cost) pairs from an FRR config (file or `show running-config`)."""
    out, iface = set(), None
    for ln in frr_text.splitlines():
        if ln.startswith("interface "):
            iface = ln.split()[1]
        elif ln.strip().startswith("ip ospf cost") and iface:
            out.add((iface, ln.split()[-1]))
    return out


def _rules(ipt_text: str) -> list[str]:
    """Normalised INPUT rules + chain policies, ignoring comments and counters."""
    keep = []
    for ln in ipt_text.splitlines():
        ln = ln.strip()
        if ln.startswith("-A INPUT"):
            keep.append(" ".join(ln.replace(" -m tcp", "").replace(" -m udp", "").replace(" -m icmp", "").split()))
        elif ln.startswith(":INPUT"):
            keep.append(ln.split("[")[0].strip())
    return keep


def _fail_dict(c: CheckResult) -> dict:
    return {"id": c.id, "kind": c.kind, "detail": c.detail, "counterexample": c.counterexample}


class Pipeline:
    def __init__(self, topo: Topology, invariants: dict, verifier: Verifier, lab: Lab | None,
                 config: PipelineConfig, parser=None, generator=None, audit_dir: str | Path = "runs"):
        self.topo = topo
        self.inv = invariants
        self.v = verifier
        self.lab = lab
        self.cfg = config
        self.parser = parser
        self.generator = generator
        self.audit = Path(audit_dir)

    # ---- verification of one candidate --------------------------------------------------------
    def check(self, base_snap: str, state: NetworkState, cand: NetworkState, intent: Intent) -> Attempt:
        att = Attempt(n=0, diff=state.diff(cand))
        changed = state.changed_files(cand)
        if not changed:
            att.failures.append({"id": "no-change", "kind": "intent", "detail": "candidate changes nothing",
                                 "counterexample": ""})
            att.oracle_failures = list(att.failures)
            return att
        for dev, fn in changed:
            if fn == IPT:
                att.lint_issues += [f"{dev}: {i}" for i in lint(cand.get(dev, fn))]
        verdict = self.v.verify(cand)
        checks = list(verdict.checks)
        if verdict.passed or all(c.kind != "parse" for c in verdict.failures):
            checks += self.v.check_intent(base_snap, verdict.snapshot, intent)
        failed = [c for c in checks if not c.passed]
        att.n_checks = len(checks)
        att.oracle_failures = [_fail_dict(c) for c in failed]
        if att.lint_issues:  # a lint failure means the Batfish verdict cannot be trusted
            att.oracle_failures.insert(0, {"id": "dialect", "kind": "lint", "detail": att.lint_issues[0],
                                           "counterexample": ""})
        enforce = set()
        if self.cfg.batfish:
            enforce |= {"parse", "routing", "deny", "only", "require"}
        if self.cfg.intent_checks:
            enforce |= {"intent", "scope"}
        att.failures = [_fail_dict(c) for c in failed if c.kind in enforce]
        if self.cfg.lint and att.lint_issues:
            att.failures.insert(0, {"id": "dialect", "kind": "lint", "detail": "; ".join(att.lint_issues[:3]),
                                    "counterexample": ""})
        att.accepted = not att.failures
        return att

    # ---- live lab -----------------------------------------------------------------------------
    def _probes(self, intent: Intent) -> list[Probe]:
        ps = invariant_probes(self.topo, self.inv)
        for pc in postconditions(intent, self.topo):
            if pc["ports"] == "icmp" or pc["ports"].startswith("tcp/"):
                ps.append(Probe(pc["src"], pc["dst"], pc["ports"], "reachable" if pc["expect"] else "blocked"))
        return ps

    def preflight(self, rec: RunRecord, intent: Intent) -> bool:
        """Probe the live network BEFORE changing it. Refuse to change a network that is already
        unhealthy, and keep the snapshot so rollback can be checked against it exactly."""
        t0 = time.time()
        inv_probes = invariant_probes(self.topo, self.inv)
        probes = self.lab.run_probes(self._probes(intent))
        self._pre = {(p.src, p.dst, p.ports): p.got for p in probes}
        # judge health on the invariant probes only: the intent's own probes are EXPECTED to differ
        # before the change (and may share src/dst/port with an invariant probe)
        n_inv = len(inv_probes)
        bad = [p for p in probes[:n_inv] if not p.ok]
        rec.timings["preflight"] = round(time.time() - t0, 2)
        rec.probes = [{"stage": "preflight", "src": p.src, "dst": p.dst, "ports": p.ports,
                       "expect": p.expect, "got": p.got} for p in bad]
        return not bad

    def apply_and_test(self, rec: RunRecord, state: NetworkState, cand: NetworkState, intent: Intent) -> bool:
        changed = state.changed_files(cand)
        rec.applied_files = [f"{d}/{f}" for d, f in changed]
        t0 = time.time()
        self.lab.push(cand, only=changed)
        converged = True
        if any(fn == FRR for _, fn in changed):
            time.sleep(1.0)  # let FRR start reacting before we poll
            converged, _ = self.lab.wait_converged(timeout=90)
        rec.timings["apply"] = round(time.time() - t0, 2)
        if not self.cfg.post_checks:
            return True
        if not converged:
            rec.probes.append({"stage": "post", "src": "ospf", "dst": "all", "ports": "-",
                               "expect": "converged", "got": str(self.lab.ospf_full())})
        t0 = time.time()
        probes = self.lab.run_probes(self._probes(intent))
        rec.timings["post_checks"] = round(time.time() - t0, 2)
        rec.probes += [{"stage": "post", "src": p.src, "dst": p.dst, "ports": p.ports, "expect": p.expect,
                        "got": p.got} for p in probes if not p.ok]
        return converged and all(p.ok for p in probes)

    def restore(self, rec: RunRecord, state: NetworkState, cand: NetworkState) -> bool:
        """Re-apply the previous config for every changed file. Success = every probe returns
        exactly what it returned in pre-flight, and the device configs really are back."""
        changed = state.changed_files(cand)
        t0 = time.time()
        self.lab.push(state, only=changed)
        if any(fn == FRR for _, fn in changed):
            time.sleep(1.0)
            self.lab.wait_converged(timeout=90)
        pre = getattr(self, "_pre", {})
        probes = self.lab.run_probes([Probe(s, d, p, "reachable") for s, d, p in pre])
        mismatch = [p for p in probes if p.got != pre[(p.src, p.dst, p.ports)]]
        ok = not mismatch
        for dev, fn in changed:
            if fn == FRR:
                ok &= _ospf_costs(self.lab.running_frr(dev)) == _ospf_costs(state.get(dev, fn))
            else:
                live = self.lab.exec(dev, "iptables-save -t filter")
                ok &= _rules(live) == _rules(state.get(dev, fn))
        rec.timings["rollback"] = round(time.time() - t0, 2)
        rec.probes += [{"stage": "rollback", "src": p.src, "dst": p.dst, "ports": p.ports,
                        "expect": pre[(p.src, p.dst, p.ports)], "got": p.got} for p in mismatch]
        return ok

    # ---- end to end ---------------------------------------------------------------------------
    def run(self, request: str, state: NetworkState, intent: Intent | None = None,
            approve=None) -> RunRecord:
        rec = RunRecord(id=uuid.uuid4().hex[:8], request=request, config=self.cfg.label(),
                        generator=getattr(self.generator, "name", "?"))
        t_start = time.time()
        try:
            self._run(rec, request, state, intent, approve)
        except Exception as e:  # noqa: BLE001 - recorded in the audit log, never hidden
            rec.outcome, rec.reason = "error", f"{type(e).__name__}: {e}"
        rec.timings["total"] = round(time.time() - t_start, 2)
        llm = getattr(getattr(self.generator, "llm", None), "usage", None)
        if llm is not None:
            from .llm import dump_usage

            rec.llm = dump_usage(llm)
        self.audit.mkdir(parents=True, exist_ok=True)
        with (self.audit / "audit.jsonl").open("a") as f:
            f.write(rec.to_json() + "\n")
        return rec

    def _run(self, rec: RunRecord, request: str, state: NetworkState, intent: Intent | None, approve) -> None:
        # 1. intent
        t0 = time.time()
        if intent is None:
            intent = self.parser.parse(request)
        rec.timings["intent"] = round(time.time() - t0, 2)
        rec.intent = intent.model_dump()
        if intent.status != "ok":
            rec.outcome, rec.reason = intent.status, intent.question or intent.reason
            return
        errs = validate_intent(intent, self.topo)
        if errs:
            rec.outcome, rec.reason = "clarify", "; ".join(errs)
            return

        # 2-4. generate, check, repair
        base_snap = self.v.load(state, "baseline-" + state.digest())
        pcs = postconditions(intent, self.topo)
        if pcs and all(self.v.flow_ok(base_snap, p["src"], p["dst"], p["ports"])[0] == p["expect"] for p in pcs):
            rec.outcome, rec.reason = "noop", "already in place on the current network"
            return
        self.generator.start(intent, state)
        feedback, cand, att = None, None, None
        max_attempts = 1 + (self.cfg.repair_attempts if self.generator.name == "llm" else 0)
        t0 = time.time()
        for n in range(1, max_attempts + 1):
            ta = time.time()
            try:
                cand, expl = self.generator.generate(state, feedback)
            except Exception as e:  # noqa: BLE001 - a bad generation is an outcome, not a crash
                rec.attempts.append(Attempt(n=n, error=f"{type(e).__name__}: {e}"))
                break
            att = self.check(base_snap, state, cand, intent)
            att.n, att.explanation, att.seconds = n, expl, round(time.time() - ta, 2)
            rec.attempts.append(att)
            if att.accepted:
                break
            failures = [CheckResult(f["id"], f["kind"], False, f["detail"], f["counterexample"])
                        for f in att.failures if f["kind"] != "lint"]
            feedback = feedback_text(failures, att.lint_issues if self.cfg.lint else None)
        rec.timings["generate_and_verify"] = round(time.time() - t0, 2)
        if att is None or not att.accepted:
            rec.outcome = "rejected"
            rec.reason = (att.failures[0]["id"] if att and att.failures else
                          (rec.attempts[-1].error if rec.attempts else "no candidate"))
            if att is not None:
                rec.oracle_safe = not att.oracle_failures
            return
        rec.final_diff = att.diff
        rec.oracle_safe = not att.oracle_failures
        self.last_candidate = cand

        # 5. approval gate
        changed = state.changed_files(cand)
        rec.risk = risk_of(changed)
        if self.cfg.approval == "interactive" and approve is not None:
            rec.approved = bool(approve(rec, cand))
        elif self.cfg.approval == "block-high-risk":
            rec.approved = rec.risk != "high"
        else:
            rec.approved = True
        if not rec.approved:
            rec.outcome, rec.reason = "rejected", "not approved"
            return

        # 6-7. apply, test, rollback
        if not (self.cfg.apply and self.lab is not None):
            rec.outcome = "approved_not_applied"
            return
        if self.cfg.post_checks and not self.preflight(rec, intent):
            rec.outcome = "preflight_failed"
            rec.reason = "network unhealthy before the change: " + ", ".join(
                f"{p['src']}->{p['dst']} {p['ports']} expected {p['expect']}, got {p['got']}" for p in rec.probes[:3])
            return
        if self.apply_and_test(rec, state, cand, intent):
            rec.outcome = "applied"
            return
        if not self.cfg.rollback:
            rec.outcome, rec.reason = "applied_broken", "live checks failed, rollback disabled"
            return
        rec.rollback_ok = self.restore(rec, state, cand)
        rec.outcome = "rolled_back" if rec.rollback_ok else "rollback_failed"
        rec.reason = "live checks failed: " + ", ".join(
            f"{p['src']}->{p['dst']} {p['ports']} expected {p['expect']}, got {p['got']}"
            for p in rec.probes if p.get("stage") == "post")
