"""Pre-deployment verification with Batfish.

Every check runs on a Batfish model of the *candidate* network, before anything is
applied to the lab. Results carry a concrete counterexample flow when a check fails,
which the agent can feed back to the LLM for repair.
"""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints

from .configs import NetworkState
from .render import batfish_snapshot
from .topology import Topology

logging.getLogger("pybatfish").setLevel(logging.WARNING)

NETWORK = "netchange"


@dataclass
class CheckResult:
    id: str
    kind: str  # parse | deny | only | require | routing
    passed: bool
    detail: str = ""
    counterexample: str = ""


@dataclass
class Verdict:
    snapshot: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]


def parse_ports(spec: str) -> dict:
    """'tcp/443' -> header kwargs. 'any' -> no constraint."""
    spec = spec.strip().lower()
    if spec == "any":
        return {}
    if spec == "icmp":
        return {"ipProtocols": ["icmp"]}
    proto, _, port = spec.partition("/")
    if proto not in ("tcp", "udp") or not port:
        raise ValueError(f"bad port spec {spec!r}")
    return {"ipProtocols": [proto], "dstPorts": port}


def _as_list(x) -> list[str]:
    return [x] if isinstance(x, str) else list(x)


def _flow_str(row) -> str:
    f = row["Flow"]
    port = f" {f.ipProtocol}/{f.dstPort}" if f.ipProtocol in ("TCP", "UDP") else f" {f.ipProtocol}"
    return f"{f.ingressNode} {f.srcIp} -> {f.dstIp}{port}"


def _trace_str(trace) -> str:
    last = trace.hops[-1] if trace.hops else None
    steps = "; ".join(str(s) for s in last.steps) if last else ""
    return f"{trace.disposition} at {last.node if last else '?'}: {steps}"


class Verifier:
    def __init__(self, topo: Topology, invariants: dict, host: str = "localhost"):
        self.topo = topo
        self.inv = invariants
        self.bf = Session(host=host)
        self.bf.set_network(NETWORK)

    # ---- snapshots -------------------------------------------------------------------------
    def load(self, state: NetworkState, name: str | None = None) -> str:
        name = name or f"s-{state.digest()}"
        if name in self.bf.list_snapshots():
            return name
        with tempfile.TemporaryDirectory() as d:
            snap = batfish_snapshot(self.topo, state, Path(d) / "snap")
            self.bf.init_snapshot(str(snap), name=name, overwrite=True)
        return name

    def _q(self, snap: str, question):
        return question.answer(snapshot=snap).frame()

    # ---- helpers ----------------------------------------------------------------------------
    def hosts_in(self, zone: str) -> list[str]:
        import ipaddress

        net = ipaddress.IPv4Network(self.topo.zones[zone])
        return [h for h, x in self.topo.hosts.items() if ipaddress.IPv4Address(x.ip) in net]

    def ips(self, hosts: list[str]) -> str:
        return ",".join(self.topo.hosts[h].ip for h in hosts)

    # ---- checks -----------------------------------------------------------------------------
    def check_parse(self, snap: str) -> list[CheckResult]:
        out = []
        fps = self._q(snap, self.bf.q.fileParseStatus())
        bad = fps[fps["Status"] != "PASSED"]
        out.append(CheckResult("config-parses", "parse", bad.empty,
                               "; ".join(f"{r.File_Name}: {r.Status}" for r in bad.itertuples())))
        issues = self._q(snap, self.bf.q.initIssues())
        detail = "; ".join(f"{r.Type}: {r.Details} [{r.Line_Text}]" for r in issues.itertuples())
        out.append(CheckResult("no-init-issues", "parse", issues.empty, detail[:2000]))
        return out

    def check_deny(self, snap: str, rule: dict) -> CheckResult:
        src = self.hosts_in(rule["from"])
        dst = _as_list(rule["to"])
        ans = self._q(snap, self.bf.q.reachability(
            pathConstraints=PathConstraints(startLocation=",".join(src)),
            headers=HeaderConstraints(dstIps=self.ips(dst), **parse_ports(rule.get("ports", "any"))),
            actions="SUCCESS"))
        if ans.empty:
            return CheckResult(rule["id"], "deny", True)
        row = ans.iloc[0]
        return CheckResult(rule["id"], "deny", False, rule.get("why", ""),
                           f"{_flow_str(row)} is ACCEPTED ({len(ans)} flow class(es))")

    def check_only(self, snap: str, rule: dict) -> CheckResult:
        dst = _as_list(rule["to"])
        allowed = {h for z in rule["allowed_from"] for h in self.hosts_in(z)}
        src = [h for h in self.topo.hosts if h not in allowed and h not in dst]
        ans = self._q(snap, self.bf.q.reachability(
            pathConstraints=PathConstraints(startLocation=",".join(src)),
            headers=HeaderConstraints(dstIps=self.ips(dst), **parse_ports(rule["ports"])),
            actions="SUCCESS"))
        if ans.empty:
            return CheckResult(rule["id"], "only", True)
        row = ans.iloc[0]
        return CheckResult(rule["id"], "only", False, rule.get("why", ""),
                           f"{_flow_str(row)} is ACCEPTED but only {rule['allowed_from']} may reach it")

    def flow_ok(self, snap: str, src: str, dst: str, ports: str) -> tuple[bool, str]:
        """Bidirectional: the request must be accepted AND the reply must get back
        (host firewalls are stateless, so return traffic needs its own rule)."""
        ans = self._q(snap, self.bf.q.bidirectionalTraceroute(
            startLocation=src,
            headers=HeaderConstraints(dstIps=self.topo.hosts[dst].ip, **parse_ports(ports))))
        if ans.empty:
            return False, "no trace"
        for row in ans.itertuples():
            fwd = row.Forward_Traces
            rev = row.Reverse_Traces
            if any(t.disposition != "ACCEPTED" for t in fwd):
                bad = next(t for t in fwd if t.disposition != "ACCEPTED")
                return False, "request: " + _trace_str(bad)
            if not rev or any(t.disposition != "ACCEPTED" for t in rev):
                bad = next((t for t in rev if t.disposition != "ACCEPTED"), None)
                return False, "reply: " + (_trace_str(bad) if bad else "no reverse trace")
        return True, ""

    def check_require(self, snap: str, rule: dict) -> CheckResult:
        ok, why = self.flow_ok(snap, rule["from"], rule["to"], rule["ports"])
        return CheckResult(rule["id"], "require", ok,
                           "" if ok else f"{rule['from']} -> {rule['to']} {rule['ports']} broken",
                           why)

    def check_routing(self, snap: str) -> list[CheckResult]:
        cfg = self.inv.get("routing", {})
        out = []
        if cfg.get("ospf_full_adjacency"):
            s = self._q(snap, self.bf.q.ospfSessionCompatibility())
            up = (s["Session_Status"] == "ESTABLISHED").sum() if not s.empty else 0
            want = 2 * len(self.topo.links)
            down = s[s["Session_Status"] != "ESTABLISHED"] if not s.empty else s
            out.append(CheckResult("ospf-full-adjacency", "routing", up == want and down.empty,
                                   f"{up}/{want} OSPF session ends established",
                                   "; ".join(f"{r.Interface}: {r.Session_Status}" for r in down.itertuples())))
        if cfg.get("loopback_mesh"):
            loops = ",".join(r.loopback.split("/")[0] for r in self.topo.routers.values())
            ans = self._q(snap, self.bf.q.reachability(
                pathConstraints=PathConstraints(startLocation=",".join(self.topo.routers)),
                headers=HeaderConstraints(dstIps=loops), actions="FAILURE"))
            out.append(CheckResult("loopback-mesh", "routing", ans.empty, "",
                                   "" if ans.empty else _flow_str(ans.iloc[0]) + " fails"))
        if cfg.get("no_forwarding_loops"):
            ans = self._q(snap, self.bf.q.detectLoops())
            out.append(CheckResult("no-forwarding-loops", "routing", ans.empty, "",
                                   "" if ans.empty else _flow_str(ans.iloc[0]) + " loops"))
        return out

    def verify(self, state: NetworkState, name: str | None = None) -> Verdict:
        snap = self.load(state, name)
        v = Verdict(snap, self.check_parse(snap))
        if not v.passed:  # a config Batfish cannot fully read cannot be trusted further
            return v
        v.checks += self.check_routing(snap)
        v.checks += [self.check_deny(snap, r) for r in self.inv.get("deny", [])]
        v.checks += [self.check_only(snap, r) for r in self.inv.get("only", [])]
        v.checks += [self.check_require(snap, r) for r in self.inv.get("require", [])]
        return v

    # ---- intent-specific checks --------------------------------------------------------------
    def check_intent(self, base: str, cand: str, intent) -> list[CheckResult]:
        """Does the candidate do what was asked (post-conditions) and nothing else (scope)?"""
        from .intent import out_of_scope_regions, postconditions

        out = []
        for pc in postconditions(intent, self.topo):
            ok, why = self.flow_ok(cand, pc["src"], pc["dst"], pc["ports"])
            good = ok == pc["expect"]
            verb = "works" if pc["expect"] else "is blocked"
            out.append(CheckResult(f"intent: {pc['src']} -> {pc['dst']} {pc['ports']} {verb}", "intent",
                                   good, "", "" if good else (why or "flow still accepted")))
        if intent.kind == "set_ospf_cost":
            f = self._q(cand, self.bf.q.ospfInterfaceConfiguration(nodes=intent.router))
            row = f[f["Interface"].astype(str) == f"{intent.router}[{intent.interface}]"]
            got = int(row.iloc[0]["OSPF_Cost"]) if not row.empty else None
            out.append(CheckResult(f"intent: OSPF cost {intent.router}:{intent.interface} = {intent.cost}",
                                   "intent", got == intent.cost, "", f"cost is {got}"))
        for reg in out_of_scope_regions(intent, self.topo):
            changed = self.diff_region(base, cand, reg["start"], reg["headers"])
            out.append(CheckResult(f"scope: {reg['name']} unchanged", "scope", not changed,
                                   f"{len(changed)} flow class(es) changed",
                                   "; ".join(f"{c['src']} {c['src_ip']}->{c['dst_ip']} {c['proto']}/{c['dst_port']}"
                                             f" {c['before']}->{c['after']}" for c in changed[:3])))
        return out

    def diff_region(self, base: str, cand: str, start: list[str], headers: dict) -> list[dict]:
        ans = self.bf.q.differentialReachability(
            pathConstraints=PathConstraints(startLocation=",".join(start)),
            headers=HeaderConstraints(**headers),
        ).answer(snapshot=cand, reference_snapshot=base).frame()
        return [self._diff_row(r) for r in ans.itertuples()]

    @staticmethod
    def _diff_row(row) -> dict:
        f = row.Flow
        return {
            "src": f.ingressNode, "src_ip": f.srcIp, "dst_ip": f.dstIp,
            "proto": f.ipProtocol, "dst_port": f.dstPort,
            "before": row.Reference_Traces[0].disposition if row.Reference_Traces else "?",
            "after": row.Snapshot_Traces[0].disposition if row.Snapshot_Traces else "?",
        }

    # ---- change scope -----------------------------------------------------------------------
    def reachability_diff(self, base: str, cand: str) -> list[dict]:
        """Host-to-host flows whose outcome differs between two snapshots."""
        hosts = list(self.topo.hosts)
        ans = self.bf.q.differentialReachability(
            pathConstraints=PathConstraints(startLocation=",".join(hosts)),
            headers=HeaderConstraints(dstIps=self.ips(hosts)),
        ).answer(snapshot=cand, reference_snapshot=base).frame()
        out = []
        for row in ans.itertuples():
            f = row.Flow
            out.append({
                "src": f.ingressNode, "src_ip": f.srcIp, "dst_ip": f.dstIp,
                "proto": f.ipProtocol, "dst_port": f.dstPort,
                "before": row.Reference_Traces[0].disposition if row.Reference_Traces else "?",
                "after": row.Snapshot_Traces[0].disposition if row.Snapshot_Traces else "?",
            })
        return out


def load_invariants(network_dir: str | Path) -> dict:
    return yaml.safe_load((Path(network_dir) / "invariants.yml").read_text())
