"""Structured change intents, their expected outcome, and a deterministic compiler.

An Intent is the contract between the natural-language request and the config change.
From it we derive, without any LLM:
  * post-conditions the candidate must satisfy (the requested flow works / is blocked);
  * the *scope*: the only traffic whose outcome may change. Everything else must be
    bit-for-bit unchanged, checked with Batfish differential reachability;
  * a reference config change (TemplateGenerator), the non-LLM baseline.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field

from .configs import FRR, IPT, NetworkState
from .topology import Topology

Kind = Literal["allow_service", "block_service", "set_ospf_cost", "none"]


class Intent(BaseModel):
    """What the operator asked for, in a form the system can check."""

    status: Literal["ok", "clarify", "refuse"] = Field(
        description="ok = a supported, fully specified change; clarify = something essential is missing "
                    "or ambiguous; refuse = outside the supported change types or clearly unsafe")
    kind: Kind = Field(description="change type; 'none' when status is not ok")
    src_zone: str | None = Field(None, description="allow/block: source zone name from the topology")
    dst_host: str | None = Field(None, description="allow/block: destination host name")
    protocol: Literal["tcp", "udp", "icmp"] | None = Field(None, description="allow/block: protocol")
    port: int | None = Field(None, description="allow/block: destination port (tcp/udp only)")
    router: str | None = Field(None, description="set_ospf_cost: router name")
    interface: str | None = Field(None, description="set_ospf_cost: interface name, e.g. eth1")
    cost: int | None = Field(None, description="set_ospf_cost: OSPF cost 1-65535")
    question: str | None = Field(None, description="clarify: the question to ask the operator")
    reason: str = Field("", description="one sentence explaining the interpretation, or why clarify/refuse")

    @property
    def ports(self) -> str:
        return "icmp" if self.protocol == "icmp" else f"{self.protocol}/{self.port}"

    def summary(self) -> str:
        if self.status != "ok":
            return f"{self.status}: {self.question or self.reason}"
        if self.kind == "set_ospf_cost":
            return f"set OSPF cost {self.cost} on {self.router}:{self.interface}"
        verb = "allow" if self.kind == "allow_service" else "block"
        return f"{verb} {self.src_zone} -> {self.dst_host} {self.ports}"


def validate_intent(intent: Intent, topo: Topology) -> list[str]:
    """Problems that make an 'ok' intent unusable (unknown names, missing fields)."""
    if intent.status != "ok":
        return []
    errs = []
    if intent.kind in ("allow_service", "block_service"):
        if intent.src_zone not in topo.zones:
            errs.append(f"unknown source zone {intent.src_zone!r}; known: {sorted(topo.zones)}")
        if intent.dst_host not in topo.hosts:
            errs.append(f"unknown destination host {intent.dst_host!r}; known: {sorted(topo.hosts)}")
        elif not topo.hosts[intent.dst_host].firewall:
            errs.append(f"{intent.dst_host} has no host firewall to change")
        if intent.protocol is None:
            errs.append("protocol missing")
        elif intent.protocol != "icmp" and not (intent.port and 1 <= intent.port <= 65535):
            errs.append("port missing or out of range")
    elif intent.kind == "set_ospf_cost":
        r = topo.routers.get(intent.router or "")
        if r is None:
            errs.append(f"unknown router {intent.router!r}")
        elif intent.interface not in r.interfaces or not r.interfaces[intent.interface].peer:
            errs.append(f"{intent.router}:{intent.interface} is not an OSPF point-to-point link")
        if not (intent.cost and 1 <= intent.cost <= 65535):
            errs.append("cost missing or out of range")
    else:
        errs.append("status ok but kind is none")
    return errs


# ---------- scope: which traffic may change ---------------------------------------------------

def _hosts_in(topo: Topology, zone: str) -> list[str]:
    net = ipaddress.IPv4Network(topo.zones[zone])
    return [h for h, x in topo.hosts.items() if ipaddress.IPv4Address(x.ip) in net]


def _port_complement(port: int) -> str:
    parts = []
    if port > 1:
        parts.append(f"1-{port - 1}")
    if port < 65535:
        parts.append(f"{port + 1}-65535")
    return ",".join(parts)


def out_of_scope_regions(intent: Intent, topo: Topology) -> list[dict]:
    """Traffic regions that must be UNCHANGED by the candidate. Each region is
    (start hosts, header constraints) for a Batfish differentialReachability query;
    together they cover all host-to-host traffic except the requested flow."""
    all_hosts = list(topo.hosts)
    ip = {h: topo.hosts[h].ip for h in all_hosts}
    if intent.kind == "set_ospf_cost":  # a path preference must not change any reachability
        return [{"name": "all host traffic", "start": all_hosts, "headers": {"dstIps": ",".join(ip.values())}}]
    dst = intent.dst_host
    srcs = _hosts_in(topo, intent.src_zone)
    others = [h for h in all_hosts if h != dst]
    regions = [
        {"name": "traffic to other hosts", "start": all_hosts,
         "headers": {"dstIps": ",".join(ip[h] for h in others)}},
    ]
    outsiders = [h for h in all_hosts if h not in srcs and h != dst]
    if outsiders:
        regions.append({"name": f"other sources to {dst}", "start": outsiders, "headers": {"dstIps": ip[dst]}})
    if intent.protocol == "icmp":
        regions.append({"name": f"non-icmp from {intent.src_zone} to {dst}", "start": srcs,
                        "headers": {"dstIps": ip[dst], "ipProtocols": ["!icmp"]}})
    else:
        p = intent.protocol
        regions.append({"name": f"non-{p} from {intent.src_zone} to {dst}", "start": srcs,
                        "headers": {"dstIps": ip[dst], "ipProtocols": [f"!{p}"]}})
        regions.append({"name": f"other {p} ports from {intent.src_zone} to {dst}", "start": srcs,
                        "headers": {"dstIps": ip[dst], "ipProtocols": [p],
                                    "dstPorts": _port_complement(intent.port)}})
    return regions


def postconditions(intent: Intent, topo: Topology) -> list[dict]:
    """Flows the candidate must make work (expect=True) or must block (expect=False)."""
    if intent.kind not in ("allow_service", "block_service"):
        return []
    expect = intent.kind == "allow_service"
    return [{"src": h, "dst": intent.dst_host, "ports": intent.ports, "expect": expect}
            for h in _hosts_in(topo, intent.src_zone)]


# ---------- deterministic reference compiler (non-LLM baseline) ------------------------------

def _rule(src_cidr: str, intent: Intent, target: str) -> str:
    if intent.protocol == "icmp":
        return f"-A INPUT -s {src_cidr} -p icmp -j {target}"
    return f"-A INPUT -s {src_cidr} -p {intent.protocol} --dport {intent.port} -j {target}"


def _insert_before_commit(text: str, line: str) -> str:
    return re.sub(r"^COMMIT\s*$", line + "\nCOMMIT", text, count=1, flags=re.M)


def _insert_first_rule(text: str, line: str) -> str:
    m = re.search(r"^-A INPUT", text, flags=re.M)
    if not m:
        return _insert_before_commit(text, line)
    return text[: m.start()] + line + "\n" + text[m.start():]


def compile_intent(intent: Intent, topo: Topology, state: NetworkState) -> NetworkState:
    """Reference implementation of each change type, in the verifier-safe dialect."""
    if intent.kind == "allow_service":
        dst = intent.dst_host
        cidr = topo.zones[intent.src_zone]
        text = state.get(dst, IPT)
        rule = _rule(cidr, intent, "ACCEPT")
        out = state
        if rule not in text:
            # explicit DROPs above would shadow an appended ACCEPT, so insert at the top
            new = _insert_first_rule(text, rule) if "-j DROP" in text else _insert_before_commit(text, rule)
            out = out.with_file(dst, IPT, new)
        # stateless host firewalls: a source host that has a firewall needs a return-traffic rule
        if intent.protocol != "icmp":
            ret = f"-A INPUT -s {topo.hosts[dst].ip}/32 -p {intent.protocol} --sport {intent.port} -j ACCEPT"
            for h in _hosts_in(topo, intent.src_zone):
                if topo.hosts[h].firewall and ret not in out.get(h, IPT):
                    out = out.with_file(h, IPT, _insert_before_commit(out.get(h, IPT), ret))
        return out
    if intent.kind == "block_service":
        dst = intent.dst_host
        cidr = topo.zones[intent.src_zone]
        text = state.get(dst, IPT)
        accept = _rule(cidr, intent, "ACCEPT")
        text = "\n".join(ln for ln in text.splitlines() if ln.strip() != accept) + "\n"
        drop = _rule(cidr, intent, "DROP")
        if drop not in text:
            text = _insert_first_rule(text, drop)
        return state.with_file(dst, IPT, text)
    if intent.kind == "set_ospf_cost":
        r, ifn = intent.router, intent.interface
        lines = state.get(r, FRR).splitlines()
        out, in_if, done = [], False, False
        for ln in lines:
            if ln.startswith("interface "):
                in_if = ln.split()[1] == ifn
            elif in_if and ln.startswith(" ip ospf cost "):
                continue  # replaced below
            if in_if and ln.strip() == "!" and not done:
                out.append(f" ip ospf cost {intent.cost}")
                done = True
                in_if = False
            out.append(ln)
        return state.with_file(r, FRR, "\n".join(out) + "\n")
    raise ValueError(f"cannot compile intent {intent.summary()}")
