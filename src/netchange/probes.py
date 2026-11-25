"""Turn invariants (and an intent's expected outcome) into live connectivity probes."""

from __future__ import annotations

import ipaddress

from .lab import Probe
from .topology import Topology


def _as_list(x) -> list[str]:
    return [x] if isinstance(x, str) else list(x)


def hosts_in(topo: Topology, zone: str) -> list[str]:
    net = ipaddress.IPv4Network(topo.zones[zone])
    return [h for h, x in topo.hosts.items() if ipaddress.IPv4Address(x.ip) in net]


def port_samples(topo: Topology, dst: str, ports: str) -> list[str]:
    """Concrete probes for a port spec. 'any' -> every service the host runs, plus icmp."""
    if ports == "any":
        return [f"tcp/{p}" for p in topo.hosts[dst].listen] + ["icmp"]
    return [ports]


def invariant_probes(topo: Topology, inv: dict) -> list[Probe]:
    out: list[Probe] = []
    for r in inv.get("require", []):
        out.append(Probe(r["from"], r["to"], r["ports"], "open"))
    for r in inv.get("deny", []):
        for src in hosts_in(topo, r["from"]):
            for dst in _as_list(r["to"]):
                out += [Probe(src, dst, p, "blocked") for p in port_samples(topo, dst, r.get("ports", "any"))]
    for r in inv.get("only", []):
        dsts = _as_list(r["to"])
        allowed = {h for z in r["allowed_from"] for h in hosts_in(topo, z)}
        for src in topo.hosts:
            if src in allowed or src in dsts:
                continue
            out += [Probe(src, dst, r["ports"], "blocked") for dst in dsts]
    # de-duplicate (same src/dst/port may come from several rules)
    seen, uniq = set(), []
    for p in out:
        k = (p.src, p.dst, p.ports)
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    return uniq
