"""Generate the baseline FRR configs from topology.yml (run once; the output is committed).

After bootstrap, frr.conf files are the native source of truth that changes edit.
"""

from __future__ import annotations

from .topology import Topology

FRR_VERSION = "10.2.1"


def baseline_frr(topo: Topology, router: str) -> str:
    r = topo.routers[router]
    out = [
        f"frr version {FRR_VERSION}",
        "frr defaults traditional",
        f"hostname {router}",
        "service integrated-vtysh-config",
        "!",
        "interface lo",
        " ip ospf area 0",
        "!",
    ]
    for ifname, i in r.interfaces.items():
        out.append(f"interface {ifname}")
        if i.is_lan:
            out.append(f" description lan:{i.lan}")
        else:
            out.append(f" description p2p:{i.peer}")
            out.append(" ip ospf network point-to-point")
        out.append(" ip ospf area 0")
        out.append("!")
    out += ["router ospf", f" ospf router-id {r.router_id}"]
    out += [f" passive-interface {ifname}" for ifname, i in r.interfaces.items() if i.is_lan]
    out += ["!", "line vty", "!", ""]
    return "\n".join(out)
