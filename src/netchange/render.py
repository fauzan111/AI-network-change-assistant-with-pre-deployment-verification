"""Render a NetworkState into (a) a Batfish snapshot and (b) a Containerlab topology.

Batfish has no standalone FRR format; FRR routers are given in the Cumulus
"concatenated" format: hostname, /etc/network/interfaces, ports.conf, frr.conf,
separated by the marker lines Batfish looks for. Interface addresses live in the
interfaces section (rendered from topology.yml); routing lives in frr.conf.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from .configs import FRR, IPT, NetworkState
from .topology import Topology

ROUTER_IMAGE = "netchange-frr:1"
HOST_IMAGE = "netchange-host:1"
MGMT_SUBNET = "172.30.30.0/24"


def cumulus_concatenated(topo: Topology, router: str, frr_conf: str) -> str:
    r = topo.routers[router]
    lines = [
        router,
        "# This file describes the network interfaces available on your system",
        "# and how to activate them. For more information, see interfaces(5).",
        "",
        "auto lo",
        "iface lo inet loopback",
        f"    address {r.loopback}",
        "",
    ]
    for ifname, i in r.interfaces.items():
        lines += [f"auto {ifname}", f"iface {ifname}", f"    address {i.address}", ""]
    lines += ["# ports.conf --", ""]
    body = frr_conf if frr_conf.lstrip().startswith("frr version") else "frr version 10.2.1\n" + frr_conf
    return "\n".join(lines) + "\n" + body


def batfish_snapshot(topo: Topology, state: NetworkState, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    (out / "configs").mkdir(parents=True)
    (out / "hosts").mkdir()
    (out / "iptables").mkdir()
    for r in topo.routers:
        (out / "configs" / f"{r}.cfg").write_text(cumulus_concatenated(topo, r, state.get(r, FRR)))
    for h, host in topo.hosts.items():
        spec: dict = {
            "hostname": h,
            "hostInterfaces": {
                "eth1": {"name": "eth1", "prefix": host.address, "gateway": topo.gateway(h)}
            },
        }
        if host.firewall:
            spec["iptablesFile"] = f"iptables/{h}.iptables"
            (out / "iptables" / f"{h}.iptables").write_text(state.get(h, IPT))
        (out / "hosts" / f"{h}.json").write_text(json.dumps(spec, indent=1))
    return out


def clab_topology(topo: Topology) -> dict:
    """Containerlab topology. Configs are pushed after deploy (see lab.py), not bind-mounted,
    so initial push, change and rollback all use the same code path."""
    nodes: dict[str, dict] = {}
    for r in topo.routers:
        nodes[r] = {"kind": "linux", "image": ROUTER_IMAGE}
    for h, host in topo.hosts.items():
        nodes[h] = {"kind": "linux", "image": HOST_IMAGE}
    links = [{"endpoints": [f"{a}:{ia}", f"{b}:{ib}"]} for a, ia, b, ib in topo.links]
    for h, host in topo.hosts.items():
        links.append({"endpoints": [f"{host.router}:{host.router_if}", f"{h}:eth1"]})
    return {
        "name": topo.name,
        "mgmt": {"network": f"{topo.name}-mgmt", "ipv4-subnet": MGMT_SUBNET},
        "topology": {"nodes": nodes, "links": links},
    }


def write_clab(topo: Topology, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    p = out / f"{topo.name}.clab.yml"
    p.write_text(yaml.safe_dump(clab_topology(topo), sort_keys=False))
    return p
