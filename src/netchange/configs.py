"""A network state = the native config text of every device.

Routers: network/routers/<name>/frr.conf      (FRR syntax)
Hosts:   network/hosts/<name>/iptables.rules  (iptables-save syntax, filter table only)

A change is a new NetworkState; rollback is re-applying the previous one.
"""

from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .topology import Topology

FRR = "frr.conf"
IPT = "iptables.rules"


@dataclass(frozen=True)
class NetworkState:
    files: dict[tuple[str, str], str] = field(default_factory=dict)  # (device, filename) -> text

    def get(self, device: str, filename: str) -> str:
        return self.files[(device, filename)]

    def with_file(self, device: str, filename: str, text: str) -> NetworkState:
        if not text.endswith("\n"):
            text += "\n"
        return NetworkState({**self.files, (device, filename): text})

    def digest(self) -> str:
        h = hashlib.sha256()
        for k in sorted(self.files):
            h.update(f"{k}\0{self.files[k]}\0".encode())
        return h.hexdigest()[:12]

    def changed_files(self, other: NetworkState) -> list[tuple[str, str]]:
        keys = set(self.files) | set(other.files)
        return sorted(k for k in keys if self.files.get(k) != other.files.get(k))

    def diff(self, other: NetworkState) -> str:
        """Unified diff from self (before) to other (after)."""
        out = []
        for dev, fn in self.changed_files(other):
            a = self.files.get((dev, fn), "").splitlines(keepends=True)
            b = other.files.get((dev, fn), "").splitlines(keepends=True)
            out.extend(difflib.unified_diff(a, b, f"a/{dev}/{fn}", f"b/{dev}/{fn}"))
        return "".join(out)


def load_state(network_dir: str | Path, topo: Topology) -> NetworkState:
    nd = Path(network_dir)
    files: dict[tuple[str, str], str] = {}
    for r in topo.routers:
        files[(r, FRR)] = (nd / "routers" / r / FRR).read_text()
    for h, host in topo.hosts.items():
        if host.firewall:
            files[(h, IPT)] = (nd / "hosts" / h / IPT).read_text()
    return NetworkState(files)


def save_state(network_dir: str | Path, state: NetworkState) -> None:
    nd = Path(network_dir)
    for (dev, fn), text in state.files.items():
        kind = "routers" if fn == FRR else "hosts"
        p = nd / kind / dev / fn
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
