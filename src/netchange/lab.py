"""Drive the Containerlab lab: deploy, push configs, apply/rollback a NetworkState, probe.

Containerlab runs from its own container image against the local Docker daemon, so
the only host requirement is Docker (tested with Docker Desktop on Apple Silicon).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .configs import FRR, IPT, NetworkState
from .render import write_clab
from .topology import Topology

CLAB_IMAGE = "ghcr.io/srl-labs/clab:0.83.0"


def _docker_env() -> dict:
    env = dict(os.environ)
    app_bin = "/Applications/Docker.app/Contents/Resources/bin"
    if Path(app_bin).exists() and app_bin not in env.get("PATH", ""):
        env["PATH"] = f"{app_bin}:{env.get('PATH', '')}"
    return env


def sh(args: list[str], stdin: str | None = None, check: bool = True, timeout: int = 120) -> str:
    p = subprocess.run(args, input=stdin, capture_output=True, text=True, env=_docker_env(), timeout=timeout,
                       check=False)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} -> {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p.stdout


@dataclass
class Probe:
    """expect: 'open' (service answers), 'reachable' (packet reaches the host: open or refused,
    i.e. the network permits it) or 'blocked' (dropped on the way: timeout)."""

    src: str
    dst: str  # host name
    ports: str  # tcp/443 | icmp
    expect: str
    got: str | None = None  # open | refused | blocked

    @property
    def ok(self) -> bool:
        if self.expect == "open":
            return self.got == "open"
        if self.expect == "reachable":
            return self.got in ("open", "refused")
        return self.got == "blocked"


class Lab:
    def __init__(self, topo: Topology, build_dir: str | Path = "build/lab"):
        self.topo = topo
        self.build = Path(build_dir).resolve()

    def node(self, name: str) -> str:
        return f"clab-{self.topo.name}-{name}"

    def exec(self, name: str, cmd: str, stdin: str | None = None, check: bool = True, timeout: int = 60) -> str:
        args = ["docker", "exec"] + (["-i"] if stdin is not None else []) + [self.node(name), "sh", "-c", cmd]
        return sh(args, stdin=stdin, check=check, timeout=timeout)

    # ---- lifecycle ----------------------------------------------------------------------------
    def _clab(self, action: str, *extra: str) -> str:
        topo_file = write_clab(self.topo, self.build)
        d = str(self.build)
        return sh(["docker", "run", "--rm", "--privileged", "--network", "host", "--pid", "host",
                   "-v", "/var/run/docker.sock:/var/run/docker.sock",
                   "-v", "/var/run/netns:/var/run/netns",
                   "-v", "/var/lib/docker/containers:/var/lib/docker/containers",
                   "-v", f"{d}:{d}", "-w", d, CLAB_IMAGE,
                   "containerlab", action, "-t", topo_file.name, *extra], timeout=300)

    def deploy(self, state: NetworkState) -> None:
        self._clab("deploy", "--reconfigure")
        with ThreadPoolExecutor(12) as ex:
            list(ex.map(self._init_router, self.topo.routers))
            list(ex.map(self._init_host, self.topo.hosts))
        self.push(state)

    def destroy(self) -> None:
        self._clab("destroy", "--cleanup")

    def running(self) -> bool:
        out = sh(["docker", "ps", "--format", "{{.Names}}"], check=False)
        names = set(out.split())
        return all(self.node(n) in names for n in [*self.topo.routers, *self.topo.hosts])

    def _init_router(self, r: str) -> None:
        rt = self.topo.routers[r]
        cmds = ["sysctl -qw net.ipv4.ip_forward=1", f"ip addr replace {rt.loopback} dev lo"]
        cmds += [f"ip addr replace {i.address} dev {ifn}" for ifn, i in rt.interfaces.items()]
        self.exec(r, " && ".join(cmds))

    def _init_host(self, h: str) -> None:
        host = self.topo.hosts[h]
        self.exec(h, f"ip addr replace {host.address} dev eth1 && "
                     f"ip route replace default via {self.topo.gateway(h)} dev eth1")
        if host.listen:
            self.exec(h, "pkill -f listener.py; true", check=False)
            sh(["docker", "exec", "-d", self.node(h), "python3", "/usr/local/bin/listener.py",
                *map(str, host.listen)])

    # ---- config push --------------------------------------------------------------------------
    def push_file(self, device: str, filename: str, text: str) -> None:
        if filename == FRR:
            self.exec(device, "cat > /etc/frr/frr.conf.new", stdin=text)
            # frr-reload diffs the candidate against the running config and applies the delta
            self.exec(device, "/usr/lib/frr/frr-reload.py --reload /etc/frr/frr.conf.new "
                              "&& cp /etc/frr/frr.conf.new /etc/frr/frr.conf", timeout=60)
        elif filename == IPT:
            self.exec(device, "iptables-restore", stdin=text)  # replaces the filter table only
        else:
            raise ValueError(filename)

    def push(self, state: NetworkState, only: list[tuple[str, str]] | None = None) -> None:
        keys = only if only is not None else list(state.files)
        with ThreadPoolExecutor(8) as ex:
            list(ex.map(lambda k: self.push_file(k[0], k[1], state.files[k]), keys))

    def running_frr(self, r: str) -> str:
        return self.exec(r, "vtysh -c 'show running-config'")

    # ---- runtime checks -----------------------------------------------------------------------
    def ospf_full(self) -> dict[str, tuple[int, int]]:
        """router -> (full neighbours, expected neighbours)."""
        out = {}
        for r, rt in self.topo.routers.items():
            want = sum(1 for i in rt.interfaces.values() if i.peer)
            try:
                js = json.loads(self.exec(r, "vtysh -c 'show ip ospf neighbor json'") or "{}")
                nbrs = js.get("neighbors", {})
                full = sum(1 for v in nbrs.values() for n in v if str(n.get("nbrState", "")).startswith("Full"))
            except (RuntimeError, json.JSONDecodeError):
                full = 0
            out[r] = (full, want)
        return out

    def wait_converged(self, timeout: float = 60, settle: float = 2.0) -> tuple[bool, float]:
        """Wait until every router has all expected OSPF neighbours Full and routes are stable."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            st = self.ospf_full()
            if all(f == w for f, w in st.values()):
                time.sleep(settle)
                return True, time.time() - t0
            time.sleep(1)
        return False, time.time() - t0

    def probe(self, p: Probe) -> Probe:
        ip = self.topo.hosts[p.dst].ip
        if p.ports == "icmp":
            out = self.exec(p.src, f"ping -c1 -W1 {ip} >/dev/null 2>&1 && echo OK || echo FAIL", check=False)
            p.got = "open" if out.strip() == "OK" else "blocked"
            return p
        proto, _, port = p.ports.partition("/")
        if proto != "tcp":
            raise ValueError(f"lab probes support tcp/icmp, got {p.ports}")
        out = self.exec(p.src, f"nc -z -v -w 2 {ip} {port} 2>&1; echo rc=$?", check=False)
        if "rc=0" in out:
            p.got = "open"
        elif "refused" in out.lower():  # RST from the host: the firewall let it through, no listener
            p.got = "refused"
        else:
            p.got = "blocked"
        return p

    def run_probes(self, probes: list[Probe]) -> list[Probe]:
        with ThreadPoolExecutor(16) as ex:
            return list(ex.map(self.probe, probes))
