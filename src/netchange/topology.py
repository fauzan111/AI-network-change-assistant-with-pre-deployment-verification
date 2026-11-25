"""Typed model of network/topology.yml, the single source of truth for the lab."""

from __future__ import annotations

import ipaddress
from functools import cached_property
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class RouterInterface(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: str  # CIDR, e.g. 10.255.0.0/31
    peer: str | None = None  # router on the other end of a point-to-point link
    lan: str | None = None  # zone name of a host-facing LAN

    @property
    def iface(self) -> ipaddress.IPv4Interface:
        return ipaddress.IPv4Interface(self.address)

    @property
    def is_lan(self) -> bool:
        return self.lan is not None


class Router(BaseModel):
    model_config = ConfigDict(extra="forbid")
    loopback: str
    interfaces: dict[str, RouterInterface]

    @property
    def router_id(self) -> str:
        return str(ipaddress.IPv4Interface(self.loopback).ip)


class Host(BaseModel):
    model_config = ConfigDict(extra="forbid")
    router: str
    router_if: str
    address: str
    listen: list[int] = Field(default_factory=list)
    firewall: bool = False

    @property
    def ip(self) -> str:
        return str(ipaddress.IPv4Interface(self.address).ip)


class Topology(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    routers: dict[str, Router]
    hosts: dict[str, Host]
    zones: dict[str, str]

    @model_validator(mode="after")
    def _check(self) -> Topology:
        for hname, h in self.hosts.items():
            r = self.routers.get(h.router)
            if r is None or h.router_if not in r.interfaces:
                raise ValueError(f"host {hname}: unknown router/interface {h.router}/{h.router_if}")
            rif = r.interfaces[h.router_if]
            if ipaddress.IPv4Interface(h.address).network != rif.iface.network:
                raise ValueError(f"host {hname}: {h.address} not in {rif.address}")
        for rname, r in self.routers.items():
            for ifname, i in r.interfaces.items():
                if (i.peer is None) == (i.lan is None):
                    raise ValueError(f"{rname}:{ifname} needs exactly one of peer/lan")
                if i.peer and i.peer not in self.routers:
                    raise ValueError(f"{rname}:{ifname} peer {i.peer} unknown")
        for z, cidr in self.zones.items():
            ipaddress.IPv4Network(cidr)  # raises on bad CIDR
        return self

    @cached_property
    def links(self) -> list[tuple[str, str, str, str]]:
        """Point-to-point router links as (router_a, if_a, router_b, if_b), each listed once."""
        out, seen = [], set()
        for ra, r in self.routers.items():
            for ia, i in r.interfaces.items():
                if not i.peer:
                    continue
                net = i.iface.network
                for ib, j in self.routers[i.peer].interfaces.items():
                    if j.peer == ra and j.iface.network == net:
                        key = frozenset([(ra, ia), (i.peer, ib)])
                        if key not in seen:
                            seen.add(key)
                            out.append((ra, ia, i.peer, ib))
        return out

    def gateway(self, host: str) -> str:
        h = self.hosts[host]
        return str(self.routers[h.router].interfaces[h.router_if].iface.ip)

    def zone_of(self, ip: str) -> list[str]:
        addr = ipaddress.IPv4Address(ip)
        return [z for z, c in self.zones.items() if addr in ipaddress.IPv4Network(c)]


def load_topology(network_dir: str | Path) -> Topology:
    data = yaml.safe_load((Path(network_dir) / "topology.yml").read_text())
    return Topology.model_validate(data)
