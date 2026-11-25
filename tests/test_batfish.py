"""Verifier tests against a real Batfish service (skipped when it is not running)."""

import socket
from pathlib import Path

import pytest

from netchange.configs import FRR, IPT, load_state
from netchange.intent import Intent, compile_intent
from netchange.topology import load_topology
from netchange.verify import Verifier, load_invariants

ROOT = Path(__file__).resolve().parents[1]


def _batfish_up() -> bool:
    try:
        socket.create_connection(("localhost", 9996), timeout=1).close()
        return True
    except OSError:
        return False


pytestmark = [pytest.mark.batfish, pytest.mark.skipif(not _batfish_up(), reason="Batfish not running")]


@pytest.fixture(scope="module")
def env():
    topo = load_topology(ROOT / "network")
    state = load_state(ROOT / "network", topo)
    v = Verifier(topo, load_invariants(ROOT / "network"))
    return topo, state, v, v.load(state, "baseline-" + state.digest())


def test_baseline_passes_every_check(env):
    _, state, v, _ = env
    verdict = v.verify(state)
    assert verdict.passed, [c.id for c in verdict.failures]
    assert len(verdict.checks) == 14


@pytest.mark.parametrize("mutate,expected", [
    (lambda s: s.with_file("web1", IPT, s.get("web1", IPT).replace(
        "COMMIT", "-A INPUT -s 10.0.0.0/8 -p tcp --dport 443 -j ACCEPT\nCOMMIT")), "guest-isolated-from-datacenter"),
    (lambda s: s.with_file("web1", IPT, s.get("web1", IPT).replace(
        "-A INPUT -s 10.3.20.0/24 -p tcp --sport 5432 -j ACCEPT\n", "")), "web-db"),
    (lambda s: s.with_file("dc", FRR, s.get("dc", FRR).replace(
        "description p2p:core1\n ip ospf network point-to-point\n ip ospf area 0",
        "description p2p:core1\n ip ospf network point-to-point\n ip ospf area 1")), "ospf-full-adjacency"),
    (lambda s: s.with_file("dc", FRR, s.get("dc", FRR).replace(
        " ip ospf area 0\n!\nrouter", " ip ospf area 0\n ip ospf hello-interval 1\n!\nrouter")), "no-init-issues"),
])
def test_bad_changes_are_caught(env, mutate, expected):
    _, state, v, _ = env
    verdict = v.verify(mutate(state))
    assert expected in {c.id for c in verdict.failures}


def test_scope_catches_overbroad_rule(env):
    topo, state, v, base = env
    intent = Intent(status="ok", kind="allow_service", src_zone="branch-users", dst_host="web1",
                    protocol="tcp", port=443)
    broad = state.with_file("web1", IPT, state.get("web1", IPT).replace(
        "COMMIT", "-A INPUT -s 10.2.10.0/24 -p tcp --dport 443 -j ACCEPT\n-A INPUT -s 10.2.10.0/24 -p icmp -j ACCEPT\nCOMMIT"))
    snap = v.load(broad)
    failed = {c.id for c in v.check_intent(base, snap, intent) if not c.passed}
    assert any(f.startswith("scope: non-tcp") for f in failed)
    good = compile_intent(intent, topo, state)
    assert all(c.passed for c in v.check_intent(base, v.load(good), intent))
