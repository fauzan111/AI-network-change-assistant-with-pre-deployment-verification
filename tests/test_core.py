"""Unit tests that need neither Docker nor Batfish."""

from pathlib import Path

import pytest

from netchange.configs import FRR, IPT, load_state
from netchange.intent import Intent, compile_intent, out_of_scope_regions, postconditions, validate_intent
from netchange.iptables_lint import lint
from netchange.pipeline import _ospf_costs, _rules, risk_of
from netchange.render import batfish_snapshot, clab_topology, cumulus_concatenated
from netchange.topology import load_topology

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def topo():
    return load_topology(ROOT / "network")


@pytest.fixture(scope="module")
def state(topo):
    return load_state(ROOT / "network", topo)


def allow(zone="branch-users", host="web1", proto="tcp", port=443):
    return Intent(status="ok", kind="allow_service", src_zone=zone, dst_host=host, protocol=proto, port=port)


def test_topology_links_and_gateways(topo):
    assert len(topo.links) == 8
    assert topo.gateway("web1") == "10.3.10.1"
    assert "guest-wifi" in topo.zone_of("10.4.10.10")


def test_cumulus_render_has_batfish_markers(topo, state):
    txt = cumulus_concatenated(topo, "dc", state.get("dc", FRR))
    assert txt.splitlines()[0] == "dc"
    for marker in ("# This file describes the network interfaces", "# ports.conf --", "frr version"):
        assert marker in txt
    assert "address 10.3.10.1/24" in txt


def test_snapshot_layout(tmp_path, topo, state):
    snap = batfish_snapshot(topo, state, tmp_path / "s")
    assert len(list((snap / "configs").glob("*.cfg"))) == 6
    assert (snap / "hosts" / "web1.json").exists() and (snap / "iptables" / "web1.iptables").exists()
    assert not (snap / "iptables" / "hq-pc.iptables").exists()


def test_clab_topology_links(topo):
    t = clab_topology(topo)
    assert len(t["topology"]["nodes"]) == 12
    assert len(t["topology"]["links"]) == 8 + 6


def test_validate_intent(topo):
    assert validate_intent(allow(), topo) == []
    assert validate_intent(allow(zone="finance"), topo)
    assert validate_intent(allow(host="hq-pc"), topo)  # no firewall to change
    bad_ospf = Intent(status="ok", kind="set_ospf_cost", router="hq", interface="eth3", cost=10)
    assert any("point-to-point" in e for e in validate_intent(bad_ospf, topo))


def test_compile_allow_is_minimal_and_in_dialect(topo, state):
    cand = compile_intent(allow(), topo, state)
    assert state.changed_files(cand) == [("web1", IPT)]
    assert "-A INPUT -s 10.2.10.0/24 -p tcp --dport 443 -j ACCEPT" in cand.get("web1", IPT)
    assert lint(cand.get("web1", IPT)) == []


def test_compile_adds_return_rule_for_firewalled_source(topo, state):
    cand = compile_intent(allow(zone="web", host="db1", port=443), topo, state)
    assert ("web1", IPT) in state.changed_files(cand)
    assert "--sport 443" in cand.get("web1", IPT)


def test_compile_block_and_ospf(topo, state):
    blk = Intent(status="ok", kind="block_service", src_zone="hq-users", dst_host="web1", protocol="tcp", port=80)
    cand = compile_intent(blk, topo, state)
    rules = _rules(cand.get("web1", IPT))
    assert rules.index("-A INPUT -s 10.1.10.0/24 -p tcp --dport 80 -j DROP") < len(rules)
    assert "-A INPUT -s 10.1.10.0/24 -p tcp --dport 80 -j ACCEPT" not in rules
    ospf = Intent(status="ok", kind="set_ospf_cost", router="branch", interface="eth1", cost=50)
    c2 = compile_intent(ospf, topo, state)
    assert _ospf_costs(c2.get("branch", FRR)) == {("eth1", "50")}
    assert _ospf_costs(compile_intent(ospf, topo, c2).get("branch", FRR)) == {("eth1", "50")}  # idempotent


def test_scope_regions_cover_everything_but_the_request(topo):
    regs = out_of_scope_regions(allow(), topo)
    names = [r["name"] for r in regs]
    assert any("other hosts" in n for n in names)
    assert any("other tcp ports" in n for n in names)
    ports = next(r for r in regs if "other tcp ports" in r["name"])["headers"]["dstPorts"]
    assert ports == "1-442,444-65535"
    ospf = Intent(status="ok", kind="set_ospf_cost", router="branch", interface="eth1", cost=50)
    assert len(out_of_scope_regions(ospf, topo)) == 1


def test_postconditions(topo):
    pcs = postconditions(allow(), topo)
    assert pcs == [{"src": "branch-pc", "dst": "web1", "ports": "tcp/443", "expect": True}]


def test_risk_policy():
    assert risk_of([("web1", IPT)]) == "low"
    assert risk_of([("branch", FRR)]) == "high"


def test_rules_normaliser_matches_iptables_save_output():
    saved = ("*filter\n:INPUT DROP [12:840]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [3:180]\n"
             "-A INPUT -s 10.1.10.0/24 -p tcp -m tcp --dport 443 -j ACCEPT\nCOMMIT\n")
    source = "# c\n*filter\n:INPUT DROP [0:0]\n-A INPUT -s 10.1.10.0/24 -p tcp --dport 443 -j ACCEPT\nCOMMIT\n"
    assert _rules(saved) == _rules(source)
