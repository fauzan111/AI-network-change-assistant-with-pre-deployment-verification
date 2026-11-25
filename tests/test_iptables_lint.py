from pathlib import Path

import pytest

from netchange.iptables_lint import lint, lint_rule

ROOT = Path(__file__).resolve().parents[1]
HEAD = "*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"


def doc(*rules: str) -> str:
    return HEAD + "".join(r + "\n" for r in rules) + "COMMIT\n"


@pytest.mark.parametrize("host", ["web1", "db1"])
def test_baseline_rules_are_in_dialect(host):
    assert lint((ROOT / "network/hosts" / host / "iptables.rules").read_text()) == []


@pytest.mark.parametrize("rule", [
    "-A INPUT -s 10.1.10.0/24 -p tcp --dport 443 -j ACCEPT",
    "-A INPUT -s 10.1.10.0/24 -p tcp -m tcp --dport 443 -j ACCEPT",
    "-A INPUT -d 10.3.10.10/32 -p udp --dport 53 -j ACCEPT",
    "-A INPUT -s 10.3.20.0/24 -p tcp --sport 5432 -j ACCEPT",
    "-A INPUT -s 10.4.10.0/24 -j DROP",
    "-A INPUT -p icmp -j ACCEPT",
])
def test_exact_constructs_allowed(rule):
    assert lint_rule(rule.split()) is None


@pytest.mark.parametrize("rule,needle", [
    ("-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT", "one rule per port"),
    ("-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "stateless return rule"),
    ("-A INPUT -i lo -j ACCEPT", "fail-open"),
    ("-A INPUT ! -s 10.4.10.0/24 -j ACCEPT", "negation"),
    ("-A INPUT -s 10.4.10.0/24 -j REJECT", "use -j DROP"),
    ("-A INPUT -p tcp --dport 8000:8100 -j ACCEPT", "port ranges"),
    ("-A INPUT -s 10.1.10.0/24,10.2.10.0/24 -j ACCEPT", "comma"),
    ("-A INPUT -p tcp --dport 443 -m comment --comment web -j ACCEPT", "comments"),
    ("-A INPUT -j WEB", "user chains"),
    ("-A FORWARD -j ACCEPT", "only INPUT"),
    ("-A INPUT --dport 443 -j ACCEPT", "needs -p tcp"),
    ("-A INPUT -p tcp --dport 443", "needs -j"),
    ("-A INPUT -p gre -j ACCEPT", "protocol"),
])
def test_unsafe_constructs_rejected_with_hint(rule, needle):
    import shlex

    reason = lint_rule(shlex.split(rule))
    assert reason is not None and needle in reason


def test_structure_checks():
    assert lint(doc("-A INPUT -p icmp -j ACCEPT")) == []
    assert any("COMMIT" in i.reason for i in lint(HEAD + "-A INPUT -p icmp -j ACCEPT\n"))
    assert any("nat" not in i.reason and "filter table" in i.reason for i in lint(doc() + "*nat\nCOMMIT\n"))
    assert any("FORWARD policy" in i.reason for i in lint(doc().replace(":FORWARD ACCEPT", ":FORWARD DROP")))
