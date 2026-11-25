"""Verifier-safe iptables dialect.

Batfish mis-models several common iptables constructs, some silently and some
fail-open (see docs/FINDINGS.md and scripts/probe_batfish_iptables.py). A firewall
change is only verifiable if every line is in the subset Batfish models exactly, so
candidates are linted BEFORE verification and anything outside the subset is rejected
with a rewrite hint (fail closed).

Allowed rule shape (INPUT chain only):
  -A INPUT [-s CIDR] [-d CIDR] [-p tcp|udp|icmp [-m tcp|udp]] [--sport N] [--dport N] -j ACCEPT|DROP
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass

CHAIN_RE = re.compile(r"^:(INPUT|FORWARD|OUTPUT) (ACCEPT|DROP) \[\d+:\d+\]$")

# construct -> why it is rejected (fidelity verdict from the probe) + how to rewrite
REJECTED = {
    "-m multiport": "silently never matches in Batfish (fail-closed); write one rule per port",
    "-m conntrack": "connection state is not modelled for host filters; use an explicit stateless "
                    "return rule, e.g. -s <server-net> -p tcp --sport <port> -j ACCEPT",
    "-m state": "connection state is not modelled for host filters; use an explicit stateless return rule",
    "-m comment": "silently breaks the rule in Batfish (fail-closed); put comments on their own '#' line",
    "-i": "'-i lo' is silently treated as match-all by Batfish (fail-open); interface matches are not allowed",
    "-o": "interface matches are not allowed",
    "!": "negation causes a Batfish conversion error; list the allowed sources explicitly",
    "-j REJECT": "REJECT is skipped by Batfish (fail-open); use -j DROP",
    "port range": "port ranges silently never match in Batfish (fail-closed); write one rule per port",
    "comma list": "comma-separated addresses silently never match in Batfish (fail-closed); one rule per CIDR",
    "custom chain": "jumps to user chains are skipped by Batfish; keep all rules in INPUT",
}


@dataclass
class LintIssue:
    line: int
    text: str
    reason: str

    def __str__(self) -> str:
        return f"line {self.line}: {self.text!r}: {self.reason}"


def _cidr_ok(v: str) -> str | None:
    if "," in v:
        return REJECTED["comma list"]
    try:
        ipaddress.IPv4Network(v, strict=False)
    except ValueError:
        return f"invalid address {v!r}"
    return None


def _port_ok(v: str) -> str | None:
    if ":" in v or "," in v:
        return REJECTED["port range"]
    if not v.isdigit() or not 1 <= int(v) <= 65535:
        return f"invalid port {v!r}"
    return None


def lint_rule(tokens: list[str]) -> str | None:
    """Return a reason if the rule is outside the dialect, else None."""
    if tokens[:2] != ["-A", "INPUT"]:
        if tokens[:1] == ["-A"]:
            return f"only INPUT rules are allowed, got chain {tokens[1] if len(tokens) > 1 else '?'}"
        return "rules must start with '-A INPUT'"
    i, proto, seen = 2, None, set()
    target = None
    while i < len(tokens):
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if t == "!":
            return REJECTED["!"]
        if t in ("-i", "-o", "--in-interface", "--out-interface"):
            return REJECTED["-i" if t in ("-i", "--in-interface") else "-o"]
        if t in seen and t != "-m":
            return f"duplicate option {t}"
        seen.add(t)
        if nxt is None:
            return f"option {t} needs a value"
        if t in ("-s", "--source", "-d", "--destination"):
            if err := _cidr_ok(nxt):
                return err
        elif t in ("-p", "--protocol"):
            if nxt not in ("tcp", "udp", "icmp"):
                return f"protocol must be tcp, udp or icmp, got {nxt!r}"
            proto = nxt
        elif t in ("-m", "--match"):
            if nxt in ("tcp", "udp"):
                if nxt != proto:
                    return f"-m {nxt} must follow -p {nxt}"
            else:
                return REJECTED.get(f"-m {nxt}", f"match module {nxt!r} is not allowed")
        elif t in ("--dport", "--sport", "--destination-port", "--source-port"):
            if proto not in ("tcp", "udp"):
                return f"{t} needs -p tcp or -p udp before it"
            if err := _port_ok(nxt):
                return err
        elif t in ("-j", "--jump"):
            if nxt == "REJECT":
                return REJECTED["-j REJECT"]
            if nxt not in ("ACCEPT", "DROP"):
                return REJECTED["custom chain"] if nxt.isupper() or nxt.isalnum() else f"bad target {nxt!r}"
            target = nxt
        else:
            return f"option {t!r} is not in the verifier-safe dialect"
        i += 2
    if target is None:
        return "rule needs -j ACCEPT or -j DROP"
    return None


def lint(text: str) -> list[LintIssue]:
    issues: list[LintIssue] = []
    tables, committed, chains = 0, False, set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            tables += 1
            if line != "*filter":
                issues.append(LintIssue(n, line, "only the filter table is allowed"))
            continue
        if line == "COMMIT":
            committed = True
            continue
        if line.startswith(":"):
            m = CHAIN_RE.match(line)
            if not m:
                issues.append(LintIssue(n, line, REJECTED["custom chain"]))
            elif m.group(1) != "INPUT" and m.group(2) != "ACCEPT":
                issues.append(LintIssue(n, line, f"{m.group(1)} policy must be ACCEPT"))
            else:
                chains.add(m.group(1))
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as e:
            issues.append(LintIssue(n, line, f"cannot tokenise: {e}"))
            continue
        if reason := lint_rule(tokens):
            issues.append(LintIssue(n, line, reason))
    if tables != 1:
        issues.append(LintIssue(0, "", f"expected exactly one '*filter' table, found {tables}"))
    if not committed:
        issues.append(LintIssue(0, "", "missing COMMIT"))
    if chains != {"INPUT", "FORWARD", "OUTPUT"}:
        issues.append(LintIssue(0, "", "must declare :INPUT, :FORWARD and :OUTPUT policies"))
    return issues
