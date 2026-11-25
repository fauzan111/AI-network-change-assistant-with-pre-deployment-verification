"""Does Batfish model each iptables construct the way Linux does?

For every construct we build a one-host snapshot whose INPUT chain is
`policy DROP` + one rule, then ask Batfish (testFilters) about two flows:
one Linux WOULD match and one Linux would NOT match. A construct is "exact" only
if Batfish agrees with Linux on both. The verifier-safe dialect (iptables_lint.py)
allows exactly the constructs that come out exact here.

Flows are new TCP connections (SYN) arriving on eth1, which is what a firewall
must get right for access policy.

usage: python scripts/probe_batfish_iptables.py   (needs Batfish on localhost:9996)
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints, MatchTcpFlags, TcpFlags

logging.getLogger("pybatfish").setLevel(logging.ERROR)

HOST_IP = "10.3.10.10"
TCP = {"ipProtocols": ["tcp"],
       "tcpFlags": [MatchTcpFlags(tcpFlags=TcpFlags(syn=True, ack=False), useSyn=True, useAck=True)]}

ACK = {"ipProtocols": ["tcp"],
       "tcpFlags": [MatchTcpFlags(tcpFlags=TcpFlags(syn=False, ack=True), useSyn=True, useAck=True)]}

# (id, rules, header-kwargs of a flow Linux MATCHES -> ACCEPT, flow Linux does NOT match -> DROP)
CASES = [
    ("plain -s -p --dport", "-A INPUT -s 10.1.10.0/24 -p tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
    ("-m tcp --dport (iptables-save style)", "-A INPUT -s 10.1.10.0/24 -p tcp -m tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
    ("--dport range", "-A INPUT -p tcp --dport 8000:8100 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="8050", **TCP), dict(srcIps="10.1.10.5", dstPorts="8200", **TCP)),
    ("-d destination", "-A INPUT -d 10.3.10.10/32 -p tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.1.10.5", dstPorts="80", **TCP)),
    ("--sport", "-A INPUT -s 10.3.20.0/24 -p tcp --sport 5432 -j ACCEPT",
     dict(srcIps="10.3.20.10", srcPorts="5432", dstPorts="40000", **TCP),
     dict(srcIps="10.3.20.10", srcPorts="5433", dstPorts="40000", **TCP)),
    ("! -s negation", "-A INPUT ! -s 10.4.10.0/24 -p tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.4.10.5", dstPorts="443", **TCP)),
    ("comma-separated -s", "-A INPUT -s 10.1.10.0/24,10.2.10.0/24 -p tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.2.10.5", dstPorts="443", **TCP), dict(srcIps="10.4.10.5", dstPorts="443", **TCP)),
    ("-m multiport --dports", "-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
    ("-m conntrack --ctstate ESTABLISHED", "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
     None, dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
    # A lone ACK with no connection is INVALID to Linux conntrack, so ESTABLISHED must not match it.
    ("-m conntrack ESTABLISHED, stray ACK", "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
     None, dict(srcIps="10.1.10.5", dstPorts="22", **ACK)),
    ("-m state --state ESTABLISHED", "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
     None, dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
    ("-i lo", "-A INPUT -i lo -j ACCEPT", None, dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
    ("-i eth1", "-A INPUT -i eth1 -p tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
    ("-m comment", '-A INPUT -p tcp --dport 443 -m comment --comment "web" -j ACCEPT',
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
    ("-j REJECT before ACCEPT", "-A INPUT -s 10.4.10.0/24 -j REJECT\n-A INPUT -p tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.4.10.5", dstPorts="443", **TCP)),
    ("-j DROP before ACCEPT", "-A INPUT -s 10.4.10.0/24 -j DROP\n-A INPUT -p tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.4.10.5", dstPorts="443", **TCP)),
    ("custom chain jump", ":WEB - [0:0]\n-A INPUT -j WEB\n-A WEB -p tcp --dport 443 -j ACCEPT",
     dict(srcIps="10.1.10.5", dstPorts="443", **TCP), dict(srcIps="10.1.10.5", dstPorts="22", **TCP)),
]


def snapshot(rules: str, d: Path) -> Path:
    s = d / "snap"
    (s / "hosts").mkdir(parents=True)
    (s / "iptables").mkdir()
    (s / "hosts" / "h.json").write_text(json.dumps({
        "hostname": "h", "iptablesFile": "iptables/h.iptables",
        "hostInterfaces": {"eth1": {"name": "eth1", "prefix": f"{HOST_IP}/24", "gateway": "10.3.10.1"}}}))
    head = rules.split("\n")
    chains = [ln for ln in head if ln.startswith(":")]
    body = [ln for ln in head if not ln.startswith(":")]
    (s / "iptables" / "h.iptables").write_text(
        "*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        + "".join(c + "\n" for c in chains) + "\n".join(body) + "\nCOMMIT\n")
    return s


def batfish_action(bf: Session, snap: str, hdr: dict) -> str:
    ans = bf.q.testFilters(headers=HeaderConstraints(dstIps=HOST_IP, **hdr), nodes="h",
                           filters="filter::INPUT", startLocation="@enter(h[eth1])").answer(snapshot=snap).frame()
    return ans.iloc[0]["Action"] if not ans.empty else "NO_ANSWER"


def main() -> None:
    bf = Session(host="localhost")
    bf.set_network("iptables-probe")
    rows = []
    for i, (cid, rules, match, nomatch) in enumerate(CASES):
        with tempfile.TemporaryDirectory() as d:
            name = f"c{i}"
            bf.init_snapshot(str(snapshot(rules, Path(d))), name=name, overwrite=True)
        issues = bf.q.initIssues().answer(snapshot=name).frame()
        warn = "; ".join(sorted({f"{r.Type}: {r.Details}"[:90] for r in issues.itertuples()}))
        m = batfish_action(bf, name, match) if match else None
        n = batfish_action(bf, name, nomatch)
        ok_m = m in (None, "PERMIT")
        ok_n = n == "DENY"
        if ok_m and ok_n:
            verdict = "exact"
        elif not ok_n:
            verdict = "FAIL-OPEN"  # Batfish permits traffic Linux would drop
        else:
            verdict = "fail-closed"  # Batfish drops traffic Linux would accept
        rows.append({"construct": cid, "linux_match_flow": m, "linux_nomatch_flow": n,
                     "verdict": verdict, "batfish_warnings": warn})
        print(f"{verdict:12s} {cid:40s} match->{m}  nomatch->{n}  {warn[:80]}")
    out = Path(__file__).resolve().parents[1] / "docs" / "iptables_fidelity.json"
    out.write_text(json.dumps(rows, indent=1))
    print("wrote", out)


if __name__ == "__main__":
    main()
