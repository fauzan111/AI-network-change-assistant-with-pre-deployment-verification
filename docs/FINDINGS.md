# Findings

What I learned building a verifier-gated change pipeline on Batfish + Containerlab. Every claim
below is reproducible with a script in this repo.

## 1. The verifier itself can be wrong: Batfish vs Linux iptables

A pre-deployment check is only as good as the model behind it. `scripts/probe_batfish_iptables.py`
builds a one-host snapshot per construct (`INPUT` policy DROP + one rule) and asks Batfish
(`testFilters`) about a new TCP connection that Linux **would** match and one it would **not**.
Raw output: [`iptables_fidelity.json`](iptables_fidelity.json).

| Construct | Batfish behaviour | Warning? | Effect on a security check |
|---|---|---|---|
| `-s/-d CIDR -p tcp --dport N` (incl. `-m tcp`) | exact | - | safe |
| `--sport N` | exact | - | safe |
| `-i eth1` | exact | - | safe |
| `-j DROP` before `ACCEPT` | exact | - | safe |
| **`-i lo -j ACCEPT`** | **matches every packet** | **no** | **fail-open, silent**: a standard first line of many host firewalls makes Batfish think everything is allowed |
| `-j REJECT` | rule skipped | red flag | fail-open, but loud |
| `! -s CIDR` (negation) | conversion error, filter not built | yes | loud |
| `--dport 8000:8100` (range) | never matches | no | fail-closed, silent |
| `-s a,b` (comma list) | never matches | no | fail-closed, silent |
| `-m multiport --dports 80,443` | never matches | no | fail-closed, silent |
| `-m comment --comment x` | rule never matches | no | fail-closed, silent |
| custom chain (`-j WEB`) | jump skipped | red flag | fail-closed, loud |
| `-m conntrack/state ESTABLISHED` | never matches (SYN or stray ACK) | no | replies are not modelled; return traffic needs an explicit stateless rule |

**What the pipeline does about it.**
- **A dialect the checker models exactly.** [`iptables_lint.py`](../src/netchange/iptables_lint.py) allows only the constructs marked *exact* above, and every rejection comes with a rewrite hint, for example "write one rule per port".
- **Fail closed on warnings.** A candidate with any Batfish parse warning or conversion issue is rejected (`no-init-issues`), which catches the loud cases even without the linter.

**Correction during development:** my first quick test blamed `conntrack` for a fail-open result. The probe showed the real culprit was the `-i lo` line in the same file. This is why the probe tests one construct at a time.

## 2. FRR coverage in Batfish

- There is no standalone FRR format. FRR routers are given in Batfish's *Cumulus concatenated* format: hostname, then `/etc/network/interfaces`, then `ports.conf`, then `frr.conf`, separated by marker lines. Interface addresses come from the interfaces section ([`render.py`](../src/netchange/render.py)).
- These are not recognised, so the checker rejects them:
  - `ip ospf passive` written under an interface; `passive-interface` under `router ospf` works;
  - `ip ospf hello-interval` and `ip ospf dead-interval`.
- `ip ospf cost` is modelled, and OSPF path selection follows it.
- Cumulus/FRR routers have no packet-filter model, so access policy lives in host firewalls, which Batfish does model. This is a design constraint, documented in [`topology.yml`](../network/topology.yml).

**Consequence:** valid FRR that Batfish can't read is rejected by design. The evaluation counts this under "legitimate changes wrongly rejected", the price of failing closed.

## 3. Stateless return rules widen access, and the scope check notices

Host firewalls here are stateless (see section 1), so a host with a firewall that *initiates* a
connection needs a return rule such as `-s db1 -p tcp --sport 443 -j ACCEPT`. That rule also lets
db1 reach **any** port on web1, as long as the traffic uses source port 443. The out-of-scope
differential reachability check flags it, so the requests "web tier to db1 over HTTPS, HTTP or SSH"
are rejected: they can't be met without side effects on this kind of firewall. The baseline's own
`--sport 5432` rule has the same weakness, which is the argument for stateful firewalls that the
checker can model.

## 4. The model is not the network: drift, absent services, pre-flight

Batfish checks configuration files, not the running network. Three live cases are built into the evaluation:

| Case | What happens | Pipeline result |
|---|---|---|
| Out-of-band blackhole route on the branch router | Batfish approves; the requested flow fails live | **rolled back**, rollback checked against the pre-flight snapshot |
| Hand-added DROP on web1 | Applying the verified file replaces it | applied: the source of truth wins |
| Blackhole on hq that already breaks management SSH to db1 | The network is unhealthy *before* the change | **pre-flight refuses to change anything** |
| Firewall opened to a port where nothing listens | The probe sees a TCP RST, not a drop | applied: the network change is correct, the service is a separate problem |

Live probes have three states: *open* (service answered), *refused* (RST: the network let the
packet through) and *blocked* (timeout: dropped). A firewall change is judged on
reachability, not on whether an application happens to be running.

## 5. Tooling notes

- Containerlab 0.83 runs from its container image against **plain Docker Desktop** on Apple Silicon (M5). OrbStack isn't needed. FRR 10.2.1 and Alpine images are native arm64.
- `batfish/allinone` has a native arm64 image. Checking a candidate against all 14 invariants takes about 2.5 s.
