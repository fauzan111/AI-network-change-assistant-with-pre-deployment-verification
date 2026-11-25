"""LLM steps: request -> Intent, and Intent -> candidate config files (with repair feedback).

Both calls use the Claude Messages API with structured outputs (Pydantic schemas), so the
pipeline always receives typed objects. The LLM never touches the lab: whatever it writes
goes through the linter, Batfish and the intent/scope checks first.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field

from .configs import FRR, IPT, NetworkState
from .intent import Intent
from .topology import Topology

MODEL = os.environ.get("NETCHANGE_MODEL", "claude-opus-5-5")
EFFORT = os.environ.get("NETCHANGE_EFFORT", "medium")
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class FileEdit(BaseModel):
    device: str = Field(description="device name, e.g. web1 or branch")
    filename: Literal["frr.conf", "iptables.rules"]
    content: str = Field(description="the COMPLETE new content of the file, not a diff")


class Candidate(BaseModel):
    files: list[FileEdit] = Field(description="only the files that change")
    explanation: str = Field(description="one or two sentences: what changed and why")


@dataclass
class LLMUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0
    refusals: int = 0
    log: list[dict] = field(default_factory=list)


def topology_brief(topo: Topology) -> str:
    lines = ["Zones (name: CIDR):"]
    lines += [f"  {z}: {c}" for z, c in topo.zones.items()]
    lines.append("Hosts (name: address, gateway router, services, host firewall):")
    for h, x in topo.hosts.items():
        svc = ",".join(f"tcp/{p}" for p in x.listen) or "-"
        lines.append(f"  {h}: {x.address} via {x.router}, services {svc}, firewall {'yes' if x.firewall else 'no'}")
    lines.append("Routers (FRR, OSPF area 0) and point-to-point links:")
    for a, ia, b, ib in topo.links:
        lines.append(f"  {a}:{ia} <-> {b}:{ib}")
    return "\n".join(lines)


INTENT_SYSTEM = """You turn a network operator's change request into a structured intent for an \
automated change pipeline. Downstream, a verifier checks the change against the real network \
model, so your job is to capture what was asked precisely, not to decide whether it is safe.

Supported change types:
- allow_service: let hosts in one source zone reach one destination host on one protocol/port.
- block_service: stop hosts in one source zone reaching one destination host on one protocol/port.
- set_ospf_cost: set the OSPF cost of one router interface (used for path preference).

Rules:
- Use only zone, host, router and interface names from the topology below.
- Map well-known service names to ports (https=443, http=80, ssh=22, postgres=5432, dns=53/udp).
- status=clarify when an essential field cannot be determined (which zone? which server? which \
port?) and put one short question in `question`. Do not guess between two plausible readings.
- status=refuse when the request is not one of the supported change types (e.g. "open everything", \
"disable the firewall", several unrelated changes at once, changes to addressing), and say why in `reason`.
- A request that is supported but looks risky (e.g. guest access to a server) is still status=ok: \
the verifier decides. Never silently narrow or widen what was asked.

Topology:
{topology}
"""

GEN_SYSTEM = """You are a network engineer writing a configuration change for a lab network. \
You receive a structured intent and the current device configs, and you return the COMPLETE new \
content of every file you change.

Devices:
- FRR routers (frr.conf, FRR 10 syntax). Interface addresses are managed outside frr.conf.
- Server host firewalls (iptables.rules, iptables-save syntax, filter table only). Policy is \
default-DROP on INPUT. Firewalls are stateless: if a host with a firewall initiates a connection, \
its replies need their own rule (e.g. `-A INPUT -s <server>/32 -p tcp --sport <port> -j ACCEPT`).

Change exactly what the intent asks and nothing else. Keep unrelated lines byte-for-byte \
identical. Prefer the narrowest rule that satisfies the intent.
{dialect}
Topology:
{topology}
{invariants}"""

DIALECT = """
Firewall dialect (the verifier only models this subset exactly; anything else is rejected):
`-A INPUT [-s CIDR] [-d CIDR] [-p tcp|udp|icmp] [--sport N] [--dport N] -j ACCEPT|DROP`
No -m modules (multiport, conntrack, state, comment), no -i/-o, no negation (!), no port ranges, \
no comma lists, no REJECT, no custom chains. One rule per port and per source CIDR.
"""


class LLM:
    def __init__(self, model: str = MODEL, effort: str = EFFORT):
        import anthropic

        self.client = anthropic.Anthropic()
        self.model = model
        self.effort = effort
        self.usage = LLMUsage()

    def _parse(self, system: str, messages: list[dict], schema: type[BaseModel], tag: str):
        t0 = time.time()
        resp = self.client.beta.messages.parse(
            model=self.model,
            max_tokens=16000,
            system=system,
            messages=messages,
            output_format=schema,
            output_config={"effort": self.effort},
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )
        dt = time.time() - t0
        u = self.usage
        u.calls += 1
        u.seconds += dt
        u.input_tokens += resp.usage.input_tokens
        u.output_tokens += resp.usage.output_tokens
        u.log.append({"tag": tag, "model": resp.model, "seconds": round(dt, 2),
                      "in": resp.usage.input_tokens, "out": resp.usage.output_tokens,
                      "stop": resp.stop_reason, "request_id": getattr(resp, "_request_id", None)})
        if resp.stop_reason == "refusal":
            u.refusals += 1
            return None
        return resp.parsed_output


class IntentParser:
    def __init__(self, llm: LLM, topo: Topology):
        self.llm = llm
        self.system = INTENT_SYSTEM.format(topology=topology_brief(topo))

    def parse(self, request: str) -> Intent:
        out = self.llm._parse(self.system, [{"role": "user", "content": request}], Intent, "intent")
        return out or Intent(status="refuse", kind="none", reason="model declined the request")


class LLMGenerator:
    """Writes candidate configs. On repair attempts it sees the verifier's counterexamples."""

    name = "llm"

    def __init__(self, llm: LLM, topo: Topology, invariants_text: str = "",
                 dialect_hint: bool = True, show_invariants: bool = True):
        self.llm = llm
        self.topo = topo
        inv = f"\nNetwork policy that must keep holding:\n{invariants_text}" if show_invariants else ""
        self.system = GEN_SYSTEM.format(dialect=DIALECT if dialect_hint else "",
                                        topology=topology_brief(topo), invariants=inv)
        self.messages: list[dict] = []

    def _files_for(self, intent: Intent, state: NetworkState) -> dict[str, str]:
        keys = [k for k in state.files if k[1] == IPT]
        if intent.kind == "set_ospf_cost":
            keys = [(intent.router, FRR)]
        return {f"{d}/{fn}": state.files[(d, fn)] for d, fn in keys}

    def start(self, intent: Intent, state: NetworkState) -> None:
        files = self._files_for(intent, state)
        body = (f"Intent:\n{intent.model_dump_json(indent=1, exclude_none=True)}\n\n"
                f"Current files:\n" + "\n".join(f"=== {k} ===\n{v}" for k, v in files.items()))
        self.messages = [{"role": "user", "content": body}]

    def generate(self, state: NetworkState, feedback: str | None = None) -> tuple[NetworkState, str]:
        if feedback:
            self.messages.append({"role": "user", "content":
                                  "The verifier rejected that candidate:\n" + feedback +
                                  "\nReturn a corrected candidate (complete file contents)."})
        cand = self.llm._parse(self.system, self.messages, Candidate, "generate" if not feedback else "repair")
        if cand is None:
            raise RuntimeError("model declined to generate a candidate")
        self.messages.append({"role": "assistant", "content": cand.model_dump_json()})
        out = state
        for f in cand.files:
            if (f.device, f.filename) not in state.files:
                raise ValueError(f"candidate edits unknown file {f.device}/{f.filename}")
            out = out.with_file(f.device, f.filename, f.content)
        return out, cand.explanation


class TemplateGenerator:
    """Deterministic baseline: compile the intent with the reference compiler."""

    name = "template"

    def __init__(self, topo: Topology):
        self.topo = topo
        self.intent: Intent | None = None

    def start(self, intent: Intent, state: NetworkState) -> None:
        self.intent = intent

    def generate(self, state: NetworkState, feedback: str | None = None) -> tuple[NetworkState, str]:
        from .intent import compile_intent

        if feedback:
            raise RuntimeError("template generator is deterministic; nothing to repair")
        return compile_intent(self.intent, self.topo, state), "compiled from intent by the reference compiler"


def feedback_text(failures: list, lint_issues: list | None = None, limit: int = 8) -> str:
    """Compact, model-readable explanation of why a candidate was rejected."""
    lines = []
    for i in (lint_issues or [])[:limit]:
        lines.append(f"- dialect: {i}")
    for c in failures[:limit]:
        ce = f" Counterexample: {c.counterexample}" if c.counterexample else ""
        lines.append(f"- {c.kind} check '{c.id}' failed. {c.detail}{ce}".strip())
    return "\n".join(lines) or "- unspecified failure"


def dump_usage(u: LLMUsage) -> dict:
    return json.loads(json.dumps({"calls": u.calls, "input_tokens": u.input_tokens,
                                  "output_tokens": u.output_tokens, "seconds": round(u.seconds, 1),
                                  "refusals": u.refusals}))
