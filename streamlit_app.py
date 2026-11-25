"""Public, read-only portfolio view of committed network-change evaluation records.

Run: streamlit run streamlit_app.py
No netchange imports: Batfish, Docker, Containerlab and LLM credentials are not needed.
"""
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st
import yaml

ROOT = Path(__file__).resolve().parent
POLICIES = {
    "full": "Full verification pipeline",
    "live-only": "Live probes + rollback",
    "llm-only": "No checks (reference compiler)",
}


def load_evaluation(root: Path = ROOT):
    """Read committed results; refuse incomplete or inconsistent comparisons."""
    summary = json.loads((root / "docs/eval/summary_template.json").read_text())
    records = {}
    for policy in POLICIES:
        path = root / "docs/eval" / f"template_{policy}.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        if len(rows) != summary[policy]["n"]:
            raise ValueError(f"Record count differs from summary for {policy}")
        ids = [row["item"]["id"] for row in rows]
        if len(set(ids)) != len(ids):
            raise ValueError(f"Duplicate request identifiers in {policy}")
        if any(row["record"]["generator"] != "template" for row in rows):
            raise ValueError("This dashboard expects the committed reference-compiler evaluation")
        records[policy] = rows
    expected = {r["item"]["id"] for r in records["full"]}
    if any({r["item"]["id"] for r in rows} != expected for rows in records.values()):
        raise ValueError("Policies were evaluated on different request sets")
    return summary, records


def topology_dot(topology):
    lines = ["graph network {", 'rankdir=LR;', 'node [shape=box, style=rounded];']
    edges = set()
    routers = topology["routers"]
    for name in routers:
        lines.append(f'{json.dumps(name)} [label={json.dumps(name + " (router)")}];')
    for router, config in routers.items():
        for interface in config["interfaces"].values():
            peer = interface.get("peer")
            if peer in routers:
                edges.add(tuple(sorted((router, peer))))
    for left, right in sorted(edges):
        lines.append(f"{json.dumps(left)} -- {json.dumps(right)};")
    for host, config in topology["hosts"].items():
        lines.append(f'{json.dumps(host)} [label={json.dumps(host + chr(10) + config["address"])}, shape=ellipse];')
        lines.append(f'{json.dumps(host)} -- {json.dumps(config["router"])};')
    return "\n".join([*lines, "}"])


def render_overview(summary, records):
    st.subheader("What the checking layers changed")
    full = records["full"]
    valid = sum(r["item"]["category"] == "valid" for r in full)
    invalid = sum(r["item"]["category"] == "violates_policy" for r in full)
    columns = st.columns(4)
    columns[0].metric("Requests per policy", len(full))
    columns[1].metric("Policies compared", len(POLICIES))
    columns[2].metric("Policy violations stopped before apply", f"{round(summary['full']['invalid_rejected_before_lab'] * invalid)}/{invalid}")
    columns[3].metric("Unsafe changes left live · full pipeline", summary["full"]["unsafe_changes_left_in_lab"])
    table = []
    for key, label in POLICIES.items():
        metrics = summary[key]
        table.append({
            "Approach": label,
            "Valid completed (includes no-op)": f"{round(metrics['valid_completed'] * valid)}/{valid}",
            "Unsafe changes reached lab": metrics["unsafe_changes_reached_lab"],
            "Unsafe changes left live": metrics["unsafe_changes_left_in_lab"],
            "Unintended changes left live": metrics["unintended_reachability_changes_applied"],
            "Rollbacks": metrics["rollbacks"],
            "Median apply time (s)": metrics["time_applied_p50_s"],
        })
    st.dataframe(table, hide_index=True, width="stretch")
    st.caption("Source: committed summary_template.json and three template_*.jsonl recordings. Valid completed includes requests already satisfied by the baseline.")
    st.info("These results use labelled intents and a reference compiler, with zero LLM calls. The historical filename ‘llm-only’ denotes the no-checks configuration here; this table does not measure Claude-generated configs.")
    st.write("The model checks policy invariants, intended reachability and out-of-scope changes before deployment. Live probes and rollback handle failures or drift that the model cannot establish. Verification is limited by the model and its supported configuration dialect.")
    st.download_button("Download recorded comparison", json.dumps(summary, indent=2),
                       file_name="network-change-comparison.json", mime="application/json")


def render_requests(records):
    st.subheader("Inspect a recorded change")
    policy = st.selectbox("Checking policy", list(POLICIES), format_func=POLICIES.get)
    rows = records[policy]
    outcomes = ["All", *sorted({r["record"]["outcome"] for r in rows})]
    outcome = st.selectbox("Recorded outcome", outcomes)
    search = st.text_input("Search requests", placeholder="Try guest, HTTPS, database or blackhole")
    selected = [r for r in rows if (outcome == "All" or r["record"]["outcome"] == outcome)
                and search.casefold() in (r["item"]["id"] + " " + r["item"]["text"]).casefold()]
    if not selected:
        st.info("No recorded requests match these filters.")
        return
    by_id = {r["item"]["id"]: r for r in selected}
    request_id = st.selectbox("Recorded request", list(by_id),
                              format_func=lambda key: f"{key} · {by_id[key]['item']['text']}")
    row = by_id[request_id]
    item, record = row["item"], row["record"]
    st.write(item["text"])
    left, right = st.columns(2)
    left.metric("Recorded outcome", record["outcome"].replace("_", " "))
    right.metric("Recorded total time", f"{record['timings']['total']:.2f} s")
    if record["reason"]:
        st.write("**Recorded reason:**", record["reason"])
    if record["outcome"] in {"rolled_back", "rollback_failed"}:
        st.warning(f"Post-change checks failed. Recorded rollback success: {record['rollback_ok']}.")
    with st.expander("Structured intent and evaluation label"):
        st.json({"recorded_intent": record["intent"], "evaluation_category": item["category"],
                 "expected_outcome": item["expected"], "label_reason": item.get("why", "")})
    st.subheader("Candidate changes and counterexamples")
    if not record["attempts"]:
        st.write("No candidate attempt was needed or recorded for this request.")
    for attempt in record["attempts"]:
        with st.expander(f"Attempt {attempt['n']} · {'accepted' if attempt['accepted'] else 'rejected'}", expanded=True):
            st.write(attempt["explanation"])
            if attempt["diff"]:
                st.code(attempt["diff"], language="diff")
            if attempt["error"]:
                st.error(attempt["error"])
            if attempt["failures"]:
                st.dataframe(attempt["failures"], hide_index=True, width="stretch")
            if attempt["lint_issues"]:
                st.json(attempt["lint_issues"])
            with st.expander("Recorded oracle diagnostics"):
                st.caption("The evaluation records full-verifier findings even when the selected policy does not enforce them.")
                st.json(attempt["oracle_failures"])
    with st.expander("Live probe and rollback evidence"):
        if record["probes"]:
            st.dataframe(record["probes"], hide_index=True, width="stretch")
        else:
            st.write("No failed-probe details were recorded for this request. An empty list is not a fresh connectivity check.")
        st.json({"approved": record["approved"], "risk": record["risk"],
                 "applied_files": record["applied_files"], "rollback_ok": record["rollback_ok"],
                 "timings": record["timings"]})
    st.download_button("Download selected recorded request", json.dumps(row, indent=2),
                       file_name=f"{policy}-{request_id}.json", mime="application/json")


def main():
    st.set_page_config(page_title="Network-change verification", page_icon="🔎", layout="wide")
    st.title("Network-change assistant")
    st.caption("Pre-deployment verification · recorded lab results and counterexamples")
    st.sidebar.header("Recorded evidence")
    st.sidebar.write("Explore the committed evaluation and topology. This dashboard makes no network changes and needs no API keys.")
    try:
        summary, records = load_evaluation()
        topology = yaml.safe_load((ROOT / "network/topology.yml").read_text())
        invariants = yaml.safe_load((ROOT / "network/invariants.yml").read_text())
        overview, requests, network, demo = st.tabs(["Results", "Recorded changes", "Topology & policy", "Demo & scope"])
        with overview:
            render_overview(summary, records)
        with requests:
            render_requests(records)
        with network:
            st.subheader("Lab topology")
            st.graphviz_chart(topology_dot(topology))
            st.caption(f"{len(topology['routers'])} FRR routers and {len(topology['hosts'])} hosts. Access policy resides in server host firewalls.")
            st.subheader("Policy invariants")
            for kind, values in invariants.items():
                with st.expander(kind.replace("_", " ").title(), expanded=kind == "deny"):
                    st.json(values)
            st.subheader("Address zones")
            st.dataframe([{"Zone": k, "CIDR": v} for k, v in topology["zones"].items()], hide_index=True)
        with demo:
            st.subheader("Recorded live-lab demonstration")
            gif = ROOT / "docs/media/demo.gif"
            if gif.exists():
                st.image(gif.read_bytes(), caption="Committed recording: applied change, policy rejection and rollback after drift.", width="stretch")
            else:
                st.info("The recording is unavailable. Include docs/media/demo.gif when publishing.")
            st.write("The recording and displayed metrics are historical lab evidence. The full CLI workflow requires a running Batfish service and Docker/Containerlab infrastructure. This public dashboard does not execute the CLI or make LLM calls.")
            st.write("The reference-compiler evaluation isolates checking layers. It does not establish LLM-generation accuracy, production network safety or completeness of Batfish modelling. See docs/FINDINGS.md for unsupported iptables constructs and model/live differences.")
            st.link_button("Source repository", "https://github.com/fauzan111/AI-network-change-assistant-with-pre-deployment-verification")
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        st.error(f"Recorded evidence could not be loaded: {exc}")
        st.info("Include docs/eval/ and network/ in the repository and keep their recorded formats unchanged.")


if __name__ == "__main__":
    main()
