# incident-correlation

[![CI](https://github.com/mizcausevic-dev/incident-correlation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/mizcausevic-dev/incident-correlation-rs/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Walks a caller-supplied Kinetic Gain Protocol Suite document graph and turns an AI Incident Card into a suggested remediation plan.** When a tool, an agent, or a vendor's AEO disclosure has an incident, the question is *what else does this touch?* This crate answers it with one BFS over the edges the caller supplied. It does not validate source documents, execute actions, or prove that the graph is complete.

```rust
use incident_correlation::{
    IncidentCard, IncidentCorrelator, NodeKind, SuiteEdge, SuiteGraph, SuiteNode,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut g = SuiteGraph::default();
    g.add_node(SuiteNode { id: "tool:lookup".into(), kind: NodeKind::ToolCard, label: "lookup_homework".into() });
    g.add_node(SuiteNode { id: "agent:tutor".into(), kind: NodeKind::AgentCard, label: "Tutor Bot".into() });
    g.add_node(SuiteNode { id: "aeo:acmetutor".into(), kind: NodeKind::Aeo, label: "AcmeTutor AEO".into() });
    g.add_node(SuiteNode { id: "vendor:acmetutor".into(), kind: NodeKind::Vendor, label: "AcmeTutor Inc.".into() });
    g.add_node(SuiteNode { id: "decision:DEC-1".into(), kind: NodeKind::DecisionCard, label: "Approval".into() });

    g.add_edge("agent:tutor", "tool:lookup", SuiteEdge::DependsOn)?;
    g.add_edge("agent:tutor", "aeo:acmetutor", SuiteEdge::DependsOn)?;
    g.add_edge("vendor:acmetutor", "aeo:acmetutor", SuiteEdge::DependsOn)?;
    g.add_edge("decision:DEC-1", "vendor:acmetutor", SuiteEdge::Approves)?;

    let incident = IncidentCard {
        incident_id: "INC-1".into(),
        summary: "lookup_homework returned PII under prompt injection.".into(),
        severity: "high".into(),
        affected_documents: vec!["tool:lookup".into()],
        notes: None,
    };
    let plan = IncidentCorrelator.correlate(&g, &incident)?;
    for n in &plan.affected_nodes {
        println!("[{}] {} -> {:?} ({:?})", n.depth, n.label, n.action, n.urgency);
    }
    Ok(())
}
```

---

## What it answers

When an **AI Incident Card** lands, you have the names of the directly-affected docs. You don't have the things you really need to do next:

- Which agent-cards depend on the affected tool?
- Which decision-cards approved the affected vendor — and therefore which PolicyBundles are now suspect?
- What's the right urgency for each follow-up call?

`IncidentCorrelator::correlate` returns a `RemediationPlan` with one `AffectedNode` per reached graph node, the BFS depth, a recommended `Action`, and a rationale. It rejects empty affected-document lists and unknown severity values instead of returning an empty or silently downgraded plan.

---

## How the BFS works

- **Seed nodes** are the ids in `incident.affected_documents` (depth 0).
- At each step we walk **incoming** edges — "what depends on this" rather than "what does this depend on" — because the propagation we care about is downstream.
- We follow `DependsOn` and `Approves`. `Mentions` is informational and is not followed.

The default urgency table follows the SRE workbook intuitions:

| severity | depth 0           | depth ≥ 1 |
| -------- | ----------------- | --------- |
| critical | **Critical (page)** | High      |
| high     | High              | Normal    |
| medium   | Normal            | Normal    |
| low      | Low               | Low       |

The action a node gets depends on its `NodeKind`:

| Node kind        | Recommended action     |
| ---------------- | ---------------------- |
| `IncidentCard`   | Page                   |
| `DecisionCard`   | RecheckPolicy          |
| `Vendor`         | RequestReview          |
| other node at depth 0 with severity=critical | Page |
| everything else  | Revalidate             |

These are recommendations, not API calls or paging operations. Decision Cards and vendors keep their specific follow-up action even at critical severity. In that case `urgency` is `critical` and `has_page()` is true so the caller can also page the on-call owner.

---

## Composes with

- **[procurement-decision-api](https://github.com/mizcausevic-dev/procurement-decision-api)** — the Decision Cards we walk.
- **[policy-as-code-engine](https://github.com/mizcausevic-dev/policy-as-code-engine)** — a `RecheckPolicy` recommendation can prompt an operator to inspect policy bundles derived from a Decision Card.
- **[aeo-validator-service](https://github.com/mizcausevic-dev/aeo-validator-service)** — an operator can use its recheck endpoint to investigate an AEO node when a watch exists.
- **[reliability-toolkit-rs](https://github.com/mizcausevic-dev/reliability-toolkit-rs)** — can be used by a separate orchestration layer for outbound calls.

This crate does not call those services. It returns a plan for a caller to review and route.

The [AI Incident Card v0.1 specification](https://github.com/mizcausevic-dev/ai-incident-card-spec) uses nested `incident` and `affected` objects. Validate a source card against that full schema first, then call `IncidentCard::from_suite_json(raw)`. The projection copies exact agent/tutor/tool card URIs into `affected_documents`. Register graph nodes with those exact URI IDs or explicitly remap them before correlation. It does not infer a vendor node or decision links from a vendor name or product label.

The projection checks the fields it needs, including nonblank incident ID, summary, severity, and references; it does **not** validate URI syntax or any other upstream schema rule. The compact `correlate` path rejects blank IDs and references as well.

---

## API surface

| Type | Notes |
| --- | --- |
| `SuiteGraph` | Typed graph (petgraph under the hood). `add_node` / `add_edge` are the whole API. |
| `SuiteNode`  | `{ id, kind, label }`. |
| `SuiteEdge`  | `DependsOn` / `Approves` / `Mentions`. |
| `NodeKind`   | `Aeo` / `AgentCard` / `TutorCard` / `ToolCard` / `DecisionCard` / `IncidentCard` / `Vendor`. |
| `IncidentCard` | Compact incident input. `from_suite_json` projects v0.1 nested identity, summary, and card URI references into this type. |
| `IncidentCorrelator` | `correlate(&graph, &incident) -> Result<RemediationPlan, _>`. |
| `RemediationPlan` | `affected_nodes: Vec<AffectedNode>`, `summary: String`, helpers `affected(kind)` and `has_page()`. |
| `Action` / `Urgency` | enums; serde-serialised as snake_case. |

---

## Run the example

```bash
cargo run --example walk
```

Builds the toy graph above, walks it for a high-severity tool incident, and prints the plan.

---

## Bench

```bash
cargo bench
```

The bundled bench builds a 1000-agent fanout off a single tool-card and times the correlator. Order-of-magnitude reference, not a vendor pitch.

---

## Tests

```bash
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -Dwarnings
cargo fmt --all -- --check
```

CI matrix: `stable`, `beta`, `1.88.0` (MSRV).

## Optional audit event

With the `audit-stream` feature, `correlate_with_audit` attempts one HTTP event to the operator-configured `AUDIT_STREAM_URL`. The endpoint must be a trusted HTTP(S) service; URL credentials, query strings, and fragments are rejected. `AUDIT_STREAM_TIMEOUT_S` defaults to 2.5 seconds and is capped at 30 seconds. The event contains the incident ID, severity, affected-node count, highest urgency, and page flag; it omits free-text summaries and affected-document IDs. Errors use a fixed reason code.

Emission is best-effort and an error does not block a plan. The caller must verify durable acceptance separately if the event is required for governance, and must configure authentication, retention, and access control for the destination service. Pass a `reqwest::Client` with redirects disabled (`redirect::Policy::none()`) when sending sensitive incident IDs; this crate cannot override the caller's redirect policy. No remote audit behavior is established by this crate's local tests.

The returned plan still contains incident text in its rationales. Treat plans as potentially sensitive, avoid logging them by default, and encode text when rendering it in an interface.

---

## License

MIT. See [LICENSE](LICENSE).
