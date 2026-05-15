# incident-correlation

[![CI](https://github.com/mizcausevic-dev/incident-correlation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/mizcausevic-dev/incident-correlation-rs/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Walks the Kinetic Gain Protocol Suite document graph and turns an AI Incident Card into a structured remediation plan.** When a tool, an agent, or a vendor's AEO disclosure misbehaves in production, the honest question is *what else does this touch?* This crate answers it with one BFS.

```rust
use incident_correlation::{
    IncidentCard, IncidentCorrelator, NodeKind, SuiteEdge, SuiteGraph, SuiteNode,
};

let mut g = SuiteGraph::default();
g.add_node(SuiteNode { id: "tool:lookup".into(),     kind: NodeKind::ToolCard,    label: "lookup_homework".into() });
g.add_node(SuiteNode { id: "agent:tutor".into(),     kind: NodeKind::AgentCard,   label: "Tutor Bot".into() });
g.add_node(SuiteNode { id: "aeo:acmetutor".into(),   kind: NodeKind::Aeo,         label: "AcmeTutor AEO".into() });
g.add_node(SuiteNode { id: "decision:DEC-1".into(),  kind: NodeKind::DecisionCard,label: "Approval".into() });

g.add_edge("agent:tutor", "tool:lookup",   SuiteEdge::DependsOn)?;
g.add_edge("agent:tutor", "aeo:acmetutor", SuiteEdge::DependsOn)?;

let incident = IncidentCard {
    incident_id: "INC-1".into(),
    summary: "lookup_homework returned PII under prompt injection.".into(),
    severity: "high".into(),
    affected_documents: vec!["tool:lookup".into()],
    notes: None,
};

let plan = IncidentCorrelator::default().correlate(&g, &incident)?;
for n in &plan.affected_nodes {
    println!("[{}] {} -> {:?} ({:?})", n.depth, n.label, n.action, n.urgency);
}
# Ok::<_, Box<dyn std::error::Error>>(())
```

---

## What it answers

When an **AI Incident Card** lands, you have the names of the directly-affected docs. You don't have the things you really need to do next:

- Which agent-cards depend on the affected tool?
- Which decision-cards approved the affected vendor — and therefore which PolicyBundles are now suspect?
- Which AEO entities mention the affected entity?
- What's the right urgency for each follow-up call?

`IncidentCorrelator::correlate` returns a [`RemediationPlan`] with one [`AffectedNode`] per touched document, the BFS depth, a recommended [`Action`], and a plain-English rationale you can paste into a ticket.

---

## How the BFS works

- **Seed nodes** are the ids in `incident.affected_documents` (depth 0).
- At each step we walk **incoming** edges — "what depends on this" rather than "what does this depend on" — because the propagation we care about is downstream.
- We follow `DependsOn` and `ApprovedBy`. `Mentions` is informational and is NOT followed (it would over-fan the plan into the long tail of papers that quote the affected entity once).

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
| anything at depth 0 with severity=critical | Page |
| everything else  | Revalidate             |

Override the table by reading the BFS output and re-deriving your own actions; the structure is small and serde-serialisable.

---

## Composes with

- **[procurement-decision-api](https://github.com/mizcausevic-dev/procurement-decision-api)** — the Decision Cards we walk.
- **[policy-as-code-engine](https://github.com/mizcausevic-dev/policy-as-code-engine)** — the `RecheckPolicy` action drives `POST /bundles/{id}/evaluate` calls against the bundles those cards produced.
- **[aeo-validator-service](https://github.com/mizcausevic-dev/aeo-validator-service)** — `Revalidate` actions on AEO nodes turn into `POST /watches/{id}/recheck` calls.
- **[reliability-toolkit-rs](https://github.com/mizcausevic-dev/reliability-toolkit-rs)** — wrap the outbound recheck calls in a circuit breaker + retry.

Same flavour as the rest of the portfolio: small surface, composable, no surprises.

---

## API surface

| Type | Notes |
| --- | --- |
| `SuiteGraph` | Typed graph (petgraph under the hood). `add_node` / `add_edge` are the whole API. |
| `SuiteNode`  | `{ id, kind, label }`. |
| `SuiteEdge`  | `DependsOn` / `ApprovedBy` / `Mentions`. |
| `NodeKind`   | `Aeo` / `AgentCard` / `ToolCard` / `DecisionCard` / `IncidentCard` / `Vendor`. |
| `IncidentCard` | Trimmed view of the v0.1 spec — only the fields the correlator reads. |
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

CI matrix: `stable`, `beta`, `1.85.0` (MSRV).

---

## License

MIT. See [LICENSE](LICENSE).
