//! `cargo run --example walk`
//!
//! Builds a tiny graph and walks it for a high-severity tool incident.

use incident_correlation::{
    IncidentCard, IncidentCorrelator, NodeKind, SuiteEdge, SuiteGraph, SuiteNode,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut g = SuiteGraph::default();
    g.add_node(SuiteNode {
        id: "tool:lookup".into(),
        kind: NodeKind::ToolCard,
        label: "lookup_homework".into(),
    });
    g.add_node(SuiteNode {
        id: "agent:tutor".into(),
        kind: NodeKind::AgentCard,
        label: "Tutor Bot".into(),
    });
    g.add_node(SuiteNode {
        id: "aeo:acmetutor".into(),
        kind: NodeKind::Aeo,
        label: "AcmeTutor AEO".into(),
    });
    g.add_node(SuiteNode {
        id: "vendor:acmetutor".into(),
        kind: NodeKind::Vendor,
        label: "AcmeTutor Inc.".into(),
    });
    g.add_node(SuiteNode {
        id: "decision:DEC-001".into(),
        kind: NodeKind::DecisionCard,
        label: "Springfield USD approval".into(),
    });

    g.add_edge("agent:tutor", "tool:lookup", SuiteEdge::DependsOn)?;
    g.add_edge("agent:tutor", "aeo:acmetutor", SuiteEdge::DependsOn)?;
    g.add_edge("vendor:acmetutor", "aeo:acmetutor", SuiteEdge::DependsOn)?;
    g.add_edge("decision:DEC-001", "vendor:acmetutor", SuiteEdge::Approves)?;

    let incident = IncidentCard {
        incident_id: "INC-2026-05-14".into(),
        summary: "lookup_homework returned PII under prompt injection.".into(),
        severity: "high".into(),
        affected_documents: vec!["tool:lookup".into()],
        notes: Some("Bug found by trust-and-safety canary".into()),
    };

    let plan = IncidentCorrelator.correlate(&g, &incident)?;
    println!("incident: {}", plan.incident_id);
    println!("summary:  {}", plan.summary);
    println!("affected ({}):", plan.affected_nodes.len());
    for n in &plan.affected_nodes {
        println!(
            "  [{:>2}] {:<14} {:<22}  -> {:?} ({:?})",
            n.depth,
            format!("{:?}", n.kind),
            n.label,
            n.action,
            n.urgency
        );
    }
    Ok(())
}
