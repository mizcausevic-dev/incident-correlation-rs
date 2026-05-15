use incident_correlation::{
    Action, IncidentCard, IncidentCorrelator, NodeKind, SuiteEdge, SuiteGraph, SuiteNode,
};

/// Build a small but realistic graph:
///
///   tool-card "lookup"  <-- agent-card "tutor"  <-- agent-card "writer"
///                                  ^
///                                  |
///                            depends-on
///                                  |
///                                  v
///                         aeo "acmetutor"
///                                  ^
///                            approved-by
///                                  |
///                     vendor "AcmeTutor Inc."  <--  decision-card "DEC-001"
fn sample_graph() -> SuiteGraph {
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
        id: "agent:writer".into(),
        kind: NodeKind::AgentCard,
        label: "Writer Bot".into(),
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

    g.add_edge("agent:tutor", "tool:lookup", SuiteEdge::DependsOn)
        .unwrap();
    g.add_edge("agent:writer", "agent:tutor", SuiteEdge::DependsOn)
        .unwrap();
    g.add_edge("agent:tutor", "aeo:acmetutor", SuiteEdge::DependsOn)
        .unwrap();
    g.add_edge("vendor:acmetutor", "aeo:acmetutor", SuiteEdge::DependsOn)
        .unwrap();
    // All edges point leaf -> root: decision-card is the approval root.
    g.add_edge("decision:DEC-001", "vendor:acmetutor", SuiteEdge::Approves)
        .unwrap();

    g
}

fn incident(severity: &str, affected: Vec<&str>) -> IncidentCard {
    IncidentCard {
        incident_id: "INC-1".into(),
        summary: "Tool returned harmful output under prompt injection.".into(),
        severity: severity.to_string(),
        affected_documents: affected.into_iter().map(String::from).collect(),
        notes: None,
    }
}

#[test]
fn bfs_finds_directly_dependent_agents() {
    let g = sample_graph();
    let i = incident("high", vec!["tool:lookup"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();

    let ids: Vec<&str> = plan.affected_nodes.iter().map(|n| n.id.as_str()).collect();
    // The seed plus the two agents that transitively depend on it.
    assert!(ids.contains(&"tool:lookup"));
    assert!(ids.contains(&"agent:tutor"));
    assert!(ids.contains(&"agent:writer"));
}

#[test]
fn depth_increases_with_each_bfs_step() {
    let g = sample_graph();
    let i = incident("medium", vec!["tool:lookup"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    let tool = plan
        .affected_nodes
        .iter()
        .find(|n| n.id == "tool:lookup")
        .unwrap();
    let tutor = plan
        .affected_nodes
        .iter()
        .find(|n| n.id == "agent:tutor")
        .unwrap();
    let writer = plan
        .affected_nodes
        .iter()
        .find(|n| n.id == "agent:writer")
        .unwrap();
    assert_eq!(tool.depth, 0);
    assert_eq!(tutor.depth, 1);
    assert_eq!(writer.depth, 2);
}

#[test]
fn aeo_incident_pulls_in_vendor_and_decision_card() {
    let g = sample_graph();
    let i = incident("high", vec!["aeo:acmetutor"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    let ids: Vec<&str> = plan.affected_nodes.iter().map(|n| n.id.as_str()).collect();
    assert!(ids.contains(&"vendor:acmetutor"));
    assert!(ids.contains(&"decision:DEC-001"));
}

#[test]
fn critical_severity_pages_for_directly_affected_nodes() {
    let g = sample_graph();
    let i = incident("critical", vec!["tool:lookup"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    let seed = plan.affected_nodes.iter().find(|n| n.depth == 0).unwrap();
    assert_eq!(seed.action, Action::Page);
    assert!(plan.has_page());
}

#[test]
fn vendor_node_recommends_review() {
    let g = sample_graph();
    let i = incident("medium", vec!["aeo:acmetutor"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    let vendor = plan
        .affected_nodes
        .iter()
        .find(|n| n.id == "vendor:acmetutor")
        .unwrap();
    assert_eq!(vendor.action, Action::RequestReview);
}

#[test]
fn decision_card_recommends_policy_recheck() {
    let g = sample_graph();
    let i = incident("medium", vec!["aeo:acmetutor"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    let card = plan
        .affected_nodes
        .iter()
        .find(|n| n.id == "decision:DEC-001")
        .unwrap();
    assert_eq!(card.action, Action::RecheckPolicy);
}

#[test]
fn unknown_affected_id_errors() {
    let g = sample_graph();
    let i = incident("low", vec!["does-not-exist"]);
    let r = IncidentCorrelator.correlate(&g, &i);
    assert!(r.is_err());
}

#[test]
fn summary_lists_counts_by_kind() {
    let g = sample_graph();
    let i = incident("low", vec!["tool:lookup"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    // Summary string should mention at least the kinds we hit.
    assert!(plan.summary.contains("ToolCard"));
    assert!(plan.summary.contains("AgentCard"));
}
