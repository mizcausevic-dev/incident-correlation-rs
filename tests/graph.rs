use incident_correlation::{CorrelationError, NodeKind, SuiteEdge, SuiteGraph, SuiteNode};

fn node(id: &str, kind: NodeKind, label: &str) -> SuiteNode {
    SuiteNode {
        id: id.to_string(),
        kind,
        label: label.to_string(),
    }
}

#[test]
fn add_node_and_edge() {
    let mut g = SuiteGraph::default();
    g.add_node(node("a", NodeKind::Aeo, "Acme AEO"));
    g.add_node(node("b", NodeKind::AgentCard, "Tutor Bot"));
    g.add_edge("b", "a", SuiteEdge::DependsOn)
        .expect("nodes exist");
    assert_eq!(g.node_count(), 2);
    assert_eq!(g.edge_count(), 1);
}

#[test]
fn add_edge_to_missing_node_errors() {
    let mut g = SuiteGraph::default();
    g.add_node(node("a", NodeKind::Aeo, "A"));
    let r = g.add_edge("a", "ghost", SuiteEdge::DependsOn);
    assert!(matches!(r, Err(CorrelationError::UnknownEdgeTarget(_))));
}

#[test]
fn re_adding_node_replaces_metadata() {
    let mut g = SuiteGraph::default();
    g.add_node(node("a", NodeKind::Aeo, "First"));
    g.add_node(node("a", NodeKind::Aeo, "Second"));
    assert_eq!(g.node_count(), 1);
}
