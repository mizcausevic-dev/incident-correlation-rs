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
fn critical_decision_preserves_policy_recheck_and_page_signal() {
    let g = sample_graph();
    let i = incident("critical", vec!["decision:DEC-001"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    let card = &plan.affected_nodes[0];
    assert_eq!(card.action, Action::RecheckPolicy);
    assert_eq!(card.urgency, incident_correlation::Urgency::Critical);
    assert!(plan.has_page());
}

#[test]
fn critical_vendor_preserves_review_and_page_signal() {
    let g = sample_graph();
    let i = incident("critical", vec!["vendor:acmetutor"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    let vendor = &plan.affected_nodes[0];
    assert_eq!(vendor.action, Action::RequestReview);
    assert_eq!(vendor.urgency, incident_correlation::Urgency::Critical);
    assert!(plan.has_page());
}

#[test]
fn unknown_affected_id_errors() {
    let g = sample_graph();
    let i = incident("low", vec!["does-not-exist"]);
    let r = IncidentCorrelator.correlate(&g, &i);
    assert!(r.is_err());
}

#[test]
fn unknown_severity_fails_instead_of_downgrading_to_low() {
    let g = sample_graph();
    let i = incident("severe", vec!["tool:lookup"]);
    let result = IncidentCorrelator.correlate(&g, &i);
    assert!(matches!(
        result,
        Err(incident_correlation::CorrelationError::InvalidSeverity(_))
    ));
}

#[test]
fn empty_affected_documents_cannot_produce_a_successful_empty_plan() {
    let g = sample_graph();
    let i = incident("high", vec![]);
    let result = IncidentCorrelator.correlate(&g, &i);
    assert!(matches!(
        result,
        Err(incident_correlation::CorrelationError::EmptyAffectedDocuments)
    ));
}

#[test]
fn severity_is_case_insensitive_and_moderate_is_medium() {
    let g = sample_graph();
    let i = incident(" MoDeRaTe ", vec!["tool:lookup"]);
    let plan = IncidentCorrelator.correlate(&g, &i).unwrap();
    assert_eq!(
        plan.affected_nodes[0].urgency,
        incident_correlation::Urgency::Normal
    );
}

#[test]
fn projects_real_incident_card_fixture_using_exact_uri_ids() {
    let source = include_str!("fixtures/incident-card-prompt-injection.json");
    let incident = IncidentCard::from_suite_json(source).expect("canonical v0.1 fixture");
    assert_eq!(incident.incident_id, "INC-2026-05-03-kineticgain-002");
    assert_eq!(incident.severity, "high");
    assert_eq!(incident.affected_documents.len(), 2);
    assert!(incident.summary.contains("base64-encoded log block"));

    let agent_uri = "https://kineticgain.com/.well-known/agents/customer-support-tier-1.json";
    let tool_uri = "https://billing.kineticgain.com/.well-known/mcp-tools/billing-lookup.json";
    assert_eq!(incident.affected_documents, [agent_uri, tool_uri]);
    let mut g = SuiteGraph::default();
    g.add_node(SuiteNode {
        id: agent_uri.into(),
        kind: NodeKind::AgentCard,
        label: "support agent".into(),
    });
    g.add_node(SuiteNode {
        id: tool_uri.into(),
        kind: NodeKind::ToolCard,
        label: "billing lookup".into(),
    });
    let plan = IncidentCorrelator.correlate(&g, &incident).unwrap();
    assert_eq!(plan.affected_nodes.len(), 2);
    assert!(plan.affected_nodes.iter().all(|node| node.depth == 0));
}

#[test]
fn projection_rejects_malformed_or_unsupported_incident_card() {
    assert!(matches!(
        IncidentCard::from_suite_json("{not JSON"),
        Err(incident_correlation::CorrelationError::InvalidIncident(_))
    ));
    let unsupported = r#"{"incident_card_version":"0.2","incident":{"id":"INC-1","severity":"high"},"summary":"x","affected":{"tool_card_uris":["https://example.test/tool"]}}"#;
    assert!(matches!(
        IncidentCard::from_suite_json(unsupported),
        Err(incident_correlation::CorrelationError::UnsupportedIncidentVersion(_))
    ));
    let wrong_type = r#"{"incident_card_version":"0.1","incident":{"id":"INC-1","severity":"high"},"summary":"x","affected":{"tool_card_uris":[42]}}"#;
    assert!(matches!(
        IncidentCard::from_suite_json(wrong_type),
        Err(incident_correlation::CorrelationError::InvalidIncident(_))
    ));
    let bad_severity = r#"{"incident_card_version":"0.1","incident":{"id":"INC-1","severity":"severe"},"summary":"x","affected":{"tool_card_uris":["https://example.test/tool"]}}"#;
    assert!(matches!(
        IncidentCard::from_suite_json(bad_severity),
        Err(incident_correlation::CorrelationError::InvalidSeverity(_))
    ));
}

#[test]
fn projection_rejects_card_without_graph_seed_references() {
    let no_refs = r#"{"incident_card_version":"0.1","incident":{"id":"INC-1","severity":"high"},"summary":"x","affected":{}}"#;
    assert!(matches!(
        IncidentCard::from_suite_json(no_refs),
        Err(incident_correlation::CorrelationError::EmptyAffectedDocuments)
    ));
}

#[test]
fn projection_rejects_blank_required_fields() {
    for source in [
        r#"{"incident_card_version":"0.1","incident":{"id":"","severity":"high"},"summary":"x","affected":{"tool_card_uris":["https://example.test/tool"]}}"#,
        r#"{"incident_card_version":"0.1","incident":{"id":"INC-1","severity":"high"},"summary":" ","affected":{"tool_card_uris":["https://example.test/tool"]}}"#,
        r#"{"incident_card_version":"0.1","incident":{"id":"INC-1","severity":"high"},"summary":"x","affected":{"tool_card_uris":[" "]}}"#,
    ] {
        assert!(matches!(
            IncidentCard::from_suite_json(source),
            Err(incident_correlation::CorrelationError::InvalidIncidentField(_))
        ));
    }
}

#[test]
fn compact_input_rejects_blank_required_fields() {
    let g = sample_graph();
    let mut i = incident("high", vec!["tool:lookup"]);
    i.incident_id = " ".into();
    assert!(matches!(
        IncidentCorrelator.correlate(&g, &i),
        Err(incident_correlation::CorrelationError::InvalidIncidentField("incident_id"))
    ));
    i.incident_id = "INC-1".into();
    i.affected_documents = vec!["".into()];
    assert!(matches!(
        IncidentCorrelator.correlate(&g, &i),
        Err(incident_correlation::CorrelationError::InvalidIncidentField("affected_documents"))
    ));
}

#[test]
fn projection_preserves_tutor_card_uri_without_guessing_a_graph_id() {
    let source = r#"{"incident_card_version":"0.1","incident":{"id":"INC-2","severity":"medium"},"summary":"x","affected":{"tutor_card_uris":["https://example.test/tutors/algebra.json"]}}"#;
    let incident = IncidentCard::from_suite_json(source).unwrap();
    assert_eq!(
        incident.affected_documents,
        ["https://example.test/tutors/algebra.json"]
    );
    let mut g = SuiteGraph::default();
    g.add_node(SuiteNode {
        id: incident.affected_documents[0].clone(),
        kind: NodeKind::TutorCard,
        label: "algebra tutor".into(),
    });
    let plan = IncidentCorrelator.correlate(&g, &incident).unwrap();
    assert_eq!(plan.affected_nodes[0].action, Action::Revalidate);
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
