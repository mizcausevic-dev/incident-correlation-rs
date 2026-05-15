//! BFS over the Suite graph that turns an incident card into a remediation plan.

use std::collections::{HashSet, VecDeque};

use petgraph::graph::NodeIndex;

use crate::error::CorrelationError;
use crate::graph::{SuiteEdge, SuiteGraph};
use crate::model::{IncidentCard, NodeKind};
use crate::plan::{Action, AffectedNode, RemediationPlan, Urgency};

/// Walks the graph and emits a [`RemediationPlan`].
#[derive(Debug, Default)]
pub struct IncidentCorrelator;

impl IncidentCorrelator {
    /// Build a remediation plan for the given incident card.
    ///
    /// BFS rules:
    ///  - Start from every `affected_documents` id (depth 0).
    ///  - At each step, walk **incoming** edges so we find "what depends on
    ///    this affected thing", not "what does this affected thing depend on."
    ///  - Edge kinds we follow: `DependsOn`, `ApprovedBy`. `Mentions` is
    ///    informational and is NOT followed (would over-fan the plan).
    pub fn correlate(
        &self,
        graph: &SuiteGraph,
        incident: &IncidentCard,
    ) -> Result<RemediationPlan, CorrelationError> {
        // Validate every affected id exists in the graph.
        let mut seeds: Vec<NodeIndex> = Vec::with_capacity(incident.affected_documents.len());
        for id in &incident.affected_documents {
            let idx = graph
                .idx(id)
                .ok_or_else(|| CorrelationError::UnknownAffectedNode(id.clone()))?;
            seeds.push(idx);
        }

        let severity = parse_severity(&incident.severity);
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(NodeIndex, u32)> = VecDeque::new();

        // Seed the BFS with all directly-affected nodes at depth 0.
        for &seed in &seeds {
            if visited.insert(seed) {
                queue.push_back((seed, 0));
            }
        }

        let mut affected: Vec<AffectedNode> = Vec::new();
        let follow_edges = [SuiteEdge::DependsOn, SuiteEdge::Approves];

        while let Some((idx, depth)) = queue.pop_front() {
            let node = graph.node(idx);
            affected.push(AffectedNode {
                id: node.id.clone(),
                kind: node.kind,
                label: node.label.clone(),
                depth,
                action: action_for(node.kind, depth, severity),
                urgency: urgency_for(severity, depth),
                rationale: rationale_for(node.kind, depth, &incident.summary),
            });
            for (neighbour, _edge) in graph.inbound(idx, &follow_edges) {
                if visited.insert(neighbour) {
                    queue.push_back((neighbour, depth + 1));
                }
            }
        }

        let summary = summarize(&affected);
        Ok(RemediationPlan {
            incident_id: incident.incident_id.clone(),
            affected_nodes: affected,
            summary,
        })
    }
}

/// Severity bucket the urgency table uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

fn parse_severity(raw: &str) -> Severity {
    match raw.to_ascii_lowercase().trim() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "moderate" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn urgency_for(severity: Severity, depth: u32) -> Urgency {
    match (severity, depth) {
        (Severity::Critical, 0) => Urgency::Critical,
        (Severity::Critical, _) => Urgency::High,
        (Severity::High, 0) => Urgency::High,
        (Severity::High, _) => Urgency::Normal,
        (Severity::Medium, _) => Urgency::Normal,
        (Severity::Low, _) => Urgency::Low,
    }
}

fn action_for(kind: NodeKind, depth: u32, severity: Severity) -> Action {
    match (kind, depth, severity) {
        (NodeKind::IncidentCard, _, _) => Action::Page,
        // Directly affected nodes at depth 0 get more aggressive treatment.
        (_, 0, Severity::Critical) => Action::Page,
        (NodeKind::DecisionCard, _, _) => Action::RecheckPolicy,
        (NodeKind::Vendor, _, _) => Action::RequestReview,
        // Everything else (AEO, agent-card, tool-card) gets re-validated.
        (_, _, _) => Action::Revalidate,
    }
}

fn rationale_for(kind: NodeKind, depth: u32, summary: &str) -> String {
    let where_from = if depth == 0 {
        "directly named in the incident".to_string()
    } else {
        format!("transitively affected (depth {depth}) via the incident")
    };
    match kind {
        NodeKind::Aeo => format!("Re-validate the AEO doc: {where_from}. Summary: {summary}"),
        NodeKind::AgentCard => format!(
            "Re-validate the agent-card and confirm refusal taxonomy still holds: {where_from}."
        ),
        NodeKind::ToolCard => {
            format!("Re-validate the tool-card and audit recent invocations: {where_from}.")
        }
        NodeKind::DecisionCard => {
            format!("Re-evaluate the PolicyBundle generated from this Decision Card. {where_from}.")
        }
        NodeKind::Vendor => {
            format!("Request a fresh procurement review for this vendor. {where_from}.")
        }
        NodeKind::IncidentCard => format!("Incident itself: page the on-call. Summary: {summary}"),
    }
}

fn summarize(affected: &[AffectedNode]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for n in affected {
        *counts.entry(format!("{:?}", n.kind)).or_default() += 1;
    }
    if counts.is_empty() {
        return "no affected nodes".to_string();
    }
    counts
        .into_iter()
        .map(|(k, v)| format!("{v} {k}"))
        .collect::<Vec<_>>()
        .join(", ")
}
