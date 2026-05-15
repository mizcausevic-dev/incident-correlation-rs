//! Output types — what the correlator hands back.

use serde::{Deserialize, Serialize};

use crate::model::NodeKind;

/// Recommended action for one affected node.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Re-fetch the doc and re-run validation. Use for upstream changes.
    Revalidate,
    /// Force re-evaluation of any PolicyBundles derived from this card.
    RecheckPolicy,
    /// Mark the contract / decision deprecated; bring forward a migration plan.
    RequestReview,
    /// Page the on-call owner. Used when severity == "critical".
    Page,
}

/// How urgent this action is.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Urgency {
    /// Wait until business hours.
    Low,
    /// Within 24 hours.
    Normal,
    /// Within an hour.
    High,
    /// Page now.
    Critical,
}

/// One affected node in the plan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AffectedNode {
    /// Stable id from the graph.
    pub id: String,
    /// What kind of node.
    pub kind: NodeKind,
    /// Human-readable label.
    pub label: String,
    /// Distance (BFS depth) from the original incident-affected document.
    pub depth: u32,
    /// Recommended action for this node.
    pub action: Action,
    /// Urgency derived from incident severity + depth.
    pub urgency: Urgency,
    /// Plain-English explanation operators can paste into a ticket.
    pub rationale: String,
}

/// Full remediation plan for an incident.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemediationPlan {
    /// Echo of the incident_id the plan was computed from.
    pub incident_id: String,
    /// Affected nodes, BFS-ordered.
    pub affected_nodes: Vec<AffectedNode>,
    /// Quick-glance summary: ``"3 agent-cards, 2 decision-cards, 1 vendor"`` etc.
    pub summary: String,
}

impl RemediationPlan {
    /// Sub-list filtered by node kind. Handy in templates.
    #[must_use]
    pub fn affected(&self, kind: NodeKind) -> Vec<&AffectedNode> {
        self.affected_nodes
            .iter()
            .filter(|n| n.kind == kind)
            .collect()
    }

    /// Whether any node was flagged for paging.
    #[must_use]
    pub fn has_page(&self) -> bool {
        self.affected_nodes
            .iter()
            .any(|n| matches!(n.action, Action::Page))
    }
}
