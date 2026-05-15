//! Serialisable types.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// What kind of Suite document this node represents. Mirrors the spec list in
/// `aeo-validator-service` plus `vendor` as a synthesized node for "the
/// organisation owning everything we approved."
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    /// `aeo.json` — entity declaration.
    Aeo,
    /// `agent-card.json` — agent capability + refusal disclosure.
    AgentCard,
    /// `tool-card.json` — MCP tool declaration.
    ToolCard,
    /// `decision-card.json` — buyer-side approval/rejection.
    DecisionCard,
    /// `incident-card.json` — the thing we're correlating *from*.
    IncidentCard,
    /// Synthesized: a vendor referenced by a decision card's `subject`.
    Vendor,
}

/// Trimmed AI Incident Card. We only model the fields the correlator cares
/// about; full validation belongs to `aeo-validator-service`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncidentCard {
    /// Stable identifier.
    pub incident_id: String,
    /// Short human-readable summary.
    pub summary: String,
    /// `"low" | "medium" | "high" | "critical"` — free-form so the spec can
    /// evolve. The correlator only uses it to set per-action `urgency`.
    pub severity: String,
    /// IDs of the Suite docs the incident affects directly.
    pub affected_documents: Vec<String>,
    /// Optional notes from the operator who filed the card.
    #[serde(default)]
    pub notes: Option<String>,
}

impl IncidentCard {
    /// Convenience: turn the list of affected document ids into a set.
    #[must_use]
    pub fn affected_set(&self) -> HashSet<String> {
        self.affected_documents.iter().cloned().collect()
    }
}
