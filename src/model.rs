//! Serialisable types.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// The Suite document or caller-supplied vendor represented by a graph node.
/// This enum covers the node kinds this correlator acts on, not every Suite spec.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    /// `aeo.json` — entity declaration.
    Aeo,
    /// `agent-card.json` — agent capability + refusal disclosure.
    AgentCard,
    /// `tutor-card.json` — AI tutor disclosure referenced by Incident Cards.
    TutorCard,
    /// `tool-card.json` — MCP tool declaration.
    ToolCard,
    /// `decision-card.json` — buyer-side approval/rejection.
    DecisionCard,
    /// `incident-card.json` — the thing we're correlating *from*.
    IncidentCard,
    /// Synthesized: a vendor referenced by a decision card's `subject`.
    Vendor,
}

/// Compact incident input. We only model the fields the correlator cares
/// about; full JSON Schema validation must happen before projection.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncidentCard {
    /// Stable identifier.
    pub incident_id: String,
    /// Short human-readable summary.
    pub summary: String,
    /// `"low" | "medium" | "high" | "critical"`; unrecognized values fail
    /// correlation instead of being downgraded.
    pub severity: String,
    /// IDs of the Suite docs the incident affects directly.
    pub affected_documents: Vec<String>,
    /// Optional notes from the operator who filed the card.
    #[serde(default)]
    pub notes: Option<String>,
}

impl IncidentCard {
    /// Project an AI Incident Card v0.1 document into compact correlator input.
    ///
    /// `affected.agent_card_uris`, `tutor_card_uris`, and `tool_card_uris`
    /// become exact graph node IDs. Callers must register those URIs as IDs or
    /// explicitly remap them to their own graph IDs. This does not validate
    /// the full Incident Card specification or infer relationships.
    ///
    /// The spec permits incidents without card URI references; these cannot
    /// seed a graph walk and return `EmptyAffectedDocuments`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, unsupported versions, or no
    /// agent/tutor/tool card URI references.
    pub fn from_suite_json(raw: &str) -> Result<Self, crate::error::CorrelationError> {
        let source: SuiteIncidentProjection = serde_json::from_str(raw)?;
        if source.incident_card_version != "0.1" {
            return Err(crate::error::CorrelationError::UnsupportedIncidentVersion(
                source.incident_card_version,
            ));
        }
        if !matches!(
            source.incident.severity.as_str(),
            "low" | "medium" | "high" | "critical"
        ) {
            return Err(crate::error::CorrelationError::InvalidSeverity(
                source.incident.severity,
            ));
        }
        let mut affected_documents = source.affected.agent;
        affected_documents.extend(source.affected.tutor);
        affected_documents.extend(source.affected.tool);
        let projected = Self {
            incident_id: source.incident.id,
            summary: source.summary,
            severity: source.incident.severity,
            affected_documents,
            notes: None,
        };
        projected.validate_required_fields()?;
        Ok(projected)
    }

    /// Check the compact fields needed for a meaningful correlation result.
    pub(crate) fn validate_required_fields(&self) -> Result<(), crate::error::CorrelationError> {
        use crate::error::CorrelationError;
        if self.incident_id.trim().is_empty() {
            return Err(CorrelationError::InvalidIncidentField("incident_id"));
        }
        if self.summary.trim().is_empty() {
            return Err(CorrelationError::InvalidIncidentField("summary"));
        }
        if self.affected_documents.is_empty() {
            return Err(CorrelationError::EmptyAffectedDocuments);
        }
        if self
            .affected_documents
            .iter()
            .any(|id| id.trim().is_empty())
        {
            return Err(CorrelationError::InvalidIncidentField("affected_documents"));
        }
        Ok(())
    }

    /// Convenience: turn the list of affected document ids into a set.
    #[must_use]
    pub fn affected_set(&self) -> HashSet<String> {
        self.affected_documents.iter().cloned().collect()
    }
}

// A field projection, deliberately not a replacement for the full JSON Schema.
#[derive(Deserialize)]
struct SuiteIncidentProjection {
    incident_card_version: String,
    incident: SuiteIncidentIdentity,
    summary: String,
    affected: SuiteAffectedReferences,
}

#[derive(Deserialize)]
struct SuiteIncidentIdentity {
    id: String,
    severity: String,
}

#[derive(Deserialize)]
struct SuiteAffectedReferences {
    #[serde(default, rename = "agent_card_uris")]
    agent: Vec<String>,
    #[serde(default, rename = "tutor_card_uris")]
    tutor: Vec<String>,
    #[serde(default, rename = "tool_card_uris")]
    tool: Vec<String>,
}
