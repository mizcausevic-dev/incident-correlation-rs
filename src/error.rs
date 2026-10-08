//! Crate-wide error type.

use thiserror::Error;

/// Anything that can go wrong inside the crate.
#[derive(Debug, Error)]
pub enum CorrelationError {
    /// Failed to deserialise the incident card.
    #[error("invalid incident card: {0}")]
    InvalidIncident(#[from] serde_json::Error),

    /// The input uses an Incident Card version this projection does not support.
    #[error("unsupported incident card version: {0}")]
    UnsupportedIncidentVersion(String),

    /// A projected or compact input has a blank required field.
    #[error("incident input has an empty required field: {0}")]
    InvalidIncidentField(&'static str),

    /// A plan needs at least one directly affected graph node.
    #[error("affected_documents must contain at least one node id")]
    EmptyAffectedDocuments,

    /// Unknown severity must not silently lower the urgency of an incident.
    #[error("unknown incident severity: {0}")]
    InvalidSeverity(String),

    /// An `affected_documents` entry pointed at a node not in the graph.
    #[error("affected_documents references unknown node id: {0}")]
    UnknownAffectedNode(String),

    /// An edge tried to point at a node id that wasn't added first.
    #[error("graph edge points at unknown node id: {0}")]
    UnknownEdgeTarget(String),
}
