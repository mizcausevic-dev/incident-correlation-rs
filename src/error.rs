//! Crate-wide error type.

use thiserror::Error;

/// Anything that can go wrong inside the crate.
#[derive(Debug, Error)]
pub enum CorrelationError {
    /// Failed to deserialise the incident card.
    #[error("invalid incident card: {0}")]
    InvalidIncident(#[from] serde_json::Error),

    /// An `affected_documents` entry pointed at a node not in the graph.
    #[error("affected_documents references unknown node id: {0}")]
    UnknownAffectedNode(String),

    /// An edge tried to point at a node id that wasn't added first.
    #[error("graph edge points at unknown node id: {0}")]
    UnknownEdgeTarget(String),
}
