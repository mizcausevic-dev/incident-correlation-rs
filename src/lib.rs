//! # incident-correlation
//!
//! Walks a caller-supplied Kinetic Gain Protocol Suite document graph starting
//! from an AI Incident Card and emits a suggested remediation plan.
//!
//! ## What it answers
//!
//! When something goes wrong with a deployed AI system, the operator writes
//! an **AI Incident Card** that references the affected pieces — usually a
//! tool, an agent, or a specific vendor's AEO entity. The honest question
//! after that is: *what else does this incident touch?*
//!
//!  - Which **agent-cards** depend on the affected tool?
//!  - Which **decision-cards** approved the affected vendor?
//!  - Which nodes depend on the affected documents through `DependsOn` and
//!    `Approves` edges?
//!
//! `IncidentCorrelator::correlate` walks the graph and returns a
//! [`RemediationPlan`] with each affected node + a suggested action.
//!
//! ## Design
//!
//! - The graph is a `petgraph::Graph` of [`SuiteNode`]s.
//! - Edges are typed ([`SuiteEdge::DependsOn`], [`SuiteEdge::Approves`],
//!   [`SuiteEdge::Mentions`]), so the correlator can answer "what depends on
//!   X" with one BFS over a typed edge filter.
//! - The whole pipeline is synchronous because graph work doesn't need an
//!   executor. `tokio` only shows up in dev-deps for the test harness.
//!
//! ## Composes with
//!
//! - **[procurement-decision-api](https://github.com/mizcausevic-dev/procurement-decision-api)** —
//!   the Decision Cards this crate walks across.
//! - **[policy-as-code-engine](https://github.com/mizcausevic-dev/policy-as-code-engine)** —
//!   a `RecheckPolicy` recommendation can prompt operator review of the
//!   PolicyBundles those cards produced.
//! - **[aeo-validator-service](https://github.com/mizcausevic-dev/aeo-validator-service)** —
//!   an operator can recheck an affected AEO doc if a watch exists.
//!
//! This crate does not fetch or validate documents, verify graph completeness,
//! execute actions, or call those services.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::match_same_arms)]

pub mod correlator;
pub mod error;
pub mod graph;
pub mod model;
pub mod plan;

/// Optional audit-stream-py producer. Gated behind the `audit-stream`
/// Cargo feature so the core graph crate stays sync and HTTP-free.
#[cfg(feature = "audit-stream")]
pub mod audit_stream;

pub use correlator::IncidentCorrelator;
pub use error::CorrelationError;
pub use graph::{SuiteEdge, SuiteGraph, SuiteNode};
pub use model::{IncidentCard, NodeKind};
pub use plan::{Action, AffectedNode, RemediationPlan, Urgency};
