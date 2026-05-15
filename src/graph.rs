//! The Suite graph.
//!
//! Nodes are typed Suite documents (or synthesized vendor nodes). Edges
//! carry a relationship kind so the correlator can ask "what depends on X"
//! without having to encode that logic in the BFS itself.

use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

use crate::error::CorrelationError;
use crate::model::NodeKind;

/// One node in the graph.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SuiteNode {
    /// Stable identifier (e.g. a Decision Card's `decision_id`, an AEO entity URL).
    pub id: String,
    /// What kind of doc this is.
    pub kind: NodeKind,
    /// Free-form human label (vendor name, tool name, …).
    pub label: String,
}

/// What kind of relationship one node has with another.
///
/// All edges point **leaf -> root**, so the correlator's BFS over INCOMING
/// edges naturally answers "what else does this incident touch":
///
///   - `agent --DependsOn--> tool`  (agent is the leaf, tool is the root)
///   - `decision_card --Approves--> vendor`  (decision is the approval root)
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuiteEdge {
    /// `from` requires the existence/health of `to` (agent -> tool, agent -> aeo).
    DependsOn,
    /// `from` (a decision_card) approves `to` (a vendor / AEO entity).
    Approves,
    /// `from` mentions `to` without depending on it (decision_card -> aeo).
    Mentions,
}

/// A typed Suite graph. Construct via [`SuiteGraph::default`] and add nodes
/// + edges before handing it to [`crate::IncidentCorrelator`].
#[derive(Debug, Default)]
pub struct SuiteGraph {
    graph: DiGraph<SuiteNode, SuiteEdge>,
    index: HashMap<String, NodeIndex>,
}

impl SuiteGraph {
    /// Register a node. Re-registering an existing id replaces its `kind` /
    /// `label` and is a no-op for incoming edges.
    pub fn add_node(&mut self, node: SuiteNode) -> NodeIndex {
        if let Some(&existing) = self.index.get(&node.id) {
            self.graph[existing] = node;
            return existing;
        }
        let id = node.id.clone();
        let idx = self.graph.add_node(node);
        self.index.insert(id, idx);
        idx
    }

    /// Add a typed edge. Returns `Err(UnknownEdgeTarget)` if either id is missing.
    pub fn add_edge(
        &mut self,
        from: &str,
        to: &str,
        edge: SuiteEdge,
    ) -> Result<(), CorrelationError> {
        let from_idx = self
            .index
            .get(from)
            .copied()
            .ok_or_else(|| CorrelationError::UnknownEdgeTarget(from.to_string()))?;
        let to_idx = self
            .index
            .get(to)
            .copied()
            .ok_or_else(|| CorrelationError::UnknownEdgeTarget(to.to_string()))?;
        self.graph.add_edge(from_idx, to_idx, edge);
        Ok(())
    }

    /// Internal — look up a node by id.
    pub(crate) fn idx(&self, id: &str) -> Option<NodeIndex> {
        self.index.get(id).copied()
    }

    /// Internal — fetch a node by index.
    pub(crate) fn node(&self, idx: NodeIndex) -> &SuiteNode {
        &self.graph[idx]
    }

    /// Internal — neighbours that point at `idx` via any of `edges`.
    pub(crate) fn inbound(
        &self,
        idx: NodeIndex,
        edges: &[SuiteEdge],
    ) -> Vec<(NodeIndex, SuiteEdge)> {
        self.graph
            .edges_directed(idx, petgraph::Incoming)
            .filter(|e| edges.contains(e.weight()))
            .map(|e| (e.source(), *e.weight()))
            .collect()
    }

    /// Number of nodes — useful for tests + bench setup.
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }
}
