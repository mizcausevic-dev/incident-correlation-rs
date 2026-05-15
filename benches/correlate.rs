//! Throughput micro-benchmark for the correlator.
//!
//! Builds a synthetic 1000-node graph (one tool-card + many agents that depend
//! on it transitively) and times the BFS-based correlation. Run with
//! `cargo bench`.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use incident_correlation::{
    IncidentCard, IncidentCorrelator, NodeKind, SuiteEdge, SuiteGraph, SuiteNode,
};

fn build_fanout(n: usize) -> SuiteGraph {
    let mut g = SuiteGraph::default();
    g.add_node(SuiteNode {
        id: "tool:0".into(),
        kind: NodeKind::ToolCard,
        label: "root".into(),
    });
    for i in 0..n {
        let id = format!("agent:{i}");
        g.add_node(SuiteNode {
            id: id.clone(),
            kind: NodeKind::AgentCard,
            label: format!("Agent {i}"),
        });
        g.add_edge(&id, "tool:0", SuiteEdge::DependsOn).unwrap();
    }
    g
}

fn bench_correlate(c: &mut Criterion) {
    let g = build_fanout(1000);
    let incident = IncidentCard {
        incident_id: "INC-bench".into(),
        summary: "bench".into(),
        severity: "medium".into(),
        affected_documents: vec!["tool:0".into()],
        notes: None,
    };
    let correlator = IncidentCorrelator;

    c.bench_function("correlate_1000_agents_fanout", |b| {
        b.iter(|| {
            let plan = correlator.correlate(&g, &incident).unwrap();
            assert_eq!(plan.affected_nodes.len(), 1001);
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30).measurement_time(Duration::from_secs(3));
    targets = bench_correlate
}
criterion_main!(benches);
