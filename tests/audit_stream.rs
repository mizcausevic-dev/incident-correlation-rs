//! Integration tests for the optional `audit-stream` feature.
//!
//! Only compiled when `cargo test --features audit-stream` is run. CI
//! exercises both paths so the default build stays sync-only.

#![cfg(feature = "audit-stream")]

use incident_correlation::audit_stream;
use serde_json::{json, Value};
use std::sync::Mutex;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// AUDIT_STREAM_URL / AUDIT_STREAM_TIMEOUT_S are process-global. Serialise
// these tests so concurrent cases don't see each other's env writes.
static ENV_GUARD: Mutex<()> = Mutex::new(());

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn lock() -> Self {
        let lock = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AUDIT_STREAM_URL");
        std::env::remove_var("AUDIT_STREAM_TIMEOUT_S");
        EnvGuard { _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("AUDIT_STREAM_URL");
        std::env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }
}

#[tokio::test]
async fn emit_is_noop_when_url_unset() {
    let _guard = EnvGuard::lock();
    // No server expectations — if emit fired, we'd see a connect refused
    // log but it would still return Ok.
    let client = reqwest::Client::new();
    audit_stream::emit(
        &client,
        "incident_correlated",
        json!({"incident_id": "INC-1"}),
    )
    .await;
}

#[tokio::test]
async fn emit_posts_to_events_endpoint() {
    let _guard = EnvGuard::lock();
    let server = MockServer::start().await;
    std::env::set_var("AUDIT_STREAM_URL", server.uri());

    Mock::given(method("POST"))
        .and(path("/events"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"event_id": 1})))
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    audit_stream::emit(
        &client,
        "incident_correlated",
        json!({
            "incident_id": "INC-2026-001",
            "affected_node_count": 5,
        }),
    )
    .await;

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let body: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(body["kind"], "incident_correlated");
    assert_eq!(body["source"], "incident-correlation");
    assert_eq!(body["payload"]["incident_id"], "INC-2026-001");
    assert_eq!(body["payload"]["affected_node_count"], 5);
}

#[tokio::test]
async fn emit_swallows_server_error() {
    let _guard = EnvGuard::lock();
    let server = MockServer::start().await;
    std::env::set_var("AUDIT_STREAM_URL", server.uri());

    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    // Must not panic / return error.
    audit_stream::emit(&client, "incident_correlated", json!({})).await;
}

#[tokio::test]
async fn emit_swallows_connection_refused() {
    let _guard = EnvGuard::lock();
    // Port nothing's listening on. emit must log + swallow.
    std::env::set_var("AUDIT_STREAM_URL", "http://127.0.0.1:1");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    audit_stream::emit(&client, "incident_correlated", json!({})).await;
}

#[tokio::test]
async fn emit_strips_trailing_slash() {
    let _guard = EnvGuard::lock();
    let server = MockServer::start().await;
    // Set URL with trailing slash. /events must still resolve.
    std::env::set_var("AUDIT_STREAM_URL", format!("{}/", server.uri()));

    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    audit_stream::emit(&client, "incident_correlated", json!({})).await;
}
