//! Optional audit-stream-py integration.
//!
//! When the `audit-stream` Cargo feature is enabled **and** the
//! `AUDIT_STREAM_URL` env var is set, callers can fire one
//! `incident_correlated` event per remediation plan. Delivery is not proof
//! that a destination stored or hash-chained the event.
//!
//! Same opt-in pattern as the Python producers (procurement-decision-api,
//! aeo-validator-service, policy-as-code-engine, data-contract-registry).
//! Identical env-var contract:
//!
//! - `AUDIT_STREAM_URL`        — base URL, e.g. `http://audit.local:8093`
//! - `AUDIT_STREAM_TIMEOUT_S`  — per-call timeout, default 2.5s
//!
//! Best-effort. Failures are logged to stderr and swallowed. This is not a
//! durable audit receipt: operators who require one must confirm acceptance
//! with the audit service before treating a plan as recorded.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "audit-stream")]
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use incident_correlation::audit_stream;
//! use serde_json::json;
//!
//! let client = reqwest::Client::new();
//! audit_stream::emit(
//!     &client,
//!     "incident_correlated",
//!     json!({
//!         "incident_id": "INC-2026-001",
//!         "affected_node_count": 7,
//!         "max_urgency": "high",
//!     }),
//! )
//! .await;
//! # Ok(()) }
//! ```

use std::env;
use std::time::Duration;

use serde_json::json;

/// Default per-call timeout when `AUDIT_STREAM_TIMEOUT_S` is unset.
pub const DEFAULT_TIMEOUT_S: f64 = 2.5;

/// True when `AUDIT_STREAM_URL` is set to a non-empty value.
#[must_use]
pub fn is_enabled() -> bool {
    base_url().is_some()
}

/// Stripped HTTP(S) audit-stream base URL, or `None` when unset or invalid.
/// URLs with embedded credentials, queries, or fragments are rejected.
#[must_use]
pub fn base_url() -> Option<String> {
    let raw = env::var("AUDIT_STREAM_URL").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(trimmed.trim_end_matches('/').to_string())
}

/// Configured per-call timeout, clamped to 0.1–30 seconds. Defaults to 2.5 seconds.
#[must_use]
pub fn timeout() -> Duration {
    let secs = env::var("AUDIT_STREAM_TIMEOUT_S")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .map_or(DEFAULT_TIMEOUT_S, |v| v.clamp(0.1, 30.0));
    Duration::from_secs_f64(secs)
}

/// Fire one event. Silent no-op when `AUDIT_STREAM_URL` is unset.
///
/// Failures (connection refused, HTTP 5xx, timeout, malformed URL) are
/// logged to stderr and swallowed — this never returns an error.
pub async fn emit(client: &reqwest::Client, kind: &str, payload: serde_json::Value) {
    let Some(url) = base_url() else {
        return;
    };
    let body = json!({
        "kind": kind,
        "source": "incident-correlation",
        "payload": payload,
    });
    let endpoint = format!("{url}/events");
    let result = client
        .post(&endpoint)
        .json(&body)
        .timeout(timeout())
        .send()
        .await;
    match result {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            eprintln!("audit-stream emit failed: HTTP {}", resp.status());
        }
        Err(_) => {
            eprintln!("audit-stream emit failed: request failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // AUDIT_STREAM_URL / AUDIT_STREAM_TIMEOUT_S are process-global, so
    // tests that mutate them must run serially. Cargo runs tests in
    // parallel by default; this mutex re-introduces serialization for
    // just these cases.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn reset_env() {
        env::remove_var("AUDIT_STREAM_URL");
        env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }

    #[test]
    fn disabled_when_unset() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        assert!(!is_enabled());
        assert!(base_url().is_none());
    }

    #[test]
    fn disabled_when_blank() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_URL", "   ");
        assert!(!is_enabled());
        env::remove_var("AUDIT_STREAM_URL");
    }

    #[test]
    fn enabled_with_value() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_URL", "http://audit.local:8093");
        assert!(is_enabled());
        assert_eq!(base_url().unwrap(), "http://audit.local:8093");
        env::remove_var("AUDIT_STREAM_URL");
    }

    #[test]
    fn trailing_slash_stripped() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_URL", "http://audit.local:8093/");
        assert_eq!(base_url().unwrap(), "http://audit.local:8093");
        env::remove_var("AUDIT_STREAM_URL");
    }

    #[test]
    fn timeout_default() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        assert_eq!(timeout(), Duration::from_secs_f64(DEFAULT_TIMEOUT_S));
    }

    #[test]
    fn timeout_override() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_TIMEOUT_S", "5.0");
        assert_eq!(timeout(), Duration::from_secs_f64(5.0));
        env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }

    #[test]
    fn timeout_bad_value_falls_back() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_TIMEOUT_S", "not-a-number");
        assert_eq!(timeout(), Duration::from_secs_f64(DEFAULT_TIMEOUT_S));
        env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }

    #[test]
    fn timeout_nonfinite_value_falls_back_and_large_value_is_clamped() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_TIMEOUT_S", "NaN");
        assert_eq!(timeout(), Duration::from_secs_f64(DEFAULT_TIMEOUT_S));
        env::set_var("AUDIT_STREAM_TIMEOUT_S", "inf");
        assert_eq!(timeout(), Duration::from_secs_f64(DEFAULT_TIMEOUT_S));
        env::set_var("AUDIT_STREAM_TIMEOUT_S", "1e300");
        assert_eq!(timeout(), Duration::from_secs(30));
        reset_env();
    }

    #[test]
    fn malformed_or_credentialed_url_is_disabled() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        for url in [
            "not-a-url",
            "file:///tmp/audit",
            "https://user:password@audit.example",
            "https://audit.example/?token=secret",
            "https://audit.example/#fragment",
        ] {
            env::set_var("AUDIT_STREAM_URL", url);
            assert!(!is_enabled(), "{url} must not enable audit emission");
        }
        reset_env();
    }
}
