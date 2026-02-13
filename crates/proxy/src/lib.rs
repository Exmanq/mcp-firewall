use audit::{AuditEvent, AuditLogger};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::Engine;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use policy::{PolicyFile, RequestContext};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: String,
    pub policy: PolicyFile,
    pub audit: AuditLogger,
    pub verify_key: Option<VerifyingKey>,
    pub sign_key: Option<SigningKey>,
}

#[derive(Clone)]
struct AppState {
    cfg: ProxyConfig,
    client: reqwest::Client,
    buckets: Arc<DashMap<String, (u32, Instant)>>,
}

#[derive(Debug, Deserialize)]
struct RpcReq {
    method: String,
    #[serde(default)]
    params: Value,
}

pub async fn run(config: ProxyConfig) -> anyhow::Result<()> {
    let state = AppState {
        cfg: config,
        client: reqwest::Client::new(),
        buckets: Arc::new(DashMap::new()),
    };

    let app = Router::new()
        .route("/mcp", post(handle_mcp))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(state.cfg.listen).await?;
    info!("mcp-firewall listening on {}", state.cfg.listen);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let request_id = Uuid::new_v4().to_string();
    let parsed: RpcReq = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_json_rpc_request"})),
            )
                .into_response()
        }
    };

    let path = parsed
        .params
        .get("path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let valid_sig = verify_signature(&state, &headers, &body);

    if is_rate_limited(&state, &headers, &parsed.method) {
        let _ = state.cfg.audit.log(AuditEvent {
            request_id,
            method: parsed.method,
            allowed: false,
            reason: "rate_limited".into(),
            origin,
            upstream_status: None,
            timestamp: String::new(),
        });
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }

    let decision = state.cfg.policy.evaluate(&RequestContext {
        method: parsed.method.clone(),
        path,
        origin: origin.clone(),
        body_len: body.len(),
        has_valid_signature: valid_sig,
    });

    if !decision.allow {
        let _ = state.cfg.audit.log(AuditEvent {
            request_id,
            method: parsed.method,
            allowed: false,
            reason: decision.reason,
            origin,
            upstream_status: None,
            timestamp: String::new(),
        });
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "blocked_by_policy"})),
        )
            .into_response();
    }

    match state
        .client
        .post(format!("{}/mcp", state.cfg.upstream))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let resp_body = resp.text().await.unwrap_or_else(|_| "{}".to_string());
            let _ = state.cfg.audit.log(AuditEvent {
                request_id,
                method: parsed.method,
                allowed: true,
                reason: "forwarded".into(),
                origin,
                upstream_status: Some(status.as_u16()),
                timestamp: String::new(),
            });
            let mut out = axum::response::Response::builder()
                .status(status)
                .header("content-type", "application/json");
            if let Some(signature) = sign_response(&state, &resp_body) {
                out = out.header("x-mcp-firewall-signature", signature);
            }
            out.body(axum::body::Body::from(resp_body))
                .unwrap()
                .into_response()
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "upstream_unreachable"})),
        )
            .into_response(),
    }
}

fn verify_signature(state: &AppState, headers: &HeaderMap, body: &str) -> bool {
    let Some(key) = &state.cfg.verify_key else {
        return true;
    };
    let Some(raw) = headers.get("x-mcp-signature").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(raw) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&bytes) else {
        return false;
    };
    key.verify(body.as_bytes(), &sig).is_ok()
}

fn sign_response(state: &AppState, body: &str) -> Option<String> {
    let key = state.cfg.sign_key.as_ref()?;
    if !state.cfg.policy.firewall.sign_responses {
        return None;
    }
    let sig = key.sign(body.as_bytes());
    Some(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

fn is_rate_limited(state: &AppState, headers: &HeaderMap, method: &str) -> bool {
    let key = format!(
        "{}:{}",
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("local"),
        method
    );
    let limit = state.cfg.policy.firewall.rate_limit_per_minute;
    let now = Instant::now();
    let mut entry = state.buckets.entry(key).or_insert((0, now));
    if now.duration_since(entry.1) > Duration::from_secs(60) {
        *entry = (1, now);
        return false;
    }
    if entry.0 >= limit {
        return true;
    }
    entry.0 += 1;
    false
}
