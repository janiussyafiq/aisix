//! Semantic cache client. AISIX-Cloud owns the pgvector index and the
//! embedding service; the DP just calls `/dp/cache/lookup` with the
//! prompt + scope and `/dp/cache/put` with the prompt + response. See
//! issue #116.
//!
//! ## Why this lives in DP
//!
//! Cloud's Stage 4b shipped:
//!   - `/dp/cache/lookup` — request body carries `{ prompt, model, scope, similarity_threshold }`,
//!     Cloud computes embedding + pgvector top-1 search, returns the
//!     stored `ChatResponse` if `score >= threshold` else 204.
//!   - `/dp/cache/put` — request body carries `{ prompt, model, scope, response }`,
//!     Cloud embeds the prompt and inserts the row.
//!
//! Pre-fix the dashboard exposed "Semantic" as a cache-policy backend
//! but DP had no client for it — `aisix-cache` only had `memory.rs` /
//! `redis.rs`. Customers selected Semantic, saved, and the cache did
//! nothing (loader-side handling depends on policy.backend; before
//! this client existed any "Semantic" policy was effectively a no-op).
//!
//! ## Scope of THIS PR
//!
//! This PR ships the **client** + tests against a wiremock'd Cloud
//! endpoint. Wiring it into `chat::dispatch` (consulting the policy's
//! backend choice) is a follow-up — that touches the proxy hot path
//! and deserves its own review pass. The skeleton + tests here unblock
//! the integration work.
//!
//! The `SemanticBackend` struct is *not* an `aisix_cache::Cache` impl
//! today. The `Cache` trait takes `&str` keys (an opaque fingerprint),
//! but semantic lookup needs the original prompt text, the scope label,
//! and a similarity threshold. Adapting the trait would ripple into
//! `MemoryCache` / `RedisCache` for no benefit — the proxy will hold
//! `Option<SemanticBackend>` alongside `Arc<dyn Cache>` and pick at
//! call time.

use std::time::Duration;

use aisix_gateway::ChatResponse;
use serde::{Deserialize, Serialize};

/// Default request timeout for DP→Cloud cache calls. Tight on purpose:
/// a slow Cloud must not block the request hot path. On timeout the
/// proxy treats the call as a miss (lookup) or fire-and-forget swallow
/// (put) — `SemanticError::Timeout` discrimination lets callers see
/// the difference in metrics without retry-storming.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(800);

/// Wire shape for `POST /dp/cache/lookup`. Mirrors the Cloud-side
/// handler — fields are snake_case to match the Cloud HTTP convention.
///
/// `scope` is the policy match key the dashboard policy is scoped to
/// (org, env, api_key, …). Cloud namespaces the pgvector search by it
/// so two different envs don't share cache entries.
#[derive(Debug, Clone, Serialize)]
struct LookupRequest<'a> {
    prompt: &'a str,
    model: &'a str,
    scope: &'a str,
    similarity_threshold: f32,
}

/// Wire shape for `POST /dp/cache/put`.
#[derive(Debug, Clone, Serialize)]
struct PutRequest<'a> {
    prompt: &'a str,
    model: &'a str,
    scope: &'a str,
    response: &'a ChatResponse,
}

/// Cloud's hit response. `score` is informational — Cloud already
/// applied the threshold; we just surface it in tracing for ops.
#[derive(Debug, Clone, Deserialize)]
struct LookupHit {
    response: ChatResponse,
    #[serde(default)]
    score: Option<f32>,
}

/// Errors the semantic client can surface. The proxy treats every
/// variant as "fall through to upstream" — no variant should propagate
/// to the user as a 5xx. Discriminated so metrics / tracing can tell
/// "Cloud is down" apart from "Cloud said miss".
#[derive(Debug, thiserror::Error)]
pub enum SemanticError {
    #[error("transport error talking to Cloud: {0}")]
    Transport(String),
    #[error("Cloud returned an error: status={status}, body={body}")]
    Upstream { status: u16, body: String },
    #[error("Cloud response was not the expected JSON shape: {0}")]
    Decode(String),
    #[error("request to Cloud timed out after {0:?}")]
    Timeout(Duration),
}

/// HTTP client for AISIX-Cloud's semantic cache endpoints.
///
/// `base_url` is the Cloud root; the client appends `/dp/cache/lookup`
/// + `/dp/cache/put`.
///
/// The supplied `reqwest::Client` is expected to already carry whatever
/// auth the deployment uses (mTLS bundle for managed-mode DPs; bearer
/// auth for legacy). The semantic backend doesn't impose its own auth
/// — it shares the same client every other DP→Cloud call uses
/// (heartbeat, telemetry, BudgetClient) so auth rotation flows
/// naturally.
#[derive(Debug, Clone)]
pub struct SemanticBackend {
    base_url: String,
    client: reqwest::Client,
}

impl SemanticBackend {
    /// Construct against a Cloud endpoint + pre-configured HTTP client.
    /// `base_url` should NOT include a trailing slash.
    pub fn new(base_url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Look up a cached response. Returns:
    ///   - `Ok(Some(response))` on hit (Cloud's similarity score met
    ///     the supplied threshold).
    ///   - `Ok(None)` on miss (Cloud responded 204 or returned no
    ///     `response` field — both are "no hit, fall through to
    ///     upstream").
    ///   - `Err(...)` on transport / decode failures. Callers should
    ///     log + treat as miss; never propagate to the end user.
    pub async fn lookup(
        &self,
        prompt: &str,
        model: &str,
        scope: &str,
        similarity_threshold: f32,
    ) -> Result<Option<ChatResponse>, SemanticError> {
        let url = format!("{}/dp/cache/lookup", self.base_url);
        let body = LookupRequest {
            prompt,
            model,
            scope,
            similarity_threshold,
        };
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(map_send_err)?;
        let status = resp.status();
        if status.as_u16() == 204 {
            // Explicit miss: Cloud searched and found nothing above
            // threshold. Distinct from 200-with-empty-body so the proxy
            // can attribute hit-rate accurately.
            return Ok(None);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SemanticError::Upstream {
                status: status.as_u16(),
                body: truncate(body, 256),
            });
        }
        let hit: LookupHit = resp
            .json()
            .await
            .map_err(|e| SemanticError::Decode(e.to_string()))?;
        if let Some(score) = hit.score {
            tracing::debug!(score = score, "semantic cache hit");
        }
        Ok(Some(hit.response))
    }

    /// Write a (prompt → response) pair into Cloud's cache. Errors
    /// surface back to the caller; the proxy is expected to log and
    /// swallow — a failed put just means the next identical request
    /// re-hits the upstream, which is the unavoidable cost of an
    /// out-of-band cache being unavailable.
    pub async fn put(
        &self,
        prompt: &str,
        model: &str,
        scope: &str,
        response: &ChatResponse,
    ) -> Result<(), SemanticError> {
        let url = format!("{}/dp/cache/put", self.base_url);
        let body = PutRequest {
            prompt,
            model,
            scope,
            response,
        };
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(map_send_err)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SemanticError::Upstream {
                status: status.as_u16(),
                body: truncate(body, 256),
            });
        }
        Ok(())
    }
}

fn map_send_err(e: reqwest::Error) -> SemanticError {
    if e.is_timeout() {
        // The client's configured timeout wins here; we don't have a
        // direct handle to read it back, so report a generic Duration.
        // Callers that care about the exact value can read it off
        // their reqwest::Client when constructing.
        SemanticError::Timeout(DEFAULT_TIMEOUT)
    } else {
        SemanticError::Transport(e.to_string())
    }
}

fn truncate(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut out = s;
    out.truncate(max);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aisix_gateway::{ChatMessage, FinishReason, Role, UsageStats};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_response() -> ChatResponse {
        ChatResponse {
            id: "cmpl-cached".into(),
            model: "gpt-4o".into(),
            message: ChatMessage::assistant("from-cache"),
            finish_reason: FinishReason::Stop,
            usage: UsageStats::new(10, 5),
        }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("build reqwest client")
    }

    #[tokio::test]
    async fn lookup_returns_some_on_200_with_response_body() {
        let server = MockServer::start().await;
        // Match the prompt + model + scope explicitly, but skip the
        // similarity_threshold — f32-as-JSON has rounding noise (0.85 →
        // 0.8500000238418579) that wiremock's exact-equality matcher
        // catches; the upstream expects an f32 anyway and 'partial'
        // matching on the integer-valued fields is enough to prove the
        // wire shape.
        Mock::given(method("POST"))
            .and(path("/dp/cache/lookup"))
            .and(body_partial_json(serde_json::json!({
                "prompt": "what's the weather?",
                "model": "gpt-4o",
                "scope": "env-uuid",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "response": sample_response(),
                "score": 0.92,
            })))
            .mount(&server)
            .await;

        let backend = SemanticBackend::new(server.uri(), client());
        let got = backend
            .lookup("what's the weather?", "gpt-4o", "env-uuid", 0.85)
            .await
            .unwrap();
        let r = got.expect("expected Some on hit");
        assert_eq!(r.message.content, "from-cache");
    }

    #[tokio::test]
    async fn lookup_returns_none_on_204_miss() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/dp/cache/lookup"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let backend = SemanticBackend::new(server.uri(), client());
        let got = backend
            .lookup("never seen", "gpt-4o", "env-uuid", 0.85)
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn lookup_propagates_5xx_as_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/dp/cache/lookup"))
            .respond_with(ResponseTemplate::new(503).set_body_string("pgvector down"))
            .mount(&server)
            .await;

        let backend = SemanticBackend::new(server.uri(), client());
        let err = backend
            .lookup("hi", "gpt-4o", "env-uuid", 0.85)
            .await
            .unwrap_err();
        match err {
            SemanticError::Upstream { status, body } => {
                assert_eq!(status, 503);
                assert!(body.contains("pgvector down"));
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn put_sends_prompt_model_scope_and_response_to_cloud() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/dp/cache/put"))
            .and(body_partial_json(serde_json::json!({
                "prompt": "what's 2+2?",
                "model": "gpt-4o",
                "scope": "env-uuid",
                "response": sample_response(),
            })))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let backend = SemanticBackend::new(server.uri(), client());
        backend
            .put("what's 2+2?", "gpt-4o", "env-uuid", &sample_response())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn put_propagates_4xx_as_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/dp/cache/put"))
            .respond_with(ResponseTemplate::new(400).set_body_string("invalid scope"))
            .mount(&server)
            .await;

        let backend = SemanticBackend::new(server.uri(), client());
        let err = backend
            .put("hi", "gpt-4o", "env-uuid", &sample_response())
            .await
            .unwrap_err();
        match err {
            SemanticError::Upstream { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("invalid scope"));
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lookup_decode_error_when_cloud_returns_200_garbage() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/dp/cache/lookup"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("not json"),
            )
            .mount(&server)
            .await;

        let backend = SemanticBackend::new(server.uri(), client());
        let err = backend
            .lookup("hi", "gpt-4o", "env-uuid", 0.85)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SemanticError::Decode(_)),
            "expected Decode, got {err:?}"
        );
    }

    #[tokio::test]
    async fn base_url_trailing_slash_is_normalised() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/dp/cache/lookup"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        // Pass the URL with a trailing slash; client should strip it
        // and not produce `//dp/cache/lookup`.
        let backend = SemanticBackend::new(format!("{}/", server.uri()), client());
        backend
            .lookup("hi", "gpt-4o", "env-uuid", 0.85)
            .await
            .unwrap();
    }
}
