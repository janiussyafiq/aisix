//! Canonical etcd snapshot → resources-file document (the inverse of
//! `aisix_core::filesource`).
//!
//! For each resource kind the exporter re-emits every entry through the
//! same typed model the loader decodes, then rewrites it into idiomatic
//! file form:
//!
//! - **id-stripping** — canonical documents carry no `id` (the typed
//!   models `#[serde(skip)]` their runtime id); the file derives every id
//!   from the entry's name, so nothing to strip beyond what serialization
//!   already omits.
//! - **reference resugaring** — a model's `provider_key_id` becomes
//!   `provider_key: <that key's name>`; a rate-limit policy's `scope_ref`
//!   for `api_key` / `model` scopes becomes the referenced entry's name
//!   (team / member / team_member scopes pass through). A reference that
//!   resolves to no entry in the export set is kept verbatim and a
//!   warning is raised — a dangling reference is a real data issue, not
//!   something to hide.
//! - **api-key identity** — canonical api-key documents have no name, but
//!   the file keys every entry by one; a deterministic `apikey-<hash…>`
//!   display_name is synthesized from the already-safe `key_hash`.
//! - **secret redaction** — see [`super::secrets`].
//!
//! Two entries of one kind that would collapse to the same file identity
//! raise a warning: the file cannot represent both (identities are unique
//! per kind), so surfacing the collision beats silently dropping one.

use std::collections::{BTreeMap, BTreeSet};

use aisix_core::AisixSnapshot;
use serde::Serialize;
use serde_json::Value;

use super::secrets::{redact_by_key, redact_headers, redact_top_level, SecretPlaceholder};

/// Guardrail credential field names, at any nesting depth, that are
/// always secrets in the guardrail schema.
const GUARDRAIL_SECRET_KEYS: &[&str] = &["api_key", "access_key_secret", "secret_access_key"];

/// The assembled export, ready to emit as YAML plus the side-channel
/// information the command reports on stderr.
pub struct ExportDocument {
    /// `(kind, entries)` in the file's fixed collection order; only
    /// non-empty kinds are included.
    pub collections: Vec<(&'static str, Vec<Value>)>,
    /// Placeholders substituted for live credentials (empty when
    /// `reveal_secrets` is set).
    pub secret_placeholders: Vec<SecretPlaceholder>,
    /// Non-fatal issues to surface: dangling references, identity
    /// collisions, kinds the file format cannot represent.
    pub warnings: Vec<String>,
}

/// Build the resources-file document from a decoded etcd snapshot.
pub fn build_export_document(snapshot: &AisixSnapshot, reveal_secrets: bool) -> ExportDocument {
    let mut warnings = Vec::new();
    let mut placeholders = Vec::new();

    // Reference resolution maps: etcd id → the name the file keys the
    // entry by. Built once so every resugared reference resolves against
    // the same identities the entries are emitted under.
    let provider_key_names = id_to_name(&snapshot.provider_keys, |pk| pk.display_name.clone());
    let model_names = id_to_name(&snapshot.models, |m| m.display_name.clone());
    let api_key_names = id_to_name(&snapshot.apikeys, |k| synthetic_api_key_name(&k.key_hash));

    let mut collections: Vec<(&'static str, Vec<Value>)> = Vec::new();

    // provider_keys — identity: display_name; secret: api_key.
    push_kind(
        &mut collections,
        "provider_keys",
        emit_entries(
            &snapshot.provider_keys,
            |pk| pk.display_name.clone(),
            "provider_keys",
            &mut warnings,
            |doc, identity, _warnings| {
                redact_top_level(
                    doc,
                    "api_key",
                    "PROVIDER_KEY",
                    "provider_keys",
                    identity,
                    reveal_secrets,
                    &mut placeholders,
                );
            },
        ),
    );

    // models — identity: display_name; resugar provider_key_id → provider_key.
    push_kind(
        &mut collections,
        "models",
        emit_entries(
            &snapshot.models,
            |m| m.display_name.clone(),
            "models",
            &mut warnings,
            |doc, identity, warnings| {
                resugar_provider_key(doc, identity, &provider_key_names, warnings)
            },
        ),
    );

    // api_keys — identity: synthesized display_name; key_hash emitted verbatim.
    push_kind(
        &mut collections,
        "api_keys",
        emit_entries(
            &snapshot.apikeys,
            |k| synthetic_api_key_name(&k.key_hash),
            "api_keys",
            &mut warnings,
            |doc, identity, _warnings| {
                if let Value::Object(map) = doc {
                    map.insert("display_name".into(), Value::String(identity.to_string()));
                }
            },
        ),
    );

    // guardrails — identity: name; recursive credential redaction.
    push_kind(
        &mut collections,
        "guardrails",
        emit_entries(
            &snapshot.guardrails,
            |g| g.name.clone(),
            "guardrails",
            &mut warnings,
            |doc, identity, _warnings| {
                redact_by_key(
                    doc,
                    GUARDRAIL_SECRET_KEYS,
                    "GUARDRAIL",
                    "guardrails",
                    identity,
                    reveal_secrets,
                    &mut placeholders,
                );
            },
        ),
    );

    // mcp_servers — identity: name; secret: secret.
    push_kind(
        &mut collections,
        "mcp_servers",
        emit_entries(
            &snapshot.mcp_servers,
            |s| s.name.clone(),
            "mcp_servers",
            &mut warnings,
            |doc, identity, _warnings| {
                redact_top_level(
                    doc,
                    "secret",
                    "MCP_SERVER",
                    "mcp_servers",
                    identity,
                    reveal_secrets,
                    &mut placeholders,
                );
            },
        ),
    );

    // a2a_agents — identity: name; secret: secret.
    push_kind(
        &mut collections,
        "a2a_agents",
        emit_entries(
            &snapshot.a2a_agents,
            |a| a.name.clone(),
            "a2a_agents",
            &mut warnings,
            |doc, identity, _warnings| {
                redact_top_level(
                    doc,
                    "secret",
                    "A2A_AGENT",
                    "a2a_agents",
                    identity,
                    reveal_secrets,
                    &mut placeholders,
                );
            },
        ),
    );

    // cache_policies — identity: name; no secrets.
    push_kind(
        &mut collections,
        "cache_policies",
        emit_entries(
            &snapshot.cache_policies,
            |c| c.name.clone(),
            "cache_policies",
            &mut warnings,
            |_, _, _| {},
        ),
    );

    // observability_exporters — identity: name; redact OTLP headers.
    push_kind(
        &mut collections,
        "observability_exporters",
        emit_entries(
            &snapshot.observability_exporters,
            |e| e.name.clone(),
            "observability_exporters",
            &mut warnings,
            |doc, identity, _warnings| {
                redact_headers(
                    doc,
                    "OBSERVABILITY_EXPORTER",
                    "observability_exporters",
                    identity,
                    reveal_secrets,
                    &mut placeholders,
                );
            },
        ),
    );

    // rate_limit_policies — identity: name; resugar scope_ref for
    // api_key / model scopes to the referenced entry's name.
    push_kind(
        &mut collections,
        "rate_limit_policies",
        emit_entries(
            &snapshot.rate_limit_policies,
            |p| p.name.clone(),
            "rate_limit_policies",
            &mut warnings,
            |doc, identity, warnings| {
                resugar_scope_ref(doc, identity, &model_names, &api_key_names, warnings)
            },
        ),
    );

    // guardrail_attachments have no collection in the file format — the
    // file has no attachment surface, so file-mode guardrails apply
    // env-globally. Surface that the bindings cannot round-trip rather
    // than dropping them silently.
    let attachments = snapshot.guardrail_attachments.len();
    if attachments > 0 {
        warnings.push(format!(
            "{attachments} guardrail_attachment(s) cannot be represented in the resources file \
             (it has no attachment collection; file-mode guardrails apply gateway-wide) — omitted \
             from the export"
        ));
    }

    ExportDocument {
        collections,
        secret_placeholders: placeholders,
        warnings,
    }
}

/// Deterministic file identity for a canonical api-key document, which
/// carries no name of its own. `key_hash` is already a SHA-256 hash
/// (safe to surface) and unique per credential, so a short prefix keys
/// the entry stably without exposing anything sensitive.
fn synthetic_api_key_name(key_hash: &str) -> String {
    let short: String = key_hash.chars().take(12).collect();
    format!("apikey-{short}")
}

fn push_kind(
    collections: &mut Vec<(&'static str, Vec<Value>)>,
    kind: &'static str,
    entries: Vec<Value>,
) {
    if !entries.is_empty() {
        collections.push((kind, entries));
    }
}

/// Build an `etcd id → file identity` map for one table.
fn id_to_name<T, F>(
    table: &aisix_core::snapshot::ResourceTable<T>,
    identity: F,
) -> BTreeMap<String, String>
where
    T: aisix_core::resource::Resource,
    F: Fn(&T) -> String,
{
    table
        .entries()
        .into_iter()
        .map(|entry| (entry.id.clone(), identity(&entry.value)))
        .collect()
}

/// Serialize every entry of a table (sorted by identity for stable
/// output), run the per-kind rewrite, and collect duplicate-identity
/// warnings. `identity` extracts the file key; `rewrite` mutates the
/// canonical JSON in place (resugaring, redaction, synthesized fields)
/// and may append its own warnings via the sink it is handed — the sink
/// is threaded through rather than captured so a resugaring rewrite and
/// this function share one `warnings` without a double borrow.
fn emit_entries<T, I, R>(
    table: &aisix_core::snapshot::ResourceTable<T>,
    identity: I,
    kind: &'static str,
    warnings: &mut Vec<String>,
    mut rewrite: R,
) -> Vec<Value>
where
    T: aisix_core::resource::Resource + Serialize,
    I: Fn(&T) -> String,
    R: FnMut(&mut Value, &str, &mut Vec<String>),
{
    let mut entries: Vec<_> = table.entries();
    // Stable, human-diffable order independent of DashMap shard layout.
    entries.sort_by(|a, b| identity(&a.value).cmp(&identity(&b.value)));

    let mut out = Vec::with_capacity(entries.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let id = identity(&entry.value);
        let mut doc = match serde_json::to_value(&entry.value) {
            Ok(Value::Object(map)) => Value::Object(map),
            Ok(other) => {
                warnings.push(format!(
                    "{kind} entry {id:?} did not serialize to a document ({other}); skipped"
                ));
                continue;
            }
            Err(e) => {
                warnings.push(format!(
                    "{kind} entry {id:?} could not be serialized ({e}); skipped"
                ));
                continue;
            }
        };
        if !seen.insert(id.clone()) {
            warnings.push(format!(
                "two {kind} entries share the identity {id:?}; the resources file keys entries by \
                 name and cannot represent both — resolve the collision in the source data"
            ));
        }
        rewrite(&mut doc, &id, warnings);
        out.push(doc);
    }
    out
}

/// `provider_key_id` (canonical) → `provider_key: <name>` (file sugar).
fn resugar_provider_key(
    doc: &mut Value,
    model: &str,
    provider_key_names: &BTreeMap<String, String>,
    warnings: &mut Vec<String>,
) {
    let Some(map) = doc.as_object_mut() else {
        return;
    };
    let Some(id) = map
        .get("provider_key_id")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return;
    };
    match provider_key_names.get(&id) {
        Some(name) => {
            map.remove("provider_key_id");
            map.insert("provider_key".into(), Value::String(name.clone()));
        }
        None => warnings.push(format!(
            "model {model:?} references provider_key_id {id:?}, which is not among the exported \
             provider keys — kept as a raw id (dangling reference in the source data)"
        )),
    }
}

/// `scope_ref` (canonical id) → the referenced entry's name for
/// `api_key` / `model` scopes. Team-family scopes pass through verbatim.
fn resugar_scope_ref(
    doc: &mut Value,
    policy: &str,
    model_names: &BTreeMap<String, String>,
    api_key_names: &BTreeMap<String, String>,
    warnings: &mut Vec<String>,
) {
    let Some(map) = doc.as_object_mut() else {
        return;
    };
    let (lookup, label) = match map.get("scope").and_then(Value::as_str) {
        Some("model") => (model_names, "model"),
        Some("api_key") => (api_key_names, "api key"),
        // team / member / team_member reference external ids the file
        // carries verbatim; anything else is left for schema validation.
        _ => return,
    };
    let Some(id) = map
        .get("scope_ref")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return;
    };
    match lookup.get(&id) {
        Some(name) => {
            map.insert("scope_ref".into(), Value::String(name.clone()));
        }
        None => warnings.push(format!(
            "rate_limit_policy {policy:?} scope_ref references {label} id {id:?}, which is not \
             among the exported {label}s — kept as a raw id (dangling reference in the source data)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aisix_core::resource::ResourceEntry;
    use serde_json::json;

    fn provider_key(display_name: &str, api_key: &str) -> aisix_core::models::ProviderKey {
        serde_json::from_value(json!({"display_name": display_name, "api_key": api_key})).unwrap()
    }

    fn model_value(json: Value) -> aisix_core::models::Model {
        serde_json::from_value(json).unwrap()
    }

    fn find<'a>(doc: &'a ExportDocument, kind: &str) -> &'a [Value] {
        doc.collections
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    }

    #[test]
    fn provider_key_ref_resugars_to_name() {
        let snap = AisixSnapshot::new();
        snap.provider_keys.insert(ResourceEntry::new(
            "pk-uuid-1",
            provider_key("openai-prod", "sk-live"),
            1,
        ));
        snap.models.insert(ResourceEntry::new(
            "m-uuid-1",
            model_value(json!({
                "display_name": "gpt-4o",
                "provider": "openai",
                "model_name": "gpt-4o-2024-11-20",
                "provider_key_id": "pk-uuid-1"
            })),
            1,
        ));

        let doc = build_export_document(&snap, false);
        let models = find(&doc, "models");
        assert_eq!(models.len(), 1);
        // Canonical id reference gone; file name sugar in its place.
        assert!(models[0].get("provider_key_id").is_none());
        assert_eq!(models[0]["provider_key"], json!("openai-prod"));
    }

    #[test]
    fn dangling_provider_key_ref_is_kept_and_warned() {
        let snap = AisixSnapshot::new();
        snap.models.insert(ResourceEntry::new(
            "m-uuid-1",
            model_value(json!({
                "display_name": "orphan",
                "provider": "openai",
                "model_name": "gpt-4o",
                "provider_key_id": "pk-does-not-exist"
            })),
            1,
        ));
        let doc = build_export_document(&snap, false);
        let models = find(&doc, "models");
        assert_eq!(models[0]["provider_key_id"], json!("pk-does-not-exist"));
        assert!(models[0].get("provider_key").is_none());
        assert!(
            doc.warnings
                .iter()
                .any(|w| w.contains("dangling") && w.contains("orphan")),
            "{:?}",
            doc.warnings
        );
    }

    #[test]
    fn api_key_gets_synthetic_name_and_keeps_key_hash() {
        let snap = AisixSnapshot::new();
        let key_hash = "91ed2dbc407561556f3e7be98ba0bd2a57986d6a868c482d867d19c6d40d201c";
        snap.apikeys.insert(ResourceEntry::new(
            "k-uuid-1",
            serde_json::from_value(json!({"key_hash": key_hash, "allowed_models": ["*"]})).unwrap(),
            1,
        ));
        let doc = build_export_document(&snap, false);
        let keys = find(&doc, "api_keys");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["display_name"], json!("apikey-91ed2dbc4075"));
        // key_hash is already hashed — emitted verbatim, no placeholder.
        assert_eq!(keys[0]["key_hash"], json!(key_hash));
        assert!(doc.secret_placeholders.is_empty());
    }

    #[test]
    fn scope_ref_resolves_for_model_and_api_key_scopes() {
        let snap = AisixSnapshot::new();
        let key_hash = "aa".repeat(32);
        snap.models.insert(ResourceEntry::new(
            "m-uuid-1",
            model_value(json!({"display_name": "gpt-4o", "provider": "openai", "model_name": "x", "provider_key_id": "pk"})),
            1,
        ));
        snap.apikeys.insert(ResourceEntry::new(
            "k-uuid-1",
            serde_json::from_value(json!({"key_hash": key_hash, "allowed_models": ["*"]})).unwrap(),
            1,
        ));
        snap.provider_keys
            .insert(ResourceEntry::new("pk", provider_key("pk", "sk"), 1));
        for (name, scope, scope_ref) in [
            ("cap-model", "model", "m-uuid-1"),
            ("cap-key", "api_key", "k-uuid-1"),
            ("cap-team", "team", "team-uuid-9"),
        ] {
            snap.rate_limit_policies.insert(ResourceEntry::new(
                format!("rlp-{name}"),
                serde_json::from_value(json!({
                    "name": name, "scope": scope, "scope_ref": scope_ref,
                    "window": "minute", "max_requests": 10
                }))
                .unwrap(),
                1,
            ));
        }

        let doc = build_export_document(&snap, false);
        let policies = find(&doc, "rate_limit_policies");
        let by_name = |n: &str| policies.iter().find(|p| p["name"] == json!(n)).unwrap();
        assert_eq!(by_name("cap-model")["scope_ref"], json!("gpt-4o"));
        assert_eq!(
            by_name("cap-key")["scope_ref"],
            json!(synthetic_api_key_name(&"aa".repeat(32)))
        );
        // team scope passes through verbatim.
        assert_eq!(by_name("cap-team")["scope_ref"], json!("team-uuid-9"));
    }

    #[test]
    fn duplicate_identity_within_a_kind_warns() {
        let snap = AisixSnapshot::new();
        // Two provider keys with the same display_name but distinct ids —
        // possible in raw etcd, impossible in the file.
        snap.provider_keys
            .insert(ResourceEntry::new("pk-a", provider_key("dup", "sk-a"), 1));
        snap.provider_keys
            .insert(ResourceEntry::new("pk-b", provider_key("dup", "sk-b"), 1));
        let doc = build_export_document(&snap, false);
        assert!(
            doc.warnings
                .iter()
                .any(|w| w.contains("share the identity") && w.contains("dup")),
            "{:?}",
            doc.warnings
        );
    }

    #[test]
    fn default_export_emits_no_live_provider_secret() {
        let snap = AisixSnapshot::new();
        snap.provider_keys.insert(ResourceEntry::new(
            "pk-1",
            provider_key("openai-prod", "sk-super-secret-do-not-leak"),
            1,
        ));
        let doc = build_export_document(&snap, false);
        let pks = find(&doc, "provider_keys");
        assert_eq!(
            pks[0]["api_key"],
            json!("${AISIXSECRET_PROVIDER_KEY_OPENAI_PROD_API_KEY}")
        );
        // Secret must appear nowhere in the assembled collections.
        let rendered =
            serde_json::to_string(&doc.collections.iter().map(|(_, v)| v).collect::<Vec<_>>())
                .unwrap();
        assert!(
            !rendered.contains("sk-super-secret-do-not-leak"),
            "{rendered}"
        );
        assert_eq!(doc.secret_placeholders.len(), 1);
    }

    #[test]
    fn reveal_secrets_emits_the_real_value_inline() {
        let snap = AisixSnapshot::new();
        snap.provider_keys.insert(ResourceEntry::new(
            "pk-1",
            provider_key("openai-prod", "sk-real-value"),
            1,
        ));
        let doc = build_export_document(&snap, true);
        let pks = find(&doc, "provider_keys");
        assert_eq!(pks[0]["api_key"], json!("sk-real-value"));
        assert!(doc.secret_placeholders.is_empty());
    }

    #[test]
    fn guardrail_attachments_are_flagged_as_unrepresentable() {
        let snap = AisixSnapshot::new();
        snap.guardrail_attachments.insert(ResourceEntry::new(
            "att-1",
            serde_json::from_value(json!({
                "guardrail_id": "g-1", "scope_type": "env", "priority": 1
            }))
            .unwrap(),
            1,
        ));
        let doc = build_export_document(&snap, false);
        assert!(
            doc.warnings
                .iter()
                .any(|w| w.contains("guardrail_attachment")),
            "{:?}",
            doc.warnings
        );
        assert!(doc
            .collections
            .iter()
            .all(|(k, _)| *k != "guardrail_attachments"));
    }

    #[test]
    fn empty_snapshot_yields_only_a_header_later() {
        let snap = AisixSnapshot::new();
        let doc = build_export_document(&snap, false);
        assert!(doc.collections.is_empty());
        assert!(doc.secret_placeholders.is_empty());
        assert!(doc.warnings.is_empty());
    }
}
