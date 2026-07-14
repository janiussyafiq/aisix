//! `aisix export` — emit a resources file from a running etcd store.
//!
//! The inverse of the file source (`aisix_core::filesource`): it reads
//! every canonical resource document under the configured prefix, decodes
//! it through the same typed models the gateway loads, and re-emits the
//! set as a `resources.yaml` the file source can load back — the
//! migration / backup path for a standalone deployment moving from
//! Admin-API-plus-etcd to the declarative file.
//!
//! Pipeline:
//!
//! ```text
//! etcd range read → decode (aisix_etcd::build_snapshot, the loader path)
//!   → resugar references + strip ids + redact secrets (document)
//!   → YAML emit (yaml_emit) → stdout / -o file
//!   → secret-placeholder list + warnings → stderr
//! ```
//!
//! Secrets are replaced with `${VAR}` placeholders by default; the real
//! values are never written unless `--reveal-secrets` is passed.

mod document;
mod secrets;
mod yaml_emit;

use std::path::PathBuf;
use std::time::Duration;

use aisix_etcd::{build_snapshot, ConfigProvider, ConnectPolicy, EtcdConfigProvider};

use document::build_export_document;
use yaml_emit::emit_yaml;

/// Arguments for the `export` subcommand, parsed by `clap` in `main`.
pub struct ExportArgs {
    pub endpoints: Vec<String>,
    pub prefix: String,
    pub reveal_secrets: bool,
    pub output: Option<PathBuf>,
}

/// A CLI-appropriate connect policy: fail after a few quick attempts
/// rather than the gateway's 25s boot budget.
const CLI_CONNECT_POLICY: ConnectPolicy = ConnectPolicy {
    interval: Duration::from_secs(1),
    attempts: 3,
};

/// Run the export end to end. Reads etcd, writes the resources file to
/// `output` (or stdout), and reports the secret-placeholder map and any
/// warnings on stderr.
pub async fn run(args: ExportArgs) -> anyhow::Result<()> {
    if args.endpoints.iter().all(|e| e.trim().is_empty()) {
        anyhow::bail!("--etcd requires at least one endpoint");
    }

    let provider = EtcdConfigProvider::connect_with_policy(
        &args.endpoints,
        &args.prefix,
        None,
        CLI_CONNECT_POLICY,
    )
    .await
    .map_err(|e| anyhow::anyhow!("etcd connect failed: {e}"))?;

    let (entries, _revision) = provider
        .load_all()
        .await
        .map_err(|e| anyhow::anyhow!("etcd range read under {:?} failed: {e}", args.prefix))?;

    // Decode through the identical loader path the gateway uses, so the
    // exported set is exactly what the running gateway would serve.
    let (snapshot, stats) = build_snapshot(&args.prefix, &entries);

    let document = build_export_document(&snapshot, args.reveal_secrets);
    let yaml = emit_yaml(&document).map_err(|e| anyhow::anyhow!(e))?;

    let resource_count = document
        .collections
        .iter()
        .map(|(_, entries)| entries.len())
        .sum::<usize>();

    match &args.output {
        Some(path) => {
            std::fs::write(path, &yaml)
                .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
            eprintln!(
                "Exported {resource_count} resource(s) to {}",
                path.display()
            );
        }
        None => {
            print!("{yaml}");
        }
    }

    report_rejections(&stats);
    report_warnings(&document.warnings);
    report_secrets(&document, args.reveal_secrets);

    Ok(())
}

/// Surface entries the loader dropped during decode (bad key / non-JSON /
/// schema / unknown kind) so a silently-skipped resource is visible.
fn report_rejections(stats: &aisix_etcd::BuildStats) {
    if stats.rejections.is_empty() {
        return;
    }
    eprintln!(
        "warning: {} etcd entr(ies) were rejected during decode and omitted from the export:",
        stats.rejections.len()
    );
    for rejection in &stats.rejections {
        eprintln!(
            "  - {} ({}): {}",
            rejection.key,
            rejection.kind.as_str(),
            rejection.error
        );
    }
}

fn report_warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
}

/// Print the operator's "set these before loading" list on stderr — never
/// into the file. Deduplicated and sorted for a stable report.
fn report_secrets(document: &document::ExportDocument, reveal_secrets: bool) {
    if reveal_secrets {
        if document_has_any_entry(document) {
            eprintln!(
                "warning: --reveal-secrets emitted live credentials inline; treat the output as a \
                 secret and do not commit it."
            );
        }
        return;
    }
    if document.secret_placeholders.is_empty() {
        return;
    }

    let mut lines: Vec<String> = document
        .secret_placeholders
        .iter()
        .map(|p| format!("  {} — {} {:?} {}", p.env_var, p.kind, p.identity, p.field))
        .collect();
    lines.sort();
    lines.dedup();

    eprintln!(
        "\n{} secret value(s) were replaced with ${{VAR}} placeholders. Set each variable to the \
         real credential in the data plane's environment before loading this file:",
        lines.len()
    );
    for line in lines {
        eprintln!("{line}");
    }
}

fn document_has_any_entry(document: &document::ExportDocument) -> bool {
    document.collections.iter().any(|(_, e)| !e.is_empty())
}
