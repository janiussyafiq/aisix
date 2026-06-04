# AISIX AI Gateway

AISIX AI Gateway is a Rust-native AI gateway for routing application traffic to
AI model providers. It exposes OpenAI-compatible and Anthropic-style proxy APIs,
keeps upstream provider credentials on the gateway side, and applies gateway
policy before requests reach providers.

Use AISIX AI Gateway when applications need a stable model alias, caller-facing
API keys, routing, failover, rate limits, guardrails, caching, and telemetry
across provider-backed models.

## Documentation

The product documentation lives under [`docs/`](docs/index.md). Start with:

- [Quickstart](docs/quickstart/quickstart.md)
- [What Is AISIX AI Gateway?](docs/overview/what-is-aisix-ai-gateway.md)
- [Configuration Overview](docs/configuration/overview.md)
- [Client APIs Overview](docs/integration/overview.md)

## Deployment Modes

AISIX AI Gateway runs in two modes from the same binary.

| Mode | Description |
| --- | --- |
| Self-hosted gateway | You run the gateway, admin API, configuration store, provider credentials, network exposure, and upgrades. |
| AISIX Cloud managed data plane | AISIX Cloud manages the control-plane workflow while the data plane serves traffic in your network. |

For a deeper comparison, see
[Deployment Modes](docs/overview/deployment-modes.md) and
[Cloud vs. Self-Hosted](docs/cloud/cloud-vs-self-hosted.md).

## Core Capabilities

AISIX AI Gateway supports:

- OpenAI-compatible chat, model discovery, responses, embeddings, images,
  audio, and rerank routes
- Anthropic-style Messages API requests
- Provider passthrough for routes that AISIX does not model directly
- Direct model aliases and routing models for failover, round-robin, and
  weighted target selection
- Provider keys for upstream credentials and provider-specific base URLs
- Caller API keys, rate limits, guardrails, caching, telemetry, and managed
  budget checks

See [Feature Availability](docs/overview/feature-matrix.md) for current feature
status and deployment-mode coverage.

## Development

Prerequisites:

- Rust toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
- Docker, when running local etcd or containerized quickstarts

Run the workspace checks:

```bash
cargo check --workspace
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

Run the gateway from source:

```bash
cargo run -p aisix-server -- --config config.example.yaml
```

## License

MIT. See [LICENSE](LICENSE).
