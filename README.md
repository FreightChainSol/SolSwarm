# SolSwarm: Multi-Agent Source Security Review Suite

SolSwarm is an automated, multi-agent security review and audit swarm designed for Solana programs, Rust crates, TypeScript/JavaScript services, smart contracts, and Web3 applications. It coordinates frontier AI models—Claude, Codex, Grok, and AGY—in parallel, inspecting source code, configuration, dependency lockfiles, and existing test suites inside disposable, airgapped Docker sandboxes using restricted Model Context Protocol (MCP) bridges.

`solswarm run` (or `audit run`) enforces the `source_security_review_v1` workflow. Reviewers inspect captured source, consult static leads, run fixed existing test suites inside an offline container, submit structured evidence-backed reports, and peer cross-check each other's claims. The bridge rejects arbitrary shell commands, runtime exploit generation, and live network access.

## How It Works

SolSwarm seals a source snapshot, collects static scanner leads, and verifies network disconnection before handing the sandbox to reviewers. Selected providers inspect the same captured source through a restricted MCP bridge.

```mermaid
flowchart TB
    Source[Sealed source snapshot] --> Prepare[Static scans and sandbox preparation]
    Prepare --> Sandbox[Verified offline Docker sandbox]
    Orchestrator[Host orchestrator] --> Reviewers[Persistent ACP sessions: Claude, Codex, Grok, AGY]
    Reviewers --> Bridge[Restricted MCP bridge]
    Bridge -->|Read source and run fixed existing tests| Sandbox
    Bridge -->|Submit findings| Commit[Canonical report commits]
    Commit --> Peers[Peer cross-checks]
    Peers --> Reports[Validation and adjudication: JSON, Markdown, HTML]
```

Providers work in parallel, with one active assignment per provider and remaining surfaces queued. Shared test runs execute one at a time inside the sandbox. After surface reviews settle, peers return claim-level verdicts: `upheld`, `partial`, or `refuted`.

Reports bring together source citations, impact, suggested fixes, peer verdicts, and coverage gaps. Missing or failed work stays **INCOMPLETE**; model agreement and passing checks do not certify security.

See the [architecture notes](docs/how-it-works.md) and [visual operator guide](docs/index.html) for the full workflow.

## Quick Start

```sh
# 1. Install pinned ACP adapters (into runtime/)
./bin/solswarm setup-agents

# 2. Check agent runtime and Docker prerequisites
./bin/solswarm check-agents

# 3. Run a security review against a local repo
./bin/solswarm run --repo /path/to/authorized-repo

# Or review a GitHub repository directly
./bin/solswarm run --github owner/repo --ref v1.2.0

# Or target specific models and surfaces (S1..S6)
./bin/solswarm run --repo /path/to/repo --agents claude,codex --surface s4

# Print review plan without launching workers
./bin/solswarm run --repo /path/to/repo --plan
```

You can also use `./bin/audit` or standard npm scripts:
```sh
npm run setup         # Installs adapter dependencies
npm run check-agents  # Runs preflight agent check
npm test              # Executes test suite
```

`setup-agents` installs lockfile-pinned adapters under `runtime/` with lifecycle scripts disabled. Existing official CLIs and subscription logins stay in place without credential exposure. Defaults: Claude `opus`, Codex `gpt-6.1-sol`, Grok `grok-4.7`, AGY `gemini-4-argon-high`.

`check-agents` checks Docker, executable versions, and adapter availability. `check-agents --live` makes real provider requests against an inert fixture to verify MCP reads, native session loading, and report submission.

## Workflow and Boundaries

1. **Capture & Seal:** Source is captured into sealed copies with a SHA-256 manifest and explicit omissions (secrets, `.env*`, build artifacts, credentials). An immutable catalog of existing tests is created before any model is prompted.
2. **Container Preparation:** Starts a disposable `audit-sandbox:local` container as unprivileged `uid 10001` with dropped capabilities. Networked preflight executes trusted static scanners (Gitleaks, Semgrep, OSV Scanner, cargo-audit, npm audit) without executing target code or builds.
3. **Airgap Verification:** Disconnects the Docker container from the network before reviewer access. All subsequent test requests check the actual Docker network state.
4. **Parallel Surface Review:** Surfaces are reviewed in parallel across providers (one active assignment per provider with remaining surfaces queued). Reviewers cite `file:line` evidence, impact, preconditions, source analysis, validation limits, and defensive remediation.
5. **Peer Cross-Check & Adjudication:** Reviewers cross-check peer claims in parallel, submitting claim-level verdicts (`upheld`, `partial`, `refuted`). A canonical report commit is validated and derived into structured JSON, Markdown, and standalone HTML reports.

## Reviewer Tools

| Tool | Behavior |
|---|---|
| `get_audit_context` | Review scope, static scanner leads, and peer assignments. |
| `get_review_plan` | Source-focused inspection plan for detected protocols and risk domains. |
| `list_files`, `read_file`, `search_code` | Bounded inspection under approved container roots. |
| `list_existing_tests` | Advertise test IDs from the frozen source test catalog. |
| `run_existing_tests` | Run one fixed existing suite after verifying its manifest and offline containment. Accepts only `test_id`. |
| `submit_audit_report` | Commit validated source findings and reviewed control assertions. |
| `submit_crosscheck_report` | Commit a verdict with citations and reasoning for assigned peer claims. |

Arbitrary execution, PoC generation, and external RPC tools are strictly denied. Existing tests run inside the offline container using fixed recognized runners (`npm --offline --ignore-scripts run test`, `cargo test --locked --offline`, `bash --noprofile --norc ./test.sh`).

For Solana programs, SBF `cdylib` programs are compiled offline into `/work/target/deploy/*.so` using provisioned Solana platform-tools before Cargo/shell tests execute, or operator-supplied artifacts can be passed via `--test-artifacts`.

## Six Review Surfaces

- **S1 / Identity:** Sessions, wallet signatures, ownership, roles, access control, CSRF, and origins.
- **S2 / Input:** Schemas, parsing, deserialization, size limits, parameter binding, command/path injection.
- **S3 / Logic:** Financial invariants, custody, state transitions, idempotency, transactions, locks, and deadlines.
- **S4 / Config:** Secrets, response DTO leakage, CI/CD, container isolation, TLS, and sensitive logging.
- **S5 / Dependencies:** Manifests, lockfiles, known vulnerabilities, supply chain, and build reproducibility.
- **S6 / Client:** DOM sinks, postMessage origins, CSP, wallet signing intent, and client/server trust boundaries.

## Sessions and Recovery

Codex uses maintained `codex-acp` 2.2.2 over its app-server; Claude uses `claude-agent-acp` 0.92.0; Grok uses native ACP stdio with isolated MCP configuration; AGY uses an ACP compatibility adapter with default-deny tool hooks.

Reviews have no reasoning deadline; a 30-second heartbeat tracks worker liveness. Interrupted or failed runs can be resumed cleanly:
```sh
./bin/solswarm run --repo /path/to/repo --agents claude,codex --surface s4 \
  --resume-from /path/to/previous-review --out /path/to/new-review
```
Successful committed reports are reused without re-invoking providers. `--restart-failed` restarts failed local sessions from scratch.

## Reports and Output

Each run produces comprehensive artifacts in `--out <dir>` (or `reports/<timestamp>-<target>/`):
- `source-manifest.json`: Captured files, exclusions, and SHA-256 digest.
- `meta.json`, `workers.json`: Workflow, requested models, jobs, turn outcomes, and exits.
- `submissions/`: Authoritative identity-bound MCP commits.
- `auditors/`: Derived structured findings, markdown summaries, and peer verdicts.
- `report-health.json`: Detailed review status, verification gates, and security summary.
- `report.html`: Standalone interactive HTML report dashboard with severity/surface filters and expandable evidence disclosures.
- `findings-by-model.html`: Direct comparison of findings across models before deduplication.

To inspect, verify, or regenerate HTML reports without invoking models:
```sh
./bin/solswarm verify /path/to/report
./bin/solswarm report /path/to/report
./bin/solswarm html /path/to/report
```

## Verification & Testing

```sh
# Run the complete test suite
npm test

# Run Docker integration fixtures
npm run test:docker

# Shell syntax validation
npm run check
```

## Documentation

- [Architecture & Workflow](docs/how-it-works.md)
- [Operator Guide & Visual Dashboard](docs/index.html)
- [Live-Model Integration](docs/live-model.md)
- [ACP Runtime Configuration](runtime/README.md)

## License

MIT License. See [LICENSE](LICENSE) for details.
