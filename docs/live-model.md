# Live-model integration: ACP audits and selected-file reviews

## What works today

Audit lifecycle diagnostics are recorded in `harness/sandbox-run/lifecycle.json`; transient Docker status failures do not release the review hold, while confirmed container loss stops active and queued review work. AGY permits exact staged-skill and own MCP schema reads needed by its native discovery flow, while other host reads stay denied. AGY retains private `native-session.json:lastTurn` completion enums/exit status and accepts complete final JSON without a trailing newline. An inert AGY MCP read, exact-session resume and report submission passed on 2026-10-17; it does not repair earlier failed turns or establish audit coverage. `--resume-from ... --restart-failed` starts new full reviews for failed local sessions and retains the originals; it rejects recorded provider refusals, quota/login failures and unresolved provider errors. Existing tests requiring Solana SBF program bytes automatically compile `cdylib` crates offline into `/work/target/deploy/*.so` via provisioned Solana `platform-tools`, or may use `audit run --test-artifacts <cargo-target-dir>` to stage frozen, hash-checked `deploy/*.so` with build provenance explicitly unverified.

`review-local` connects an isolated Docker source reader to a host-terminal result. It does not itself authenticate or start a model. You can either submit a result manually, or use the explicit `connect-terminal` consumer to invoke a supported inference-only local CLI and submit its validated result automatically.

Whole-repository `run` enforces `source_security_review_v1`: source/configuration/dependency inspection, evidence and fixes, and catalogued existing tests only after verified Docker network disconnection. It excludes arbitrary commands, PoCs and deployed probes; legacy adversarial sessions cannot resume into it. It uses persistent ACP sessions and the Docker MCP bridge for Claude, Codex, Grok and AGY. See [the source-review workflow](../README.md) for installation, qualification and `--resume-from`. All four passed real inert transport/resume/submission checks on 2026-10-16, before the restricted source-review workflow was introduced. This does not resolve the original Codex provider-policy refusal or establish whole-repository security coverage.

The rest of this guide describes the **separate selected-file relay**, with its narrower tool-free profiles and independent admission receipts. It is not an automatic fallback for ACP audit failures. Historical native-broker verification below describes the tested source/recipe at that time; changed recipes require fresh admission. Missing pinned private source/protoc prerequisites keep those optional rebuilds unavailable.

The selected-file review scope is static correctness, maintainability and defensive hardening of explicitly selected local text. No source execution, scans, host probing, exploit steps or PoC generation are part of this workflow.

## Prerequisites

- Run commands from this repository root with Node available.
- Docker must be running with the immutable Node image referenced by `scripts/worker-isolation.mjs` already provisioned. The supervisor does not pull or install it automatically.
- Prepare a local source directory you are authorized to disclose. Select one to three relative UTF-8 files, at most 64 KiB combined. Named credentials, `.env*`, symlinks and other excluded entries cannot be selected. Filename exclusions do not detect every secret embedded in ordinary source: inspect the selected material before sending it to a provider.
- Open your authenticated model session before starting the job. Use a text-only conversation or an independently verified tools-disabled interface. Do not feed untrusted source into an unrestricted credential-bearing coding agent.
- Selected-file handoffs and inference have no default reasoning deadline. Explicit caller-supplied test deadlines remain supported; cancellation still invalidates a handoff. Selected-file relay claim bindings cannot be replayed as an ACP session resume.

## Grok with the authenticated inference client inside Docker

Use `grok-docker` when the AI client itself must be contained. The older `grok-native` profile intentionally executes the native broker on the host; its successful smoke tests establish that older route only.

```sh
./bin/audit grok-docker setup
./bin/audit grok-docker login
./bin/audit check-model-cli --provider grok-docker
./bin/audit review-with-cli \
  --repo /path/to/local-repo --file src/example.mjs \
  --provider grok-docker --model grok-4.7 --out /tmp/grok-review
```

`setup` verifies the prepared public source, builds/tests the Linux native broker and installs the pinned official Grok CLI inside the image for login only. The broker links native auth, sampling, HTTP and foundation crates without the full agent shell/tool/UI crate. Its routing module mechanically projects the pinned native header function, changing only module references; preparation compares the complete projection against upstream before compilation. The Docker build uses one compilation job, disabled debug symbols and reusable source/dependency/target caches. It records an immutable local image ID and current package/recipe identities under private ignored `native/.cache/grok-docker/`. It uses the existing pinned source/private-protoc preparation prerequisites; it does not install global host tools. Changed source, shared scripts or Docker recipe invalidate the receipt and require setup again.

`login` starts the official CLI's device authorization inside a separate container. The owner approves the displayed URL/code in their browser. Only the dedicated Docker volume `freightchain-grok-isolated-auth-v1` receives the resulting credentials. The host's `.grok`, home, session stores and environment credentials are never imported. This follows the [official device-code flow for containers](https://docs.x.ai/build/enterprise#device-code). Login cannot be inferred from a ready host session.

During review, the client is uid 10001, drops all capabilities, has a read-only root and auth volume, bounded tmpfs/memory/CPU/PIDs, and no host-source or socket mounts. It accepts only the existing strict instruction/files JSONL frame, constructs no tools and permits one inference. Its internal network connects only to an isolated HTTPS CONNECT proxy; that proxy permits the two official core domains `cli-chat-proxy.grok.com` and `auth.x.ai`, port 443, resolving public IPv4 itself. No alternate model, provider, billing route or unrestricted host client is used after failure. The network-disabled source worker, validated reports, unverified model/tool provenance and three-file/64 KiB limit are preserved.

Owned client/proxy containers and per-session internal/external networks are removed after success, refusal or cancellation. Parent-owned private records under `native/.cache/grok-docker/sessions/` retain their exact identities and cleanup status without source, prompts or credentials; journal failure cannot prevent teardown attempts. The login volume persists for subsequent checks; the inference path cannot refresh or mutate it. Near-expiry credentials require a separate official Docker login. A recipe-valid image plus a passing dummy Docker test is preparation evidence; actual inference still requires the Docker login and a real review.

**Verified on 2026-10-16:** the Linux image passed 26 native tests, the bridge passed 143 Node tests and 21 Docker tests, and an actual Docker auth preflight correctly refused the empty login volume. A separate official device login was attempted but expired without issuing credentials. Authenticated Docker inference therefore remains pending owner login; no host credential or API-billing fallback was used. Login timeout/cancellation now remains incomplete even if the Docker attachment exits zero.

`node --test scripts/grok-docker.docker.mjs` uses a dummy Linux broker and a disposable dummy auth volume. It verifies client mounts, private networking, runtime identity, read-only credentials and cleanup, with no account/provider requests. `model-cli-grok-docker.test.mjs` checks receipt invalidation, strict destinations and metadata, provisioning/refusal, and use of the existing strict native protocol.

## 1. Start the isolated source job

### Single-command static review

```sh
./bin/audit check-model-cli --all
./bin/audit review-with-cli \
  --repo /path/to/local-repo \
  --file src/example.mjs \
  --provider claude \
  --model haiku \
  --out /tmp/selected-source-review
```

This composes the source job and fixed consumer without a second terminal. Both Claude and `codex-native` completed inert-source live smoke tests; native Codex requires the separate admission procedure below. Select one to three approved local UTF-8 files, at most 64 KiB combined, and a new/empty output directory. There is no GitHub acquisition, whole-repository default, custom prompt or executable override. Provider/option validation precedes source access; one session is preflighted before the job starts and reused for its single request. Connector failure aborts the parent; parent failure cancels the connector. Both sides finish cleanup before the command returns. A submission accepted during an acknowledgement/cancellation race may still be recorded by the parent; incomplete connector status does not roll it back.

`connector-state.json` records collected/incomplete connector state and requested versus CLI-reported model metadata. Existing transport reports keep unverified provenance and `executionEvidence: not_collected`. Preflight failure creates no source job/output directory; failures after the worker is ready retain parent journals and connector status. No retry changes provider, model, credentials or permissions.

**Live verification status:** the initial Claude 2.1.300/Haiku inert-source smoke test on 2026-10-15 rejected an unhandled `system/thinking_tokens` progress event. After strict numeric metadata validation was added, a new one-line inert-source review completed with exit 0, a validated report and verified owned-resource cleanup. The CLI reported `claude-haiku-5-5` for requested `haiku`; this is client-reported metadata, not served-model attestation. This verifies that one selected-file workflow, not other providers, all models or a whole-repository audit. Unknown/tool/control events remain rejected.

The only added event allowance is `system/thinking_tokens` after accepted initialization and before the final result. Its six fields are fixed: `type`, `subtype`, `estimated_tokens`, `estimated_tokens_delta`, `session_id` and `uuid`. Counters must be finite numbers between zero and one billion; IDs are bounded to 128 alphanumeric/hyphen characters, and the session must match when initialization supplies one. Extra fields, malformed metadata and invalid ordering are rejected. Numeric progress is discarded, never retained as reasoning text or review evidence.

Rejected execution/telemetry events carry only allowlisted type/subtype labels and a 1-based event index in CLI errors and `connector-state.json`. Unknown labels are replaced with `unknown`; raw payloads, IDs, account details and reasoning are never included in these diagnostics.

### Provider inventory

`check-model-cli --all` reports the fixed set Claude, Codex, Grok, Agy, Gemini and Ollama. Exit 0 means inventory completed, not that all providers work. A single-provider diagnostic returns exit 2 when blocked/unavailable. Installed version metadata is not provider attestation.

- Claude: the live-tested automatic profile; version/help/subscription checks determine preflight readiness, not entitlement or successful inference.
- `codex-native`: a separate source-built profile, not an installed CLI inventory entry. Use `check-model-cli --provider codex-native` explicitly; it refuses absent/stale admission before auth or source access. The `--all` inventory still describes the unmodified installed `codex` CLI as blocked.
- Codex 0.162.1: the installed stable and experimental app-server schemas expose no public exact-tools-empty selector or capability declaration. `dynamicTools: []` and `environments: []` do not remove all native tools. The [version-pinned internal extension tool policy](https://github.com/openai/codex/blob/rust-v0.162.1/codex-rs/ext/extension-api/src/tool_policy.rs) supports an empty allowlist, but that is not an exposed CLI/config/JSON-RPC option. Do not invent a config key or treat read-only sandboxing as equivalent.
- Grok 1.0.52: `--tools` filters built-in tools, but the [upstream headless guide](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/14-headless-mode.md) documents retained MCP meta-tools. That guide is not pinned to the installed build; a matching installed-CLI tools-empty/config-isolation contract remains unverified. The [MCP documentation](https://docs.x.ai/build/features/mcp-servers) also describes config discovery. The separate `grok-native` profile below completed an inert live review after fixing empty-tool serialization. Inventory still probes only the installed CLI version.
- Gemini and Ollama: absent in the checked environment and no automatic profile implemented. Recognized names do not imply support. Unsupported installed providers receive only bounded `--version` discovery during normal inventory, not auth requests or source text; deeper compatibility research uses public help/schema/documentation only.
- Agy: installed 1.3.5 exposes `--print` and `--output-format stream-json`; its help is emitted on stderr. The block is an unverified tools-empty/config-isolation profile, not absence of headless mode. The [official headless documentation](https://antigravity.google/docs/cli/headless/) describes a tool-bearing `init.tools` inventory; permission/sandbox modes alone do not remove that tool surface. No Agy inference or authentication was tested.
- Missing executables: `unavailable`, distinct from installed-but-blocked. Unknown provider names and automatic review requests for unsupported providers fail before source capture or a claim.

Discovery uses fixed executable names, a filtered environment, five-second version deadlines and an 8 KiB output budget. Raw version stderr/account information is not printed. No config/credential stores are read by the inventory code, no login is performed and no API-billing fallback exists. Manual structured-result handoff remains provider-independent; the harness does not control or authenticate an externally operated CLI.

### Automatic local CLI route

First check the supported CLI profile and normal subscription login, without claiming a job or running inference:

```sh
./bin/audit check-model-cli --provider claude
```

The connector currently accepts inspected Claude Code versions 2.1.299 and 2.1.300 with all required flags. Unknown versions or missing controls fail closed. Authentication must be the official CLI's existing `claude.ai` subscription login. Missing login returns `subscription_login_required`; API-key, third-party and environment-token overrides are not accepted. If needed, authenticate separately through the official `claude auth login` flow in your terminal. The connector never performs login/logout, extracts tokens, opens auth files or changes billing. A successful check is preflight readiness, not a successful model request.

Start the source job in terminal A using the command below. In terminal B, use the printed socket path and choose your requested model:

```sh
./bin/audit connect-terminal \
  --provider claude \
  --model opus \
  --socket /tmp/fc-tr-XXXXXX/s
```

This replaces manual claim/copy/submit: the connector preflights before claiming, sends only the approved instruction/source to the official CLI over stdin, validates the returned summary/notes JSON, and submits the original binding. It does not send the socket path, claim ID or job identity to the model. Manual handoff in steps 2–4 remains available.

The host adapter uses a fresh private neutral directory; restricted mode; an empty built-in tool list; strict empty MCP configuration; disabled skills; explicit hook/automatic-memory disable settings and `forceLoginMethod: claudeai`; ignored user/project/local settings; no session persistence; and a minimal environment. The login-method setting is passed per invocation, not written to global configuration. It never invokes a shell or accepts executable/argv/URL/env plugins. Provider/API-key overrides, proxies, `NODE_OPTIONS`, shell startup variables and token overrides are not forwarded. These controls do not attest suppression of every user/ancestor instruction file or plugin-context input. The installed official CLI, its normal login store and trusted user/administrator context remain trusted computing base.

CLI inspection is bounded to 5 seconds for version/help and 10 seconds for auth; inference has no default deadline and combined stdout/stderr is bounded to 2 MiB. The connector polls claimed-job state during inference and cancels its owned CLI process group if the relay expires/disappears. Connector cancellation also cancels relay I/O. A submission already accepted during a cancellation race cannot be rolled back; inspect the parent record rather than assuming cancellation means no result was stored. Prompts, account details, stderr and reasoning are not logged or printed. Machine output must report empty tool/MCP inventories; tool-use, control/execution events, ambiguous success flags, formatter output, prose-wrapped JSON or invalid citations are rejected. No automatic retry changes provider/model or weakens restrictions.

Connector status distinguishes `requestedModel` from `cliReportedModel`; the latter is client-reported metadata, not served-provider attestation. Login readiness does not independently establish subscription entitlement, quota or billing; inference can still be refused by the official client/provider. Existing reports retain unverified terminal provenance. A fake-CLI integration test is not live inference. If the supported subscription login is absent, real-model testing remains blocked even when all simulated tests pass.

### Source job (terminal A)

In terminal A:

```sh
./bin/audit review-local \
  --repo /path/to/local-repo \
  --file src/example.mjs \
  --out /tmp/live-source-review
```

Repeat `--file` for additional approved files. Choose a new or empty output directory. The parent seals source/runtime copies, starts a non-root network-disabled worker with a private outbox, and prints `socketPath` after the worker emits the authorized request.

The socket is a local owner-only Unix socket. Its path is routing information, not a provider credential. Never mount it, a home directory, CLI session store, SSH agent or Docker socket into the worker.

## 2. Claim and save the handoff (manual route)

In terminal B, replace the path below with the printed `socketPath`:

```sh
umask 077
node scripts/terminal-review-client.mjs claim \
  --socket /tmp/fc-tr-XXXXXX/s > /tmp/live-review-claim.json
```

The JSON contains:

- `request.instruction`: the fixed read-only review policy.
- `request.files`: approved paths, original source text, hashes and line counts.
- `submissionTemplate`: the correlated result envelope you will send back.

Only one claim is accepted per job. Retain the original claim locally; do not claim again to recover it. Check state without claiming:

```sh
node scripts/terminal-review-client.mjs status \
  --socket /tmp/fc-tr-XXXXXX/s
```

Source and result display escape terminal control/bidirectional characters. Treat all source comments, repository instructions and returned prose as untrusted data, not instructions for your shell.

## 3. Obtain a real model review outside the harness

In your authenticated, text-only/tools-disabled model session, supply **only** `request.instruction` and `request.files`. Do not supply login data, environment values, the socket path or the claim envelope. No account or credential information is needed to review the source.

Ask for exactly this result shape, using the actual approved paths and original 1-based line numbers:

```json
{
  "summary": "Static review of the supplied source only; no execution performed.",
  "notes": [
    {
      "path": "src/example.mjs",
      "line": 1,
      "kind": "maintainability",
      "message": "An observation grounded in the supplied source.",
      "recommendation": "A defensive or readability improvement."
    }
  ]
}
```

`notes` may be empty. Valid kinds are `correctness`, `maintainability` and `hardening`. Limits are 4,000 characters for summary, 20 notes, and 2,000 characters each for a note's message/recommendation. The relay rejects additional fields, unapproved paths and lines outside the captured file.

The harness cannot verify which external model answered, whether its tools were disabled, or whether a person supplied the response. A model's own claim about these properties is not attestation.

## 4. Fill and submit the original template

Copy `submissionTemplate` from the saved claim into a private local `response.json`. Replace only its `result` with the model's JSON object. Preserve `version`, `method`, `requestId`, `jobId`, `sourceDigest` and `claimId` exactly as returned.

Do not submit the whole claim, raw prose, Markdown fences, credentials, commands, URLs to fetch, or a previous job's result.

```sh
node scripts/terminal-review-client.mjs submit \
  --socket /tmp/fc-tr-XXXXXX/s < response.json
```

The client reads JSON from stdin; it does not execute the response or run a model command. Stdin is bounded to 512 KiB and 30 seconds. Submissions are single-use. A rejected result can be corrected and submitted while the original claim/job is still active; a duplicate accepted submission or stale binding is rejected.

Terminal A finishes only after worker output validation, stopped-job collection, required cleanup and parent output publication succeed.

## 5. Inspect evidence without overclaiming it

The output directory contains:

- `report.json` / `report.md`: submitted review data with explicit unverified provenance.
- `result-state.json`: successful transport collection state and output hashes.
- `source-manifest.json`: selected capture inventory, omissions and source digest.
- `job.json`: parent-owned job identity and terminal state.
- `journal/ledger.json`: parent-observed worker/runtime boundaries, limits, digests and Docker cleanup.
- `relay-events.json` / `relay-state.json`: exchange events and final socket/source cleanup state.

Successful reports keep:

```json
{
  "origin": "terminal_supplied_unverified",
  "modelIdentity": "unverified",
  "toolsDisabled": "unverified",
  "executionEvidence": "not_collected"
}
```

This is an actual model-assisted review only if you obtained and submitted an actual model result. The transport record alone proves neither that inference occurred nor that the source is safe. An incomplete job, missing report or nonzero exit is not a zero-finding pass.

Keep source-bearing claim/result/journal files private and follow your provider's data-handling policy. Remove your own temporary handoff files when no longer needed; the harness cannot manage files you created outside its output directory.

## Failure and recovery

- **ACP review incomplete:** inspect the job failure reason, private session state and report health. Install adapters with `setup-agents`, check transport with explicit `check-agents --live`, or use `--resume-from` after a transport interruption. Provider refusals require resolving provider access; quotas require waiting for reset. Historical blocked records remain historical. `check-model-cli` inventories the separate selected-file workflow.
- **Docker/image unavailable:** provision the required runtime separately; do not fall back to a host reviewer.
- **No request/timeout:** inspect the parent journal. Start a fresh job/output directory rather than replaying a stale result.
- **Invalid citation/schema:** correct only the result data while the claim remains active.
- **Ctrl-C/SIGTERM:** the supervisor cancels/reaps owned work and records cleanup. A Docker daemon failure may leave cleanup unverified; inspect recorded resource identities before any operator cleanup.
- **No socket after completion:** normal—the relay removes its socket directory. Use saved output records, not `status`, to inspect the completed job.
- **External provider needs commands/credentials:** decline that request. The relay has no host exec, file-read, environment, credential or arbitrary HTTP/model-call RPC.

## Requirements before enabling additional live adapters

### Grok native broker (experimental)

`native/grok-review/` pins public Grok commit `2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8`, with SOURCE_REV `559751fdcec02d413e4c57c8832ab275e4f44980`. It cannot be mapped to installed `1.0.52 (0920c8169e27)` and must not impersonate that build. The CLI selector is explicitly `grok-native`; its compiled native client version/routing remain those of the public source, with a separate broker identity.

It constructs only the native low-level sampler, never an agent/session, workspace, ToolSet, hooks, plugins or MCP runtime. Internal local/hosted inventories are empty and internal tool choice is none. The pinned native conversion omits `tools`/`tool_choice` on the wire for that empty set; guards require their absence and no search parameters before sending. This is compatible zero-tool serialization, not a tool grant. One inference is permitted, without automatic retries or side-model calls. Raw SSE/output/deadlines are bounded; nonempty tool calls, invalid citations and truncated/non-text results are refused. Empty tool-call metadata arrays do not count as execution requests. Node shares lifecycle code only, never another provider's model/login.

The normal native auth startup/refresh path can repair/prune credential files, log token fragments and start auxiliary requests. This first profile deliberately supports **cached first-party OIDC only**. Its declared in-tree adaptation reads a bounded owned regular private store without following links, chmod, backup, pruning or logging; native issuer/client/expiry/team-policy checks precede readiness. The official resolver has a structural cached-only no-refresh branch, including after expiry/suspend. A missing send-time credential fails before an anonymous request. No `auth()` recovery, refresher, login UI, external provider command, enrichment or diagnostic uploader is started. Near-expiry/expired credentials fail; use the official CLI separately to maintain login, never supply a token to the harness.

Native auth policy is applied from bounded read-only file snapshots with no create-on-resolve, environment expansion or second policy read. Requirements take precedence over environment/user team pins. Unsupported raw mandatory/campaign/version/auth policies and ambiguous aliases block instead of being silently dropped. Forced MDM is detected before decoding and is unsupported/fail-closed, even if malformed. The initial profile does not support enterprise/custom endpoints. Fixed routing headers are obtained through a narrow official native facade, not hand-built subscription headers.

Private derived source/Cargo/HOME/target/logs live under ignored `native/.cache/`. `grok-review/build.mjs --prepare` requires the pinned source checkout already provisioned and refuses unexpected tracked/untracked/ignored inputs or unrecognized cached overlays. Registry/Git dependency versions/checksums stay locked; only the broker package entry is added. Existing Rust 1.99.0 compiled the source's 1.94.0 snapshot. The user approved the upstream-pinned protoc 29.3 macOS ARM archive, verified as SHA-256 `2b8a3403cd097f95f3ba656e14b76c732b6b26d7f183330b11e36ef2bc028765`, installed only in the private build cache. No DotSlash/global toolchain/package installation was performed.

```sh
node native/grok-review/build.mjs --test
node native/grok-review/admit.mjs --admit
./bin/audit check-model-cli --provider grok-native
```

`--test` always records admission false. `--admit` revokes an older receipt, requires native/build/Node/Docker gates, and only then issues a source/revision/package/recipe/overlay/binary-bound local receipt. It requires the real native dummy-home preflight and the fake-Grok Docker round trip, not merely zero executed tests. Changed shared scripts invalidate Codex admission too; Codex admission was rerun after this integration.

**Current verification (2026-10-15):** 25 native tests, 132 Node tests and 20 Docker tests passed, along with the broker build and refreshed Codex admission. Native gates cover unchanged store bytes/permissions/mtime, no new log/session/lock/home, bounded config reads, policy refusal, canonical zero-tool requests, rejected nonempty tool calls, no anonymous send/retry, error-body caps/deadline and classifier leak refusal. Node gates check enum parity, forged/extra diagnostic refusal and propagation through private coordinator cleanup.

After the initial HTTP 400 attempts, a bounded classified same-model request recorded only `{"category":"parameter_hint","parameter":"tool_choice"}`. Restoring the canonical empty-tool encoding then produced a real collected review with exit 0: requested `grok-4.7`, client-reported `grok-4.7-build`. Report hashes and exact owned Docker/socket/staged-source cleanup were verified. Successful private evidence is retained in `fc-grok-fixed-4jt66yia/review`; the classified failure is `fc-grok-classified-fk9w4k68/review`. Model identity/tools/prose remain unverified provenance, not independent attestation.

The report passed schema/citation validation, not factual review. In particular, its assertion that explicit `String(symbol)` throws is incorrect for a primitive Symbol. Keep original reports/hash evidence unchanged and treat recommendations as unverified model statements; this smoke test is not a whole-repository audit or source execution proof.

#### HTTP 400 evidence and request-shape analysis

**Resolution:** bounded error classification implicated `tool_choice`; the targeted restoration of upstream's empty-set encoding resolved the observed HTTP 400 in a live same-model review. The diagnostic was a message-derived hint, not a structured server `param`; the successful before/after result corroborates the encoding fix without claiming knowledge of the full server-side validation rule.

The diagnostic run's `connector-state.json` records requested model `grok-4.7` and `grok_provider_http_400`; its parent ledger records cancellation and removed resources. That code is generated from the HTTP response status before SSE decoding. Thus this is not a locally rejected citation/result or an SSE-parser error. The ledger's generic `isolation_runtime_failure` is a parent outcome after connector failure, not evidence that Docker networking caused the HTTP rejection; the credential-bearing native broker runs on the host. Local cached-auth readiness does not establish server-side token acceptance, entitlement or served-model identity.

**Initial diagnostic gap.** The old overlay returned a fixed message and `error_code: None` without reading the response body, so those original logs could not identify a rejected parameter. The original payload cannot be recovered retrospectively. The new classifier reads the error envelope in memory only, at most **16 KiB with a separate two-second deadline**, and discards the bytes. Only fixed categories and known parameter names are emitted; raw bodies/messages, headers, IDs and credential/source fragments are never persisted or reflected.

**Reconstructed pre-fix request, not a captured live HTTP transcript:** native proxy Chat Completions, requested model `grok-4.7`, two text messages, `max_tokens: 8192`, `tools: []`, `tool_choice: "none"`, `stream: true`, and `stream_options.include_usage: true`. Search/temperature/top-p/reasoning are unset. The successful request differs in empty-set encoding: `tools` and `tool_choice` are absent. Model, route, token limit, client/version, auth/billing and other headers were unchanged.

1. **Resolved encoding mismatch: empty tools plus explicit tool choice.** The old broker overwrote the converted request with `Some(Vec::new())` and `Some(ToolChoice::none())`, bypassing upstream's [canonical conversion, lines 245–271](https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-sampling-types/src/conversation/chat_completions.rs#L245-L271). Upstream omits both empty fields and explicitly notes client compatibility. The broker now follows that conversion, verifies empty local/hosted inventories and internal none choice, and refuses unexpected tools/choice/search fields after conversion. No dummy tool, search, execution loop, auth relaxation or provider/model/billing/version fallback was introduced.

2. **Tracking-header hypothesis was not needed for this fix.** The native [stream builder](https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-sampler/src/client.rs#L1058-L1109) turns unset conversation/request/session/agent identifiers into empty strings, and [`GrokRequestHeaders::apply`](https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-sampler/src/client.rs#L55-L90) attaches them, unlike the populated upstream [classifier caller](https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-shell/src/session/acp_session_impl/sampler_turn.rs#L895-L922). These headers were unchanged in the successful live request, so they were not a blocker for that run. No harness binding or account IDs were added to work around the failure.

3. **Other unverified contract differences must not be mistaken for conclusions.** The broker fixes Chat Completions and an 8,192-token output limit rather than resolving a subscription model descriptor. Upstream's classifier notes that some thinking modes reject explicit output limits. The source-built client honestly uses the pinned version crate's `1.0.45` fallback and the broker's own client identifier, not installed `1.0.52`. None of those facts proves a backend, limit, model, entitlement or version rejection. [Public Chat documentation](https://docs.x.ai/developers/rest-api-reference/inference/chat) still documents `max_tokens` as deprecated rather than forbidden and supports streaming usage options; [public legacy examples](https://docs.x.ai/developers/model-capabilities/legacy/chat-completions) use `grok-4.7`. Those API-key-route documents are wire-format references, not a subscription-proxy compatibility guarantee or permission to change billing.

**Updated regression evidence:** the loopback success fixture now requires canonical omission of tools/choice/search fields before returning synthetic HTTP 200. Separate tests still reject nonempty tool calls, accept only empty tool-call metadata, and refuse malformed/truncated results. Error tests cover structured parameter extraction, message hints versus confirmed parameters, unknown/forged labels, private-text sentinels, malformed/oversized bodies, read deadlines and coordinator propagation. These tests plus the live result resolve the observed failure; they do not emulate every server-side validation rule.

**Ongoing privacy boundary:** diagnostics retain only an allowlisted `{category, parameter}` pair through the native broker, Node adapter, CLI and private `connector-state.json`. Structured parameters are labelled `invalid_parameter`; text mentions are only `parameter_hint`, multiple mentions are ambiguous, and unrecognized fields are never reflected. Capture is bounded in memory, not raw error-body storage. Future changes still require admission and must not spoof version, change billing/reviewer, remove bounds or enable tools to obtain a pass.

### Native Codex broker

`native/codex-review/` is a separately compiled review-only embedding of Codex source commit `092d3acd6bec3e3a14bdc7e7a2810ab628ab759d`. It now has a bounded runtime/auth executable and a Node adapter selected explicitly with `--provider codex-native`. It is not the unmodified installed `codex` executable and never substitutes Claude. Native `AuthManager` loads the normal credential store with ChatGPT-only authentication and preserved managed login/workspace restrictions; no token extraction, credential copying, synthetic headers, custom endpoints or API-billing fallback is implemented.

Its strict request/result types reject arbitrary commands, URLs, model/provider/config/resume overrides and extra fields. The fixed source instruction matches the existing relay; source hashes, relative paths, line counts, three-file/64 KiB bounds and result citations are validated. The startup constructor applies an empty native tool ceiling and isolated session, omits environments/dynamic tools, disables source-facing startup features through constrained setters and rejects configured MCP/notification actions rather than silently discarding them.

Native mock tests exercise the actual runtime, single-use review, malformed-result refusal, managed auth/config restrictions and refusal of MCP/notification startup actions. Every captured startup-test model request has `tools: []`; an AGENTS sentinel is excluded and fabricated tool calls remain unsupported after attempted policy mutation. The pinned upstream router gate covers empty registered, advertised and Code Mode tool inventories. These are version-specific tests, not provider attestation or a complete proof of every upstream side effect.

The adapter starts in a private neutral directory with filtered environment and fixed arguments, accepts one strict JSONL preflight/result sequence, sends only the fixed instruction/source frame, and waits for clean process exit before accepting a result. It limits combined output to 2 MiB, preflight to 55 seconds, source staging to 120 seconds and review/cleanup to 70 seconds. Cancellation terminates the owned process group; remaining members are killed on leader close before runtime-tree cleanup. Early exit, extra frames, unsupported events, changed models and invalid citations fail closed. Requested/client-reported model metadata remains unverified; provider safety reroutes are preserved.

Admission is deliberately separate from preliminary policy tests:

```sh
node native/codex-review/build.mjs --test
node native/codex-review/admit.mjs --admit
./bin/audit check-model-cli --provider codex-native
```

`--admit` first revokes an older receipt, then requires native tests, the exact pinned router test, a broker build, all Node tests and all five real-Docker fixture suites. Zero-test selectors/skipped suites do not count as passes. Only success writes private `native/.cache/runtime-admission.json` with admission true, gate evidence and source/package/recipe/binary identities. The adapter rechecks current identities and hashes the binary before starting it; changed inputs require a fresh admission run. This is a local reproducibility gate under the trusted owner's control, not a signed attestation against a malicious host owner.

**Current status (2026-10-15):** all five admission gates passed: 14 native tests, the exact pinned router test, broker build, 118 Node tests and 17 Docker tests, with no skips or failures. A current local runtime admission receipt was issued. The public `review-with-cli --provider codex-native --model gpt-6.1-sol` then reviewed a generated three-line inert sample through the full Docker/adapter/native-subscription path and exited 0. Requested and client-reported model were both `gpt-6.1-sol`. The report validated with zero notes; the parent recorded collection and cleanup, report hashes matched, and independent inspection confirmed the exact owned containers/volume were absent. Socket and staged source were removed. Private evidence is retained in the `fc-codex-live-ux38ixu6/review` temporary directory.

This verifies one selected-file end-to-end smoke test, not a whole-repository audit, executed source properties or independently attested model/tool identity. The compiled pinned native client, its normal authentication store and the provider service remain trusted components; entitlement/quota and other model requests can still fail. Do not bypass the receipt using internal test-only executable injection. The optional MCP facade is explicitly deferred; the direct selected-file adapter does not require MCP.

The builder uses private ignored source/Cargo/HOME/target caches and records `admission: false`. It preserves the pinned upstream source and registry/Git package versions/checksums; only local workspace lock labels `0.0.0` are reconciled to the tagged manifests' `0.162.1`, with the new package entry added. Existing stable Rust 1.99.0 was used against the upstream 1.95.0 requirement without installing a toolchain. Codex's protobuf build uses a vendored compiler. The mock startup gate uses upstream's explicit 8 MiB large-stack runner. Native logs are bounded/private, builds use two jobs, and missing prerequisites are blockers, not an excuse to install globally or bypass admission.

The fixed Claude terminal consumer is implemented above, but actual inference still requires supported subscription authentication and a valid CLI response. Enabling additional providers or the generic audit launchers is separate engineering work, not a switch enabled by a successful manual/fake-CLI handoff:

1. Verify an official supported subscription/inference interface and its billing/entitlement rules for the installed version. Never extract session tokens or emulate private provider endpoints.
2. Keep provider authentication in a trusted inference-only broker outside source-facing workers. Do not give the broker general model-controlled tools or let repository content configure hooks, plugins, MCP servers or command execution.
3. Require a documented, testable zero-tool/config-isolation contract before sending untrusted content. Read-only sandboxing or rejecting tool calls after they happen is not an equivalent boundary.
4. Restrict the broker to parent-authorized source/model requests with fixed routing, bounded input/output/deadline/spend controls and cancellation. Do not introduce a general command, file or HTTP proxy.
5. Record served-model identity only when independently available from the supported response; otherwise keep it unknown. Do not infer it from a requested slug or filename.
6. Test with inert source, forbidden-operation cases, missing auth, malformed output, cancellation and cleanup. Retain the difference between transport success, source-review assertions and executed security-property evidence.

Until those conditions are implemented and reviewed for each additional provider, it stays blocked. `review-local` remains data-only; host consumers do not weaken its schema, Docker or provenance boundaries.

## Reproduce the automated checks

```sh
node --test scripts/*.test.mjs
node --test scripts/worker-isolation.docker.mjs
node --test scripts/terminal-relay.docker.mjs
node --test scripts/terminal-model-connector.docker.mjs
node --test scripts/static-cli-review.docker.mjs
```

The terminal-relay Docker test uses a simulated terminal responder; the automatic connector Docker test uses a **fake local CLI** with inert source. They validate transport, flag/environment controls and refusal/cleanup, not live inference or an actual subscription account.
