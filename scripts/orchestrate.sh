#!/usr/bin/env bash
set -euo pipefail

# orchestrate.sh
# Multi-agent security review of ONE target repo (already resolved to a directory by bin/audit).
# Isolated source-review policy. Subscription adapters stay blocked until a
# credential-safe, tools-disabled bridge is verified. No host CLI fallback.
# Defaults: claude opus, grok grok-4.7, agy gemini-4-argon-high, codex gpt-6.1-sol (reasoning effort high).
#
# Usage (normally via bin/audit):
#   orchestrate.sh --target <dir> --out <dir> [--name <slug>] [--surface s1..s6|all]
#                  [--agents claude,grok,agy,codex] [--mode local|remote] [--source <path|url>]
#                  [--ref <ref>] [--commit <sha>] [--plan]
#                  [--model <slug>] [--models claude=<slug>,grok=<slug>,agy=<slug>,codex=<slug>]
#                  [--model-claude <slug>] [--model-grok <slug>] [--model-agy <slug>] [--model-codex <slug>]
#                  [--rpc <https URL>]   legacy request, not executed while transport is blocked
# Precedence for a vendor's model: --model-<vendor>, then --models, then --model, then the default above.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGET_DIR="" OUTPUT_DIR="" TARGET_NAME="" SURFACE="all" AGENT_LIST="claude,grok,agy,codex" RPC="" RESUME_FROM="" TEST_ARTIFACTS="" RESTART_FAILED=0
TARGET_MODE="local" TARGET_SOURCE="" TARGET_REF="" TARGET_COMMIT=""
MODEL_ALL="" MODELS_CSV="" PLAN=0 BLOCKED="${AUDIT_BLOCKED_RUN:-0}"
MODEL_CLI_CLAUDE="" MODEL_CLI_GROK="" MODEL_CLI_AGY="" MODEL_CLI_CODEX=""
MODEL_MAP_CLAUDE="" MODEL_MAP_GROK="" MODEL_MAP_AGY="" MODEL_MAP_CODEX=""
# Catalog default for gpt-6.1-sol is "low". An audit wants the high effort.
CODEX_EFFORT="high"

valid_model() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo "orchestrate: bad model slug: $1" >&2; exit 1; }
}

apply_models_csv() { # vendor=slug,vendor=slug
  local pair agent slug
  IFS=',' read -r -a _pairs <<<"$1"
  for pair in "${_pairs[@]}"; do
    pair="${pair// /}"
    [ -n "$pair" ] || continue
    agent="${pair%%=*}"
    slug="${pair#*=}"
    [ "$pair" != "$agent" ] || { echo "orchestrate: --models entry needs vendor=slug ($pair)" >&2; exit 1; }
    valid_model "$slug"
    case "$agent" in
      claude) MODEL_MAP_CLAUDE="$slug" ;;
      grok) MODEL_MAP_GROK="$slug" ;;
      agy) MODEL_MAP_AGY="$slug" ;;
      codex) MODEL_MAP_CODEX="$slug" ;;
      *) echo "orchestrate: unknown vendor in --models: $agent (claude, grok, agy, codex)" >&2; exit 1 ;;
    esac
  done
}

resolve_model() { # <agent> -> slug. Per-vendor flag, then --models, then --model, then the built-in default.
  local agent="$1" pick=""
  case "$agent" in
    claude) pick="$MODEL_CLI_CLAUDE" ;;
    grok) pick="$MODEL_CLI_GROK" ;;
    agy) pick="$MODEL_CLI_AGY" ;;
    codex) pick="$MODEL_CLI_CODEX" ;;
  esac
  if [ -z "$pick" ]; then
    case "$agent" in
      claude) pick="$MODEL_MAP_CLAUDE" ;;
      grok) pick="$MODEL_MAP_GROK" ;;
      agy) pick="$MODEL_MAP_AGY" ;;
      codex) pick="$MODEL_MAP_CODEX" ;;
    esac
  fi
  if [ -z "$pick" ]; then pick="$MODEL_ALL"; fi
  if [ -z "$pick" ]; then
    case "$agent" in
      claude) pick="opus" ;;
      grok) pick="grok-4.7" ;;
      agy) pick="gemini-4-argon-high" ;;
      codex) pick="gpt-6.1-sol" ;; # latest Sol in `codex debug models`
    esac
  fi
  printf '%s' "$pick"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET_DIR="$2"; shift 2 ;;
    --out) OUTPUT_DIR="$2"; shift 2 ;;
    --name) TARGET_NAME="$2"; shift 2 ;;
    --surface) SURFACE="$2"; shift 2 ;;
    --agents) AGENT_LIST="$2"; shift 2 ;;
    --mode) TARGET_MODE="$2"; shift 2 ;;
    --source) TARGET_SOURCE="$2"; shift 2 ;;
    --ref) TARGET_REF="$2"; shift 2 ;;
    --commit) TARGET_COMMIT="$2"; shift 2 ;;
    --model) MODEL_ALL="${2:?--model needs a slug}"; shift 2 ;;
    --models) MODELS_CSV="${2:?--models needs vendor=slug pairs}"; shift 2 ;;
    --model-claude) MODEL_CLI_CLAUDE="${2:?--model-claude needs a slug}"; shift 2 ;;
    --model-grok) MODEL_CLI_GROK="${2:?--model-grok needs a slug}"; shift 2 ;;
    --model-agy) MODEL_CLI_AGY="${2:?--model-agy needs a slug}"; shift 2 ;;
    --model-codex) MODEL_CLI_CODEX="${2:?--model-codex needs a slug}"; shift 2 ;;
    --plan) PLAN=1; shift ;;
    --blocked) BLOCKED=1; shift ;;
    --resume-from) RESUME_FROM="${2:?--resume-from needs a report directory}"; shift 2 ;;
    --test-artifacts) TEST_ARTIFACTS="${2:?--test-artifacts needs a Cargo target directory}"; shift 2 ;;
    --restart-failed) RESTART_FAILED=1; shift ;;
    --rpc) RPC="${2:?--rpc needs an https URL}"; shift 2 ;;
    *) echo "orchestrate: unknown option $1" >&2; exit 1 ;;
  esac
done

[ -n "$TARGET_DIR" ] && [ -d "$TARGET_DIR" ] || { echo "orchestrate: --target <dir> is required" >&2; exit 1; }
[ -n "$OUTPUT_DIR" ] || [ "$PLAN" -eq 1 ] || { echo "orchestrate: --out <dir> is required" >&2; exit 1; }
TARGET_NAME="${TARGET_NAME:-$(basename "$TARGET_DIR")}"
TARGET_SOURCE="${TARGET_SOURCE:-$TARGET_DIR}"
[ -n "$MODEL_ALL" ] && valid_model "$MODEL_ALL"
[ -n "$MODEL_CLI_CLAUDE" ] && valid_model "$MODEL_CLI_CLAUDE"
[ -n "$MODEL_CLI_GROK" ] && valid_model "$MODEL_CLI_GROK"
[ -n "$MODEL_CLI_AGY" ] && valid_model "$MODEL_CLI_AGY"
[ -n "$MODEL_CLI_CODEX" ] && valid_model "$MODEL_CLI_CODEX"
[ -n "$MODELS_CSV" ] && apply_models_csv "$MODELS_CSV"

[ -z "$RPC" ] || { echo "source security review does not contact deployed RPCs" >&2; exit 2; }

# --- surfaces: generic attack areas, not tied to any one codebase --------------------
# id|slug|name|focus
SURFACES=(
  "s1|auth|Identity & Access Control|authentication, sessions/tokens/cookies, authorization and IDOR, privilege escalation, admin/internal planes, CSRF, password/key handling"
  "s2|input|Input Handling & Injection|injection (SQL/NoSQL/command/template), deserialization, SSRF, path traversal, file upload, XXE, request smuggling, validation gaps on every network or file input"
  "s3|logic|Business Logic & Value Flows|money / credit / entitlement flows, race conditions and double-spend, idempotency, state-machine bypass, rate and quota limits, smart-contract or ledger invariants where present"
  "s4|config|Secrets, Config & Infrastructure|hard-coded or leaked secrets, env/config handling, Dockerfiles, IaC, CI/CD workflows, reverse-proxy and TLS config, security headers, logging of sensitive data"
  "s5|deps|Dependencies & Supply Chain|manifests and lockfiles, known-vulnerable or typosquatted packages, install/postinstall scripts, unpinned CI actions, vendored code, build reproducibility"
  "s6|client|Client & Web Surface|DOM XSS sinks, postMessage/origin checks, CSP/SRI, CORS, token storage in the browser, wallet/signing flows, mobile or desktop client trust boundaries"
)

surface_row() { # <id|slug> -> prints the matching SURFACES row
  local want="$1" row id slug
  for row in "${SURFACES[@]}"; do
    IFS='|' read -r id slug _ <<<"$row"
    case "$want" in
      "$id"|"$slug") printf '%s' "$row"; return 0 ;;
    esac
  done
  return 1
}

SELECTED=()
if [ "$SURFACE" = "all" ]; then
  for row in "${SURFACES[@]}"; do SELECTED+=("$row"); done
else
  row="$(surface_row "$SURFACE")" || { echo "Unknown surface: $SURFACE. Valid: s1..s6 (auth, input, logic, config, deps, client) or all" >&2; exit 1; }
  SELECTED+=("$row")
fi

ENABLED=()
IFS=',' read -r -a REQUESTED <<<"$AGENT_LIST"
for a in "${REQUESTED[@]}"; do
  a="${a// /}"
  case "$a" in claude|grok|agy|codex) ;; "") continue ;; *) echo "Unknown agent: $a (valid: claude, grok, agy, codex)" >&2; exit 1 ;; esac
  for seen in ${ENABLED[@]+"${ENABLED[@]}"}; do
    [ "$seen" != "$a" ] || { echo "Duplicate reviewer adapter: $a" >&2; exit 2; }
  done
  ENABLED+=("$a")
done
[ "${#ENABLED[@]}" -gt 0 ] || { echo "Error: no reviewers requested." >&2; exit 2; }

MODEL_OF_CLAUDE="$(resolve_model claude)"
MODEL_OF_GROK="$(resolve_model grok)"
MODEL_OF_AGY="$(resolve_model agy)"
MODEL_OF_CODEX="$(resolve_model codex)"
model_of() {
  case "$1" in
    claude) printf '%s' "$MODEL_OF_CLAUDE" ;;
    grok) printf '%s' "$MODEL_OF_GROK" ;;
    agy) printf '%s' "$MODEL_OF_AGY" ;;
    codex) printf '%s' "$MODEL_OF_CODEX" ;;
  esac
}

MODEL_LINE=""
for a in "${ENABLED[@]}"; do MODEL_LINE+="${MODEL_LINE:+ }$a=$(model_of "$a")"; done

echo "=========================================================="
echo " Audit Multi-Agent Orchestrator"
echo " Target:   $TARGET_NAME ($TARGET_MODE)"
echo " Source:   $TARGET_SOURCE${TARGET_REF:+ @ $TARGET_REF}${TARGET_COMMIT:+ [$TARGET_COMMIT]}"
echo " Path:     $TARGET_DIR"
echo " Surface:  $SURFACE"
echo " Agents:   ${ENABLED[*]}"
echo " Models:   $MODEL_LINE"
echo " Output:   ${OUTPUT_DIR:-<plan>}"
echo " Policy:   persistent ACP sessions + one-shot Docker MCP bridge; committed reports are authoritative"
echo "=========================================================="

if [ "$PLAN" -eq 1 ]; then
  echo "Plan only. No harness, no agents."
  exit 0
fi

umask 077
if [ -d "$OUTPUT_DIR" ] && [ -n "$(ls -A "$OUTPUT_DIR")" ]; then
  echo "orchestrate: output directory must be empty; stale reports are not current evidence" >&2
  exit 2
fi
AGENTS_CSV="$(IFS=,; echo "${ENABLED[*]}")"
MODELS_JSON="{"
_first=1
for a in "${ENABLED[@]}"; do
  [ "$_first" -eq 1 ] || MODELS_JSON+=","
  _first=0
  MODELS_JSON+="\"$a\":\"$(model_of "$a")\""
done
MODELS_JSON+="}"
REQUEST_FILE="$(mktemp "${TMPDIR:-/tmp}/audit-review-request.XXXXXX")"
trap 'rm -f -- "$REQUEST_FILE"' EXIT
node -e '
const fs = require("node:fs");
const [file, target, out, name, mode, source, ref, commit, surface, agents, models, rpc, resumeFrom, testArtifacts, restartFailed] = process.argv.slice(1);
fs.writeFileSync(file, JSON.stringify({target, out, name, mode, source, ref, commit, surface, agents: agents.split(","), models: JSON.parse(models), rpc: rpc || "", resumeFrom: resumeFrom || null, testArtifacts: testArtifacts || null, restartFailed: restartFailed === "1"}), {mode: 0o600});
' "$REQUEST_FILE" "$TARGET_DIR" "$OUTPUT_DIR" "$TARGET_NAME" "$TARGET_MODE" "$TARGET_SOURCE" "$TARGET_REF" "$TARGET_COMMIT" "$SURFACE" "$AGENTS_CSV" "$MODELS_JSON" "$RPC" "$RESUME_FROM" "$TEST_ARTIFACTS" "$RESTART_FAILED"

code=0
if [ "${BLOCKED:-${AUDIT_BLOCKED_RUN:-0}}" = "1" ]; then
  node "$SCRIPT_DIR/worker-supervisor.mjs" blocked-run "$REQUEST_FILE" || code=$?
  if [ -f "$OUTPUT_DIR/meta.json" ]; then
    node "$SCRIPT_DIR/generate-html-report.mjs" "$OUTPUT_DIR" || code=2
  fi
  [ "$code" -ne 0 ] || code=2
  echo "Blocked/incomplete review record saved to: $OUTPUT_DIR"
  exit "$code"
fi

node "$SCRIPT_DIR/docker-agent-orchestrator.mjs" "$REQUEST_FILE" || code=$?
if [ -f "$OUTPUT_DIR/meta.json" ]; then
  # HTML generation revalidates and scores current inputs before rendering.
  node "$SCRIPT_DIR/generate-html-report.mjs" "$OUTPUT_DIR" || code=2
fi
echo "Audit report saved to: $OUTPUT_DIR"
exit "$code"
