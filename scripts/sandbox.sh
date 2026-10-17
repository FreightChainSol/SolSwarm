#!/usr/bin/env bash
# Disposable sandbox for one audit run.
# No host secrets, SSH keys, Solana keys, or Docker socket are mounted.
# The target container sits on an internal network. Its only egress is the
# allowlist proxy (crates.io, registry.npmjs.org, registry.yarnpkg.com, GitHub, port 443).
# A check that cannot be started is written as "impossible" in harness/sandbox.md
# and appended to harness/summary.md.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB="$SCRIPT_DIR/sandbox-lib.mjs"
TARGET=""
OUT=""
RPC=""
POCS=""
POCS_ONLY=0
REVIEW_ONLY=0
HOLD_FILE=""
READY_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --review-only) REVIEW_ONLY=1; shift ;;
    --target) TARGET="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --rpc) RPC="$2"; shift 2 ;;
    --pocs) POCS="$2"; POCS_ONLY=1; shift 2 ;;
    --hold-file) HOLD_FILE="$2"; shift 2 ;;
    --ready-file) READY_FILE="$2"; shift 2 ;;
    *) echo "sandbox: unknown option $1" >&2; exit 2 ;;
  esac
done

[ -n "$TARGET" ] && [ -d "$TARGET" ] || { echo "sandbox: --target <dir> is required" >&2; exit 2; }
[ -n "$OUT" ] || { echo "sandbox: --out <dir> is required" >&2; exit 2; }
[ -z "$POCS" ] || [ -d "$POCS" ] || { echo "sandbox: --pocs directory not found" >&2; exit 2; }

[ "$REVIEW_ONLY" -eq 0 ] || { [ -z "$RPC" ] && [ "$POCS_ONLY" -eq 0 ]; } || { echo "source security review excludes RPC comparisons and PoCs" >&2; exit 2; }

OUT="$(cd "$OUT" && pwd -P)"
HARNESS="$OUT/harness"
RUN="$HARNESS/sandbox-run"
SANDBOX_MD="$HARNESS/sandbox.md"
SUMMARY="$HARNESS/summary.md"
mkdir -p "$RUN"

ID="$(date +%H%M%S)-$$"
NET="audit-sbx-$ID"
OUTNET="audit-sbx-out-$ID"
PROXY="audit-proxy-$ID"
INIT="audit-init-$ID"
SBX="audit-sbx-$ID"
ZAP="audit-zap-$ID"
SVERIFY="audit-sverify-$ID"
OSVFETCH="audit-osv-$ID"
TOOLS="audit-tools-$ID"
EXPORT="audit-export-$ID"
VOL="audit-work-$ID"
STAGE=""
MEMORY="${AUDIT_SANDBOX_MEMORY:-8g}"
CPUS="${AUDIT_SANDBOX_CPUS:-2}"
BUDGET_MS="${AUDIT_SANDBOX_BUDGET_MS:-2700000}"
RENDERED=0
VOLUME_READY=0

cleanup_docker() {
  docker rm -f "$SBX" "$INIT" "$PROXY" "$ZAP" "$SVERIFY" "$OSVFETCH" "$TOOLS" "$EXPORT" >/dev/null 2>&1 || true
  docker network rm "$NET" "$OUTNET" >/dev/null 2>&1 || true
  docker volume rm "$VOL" >/dev/null 2>&1 || true
  if [ -n "$STAGE" ] && [ -d "$STAGE" ]; then rm -rf "$STAGE"; fi
}

# docker run -d only records the client. The process log is docker logs.
capture_logs() {
  if docker inspect "$SBX" >/dev/null 2>&1; then
    docker logs "$SBX" >"$RUN/container-console.log" 2>&1 || true
  fi
}

render() {
  [ "$RENDERED" -eq 1 ] && return 0
  capture_logs
  if [ -d "$RUN/harness-leads" ]; then
    for f in "$RUN/harness-leads"/*.md "$RUN/harness-leads"/*.json; do
      [ -f "$f" ] && cp -f "$f" "$HARNESS/" 2>/dev/null || true
    done
  fi
  if [ ! -s "$RUN/results.json" ]; then
    tail="$(tail -n 4 "$RUN/container-console.log" 2>/dev/null | tr '\n' ' ' | cut -c1-240 || true)"
    msg="The sandbox produced no results."
    if [ -n "$tail" ]; then msg="The sandbox produced no results. ${tail}"; fi
    node "$LIB" blocked "$RUN/results.json" "$msg" || true
  fi
  node "$LIB" render "$RUN/results.json" "$SANDBOX_MD" "$SUMMARY" || true
  mkdir -p "$RUN/harness"
  for f in "$HARNESS"/*.md "$HARNESS"/*.json; do
    [ -f "$f" ] && cp -f "$f" "$RUN/harness/" 2>/dev/null || true
  done
  RENDERED=1
}

# The work volume is removed in cleanup. Copy built programs out first.
# solana-verify already wrote its .so on the host; anchor/cargo wrote theirs on the volume.
export_files() {
  [ "$VOLUME_READY" -eq 1 ] || return 0
  mkdir -p "$OUT/files"
  chmod 777 "$OUT/files" || true
  if docker volume inspect "$VOL" >/dev/null 2>&1 && docker image inspect audit-sandbox:local >/dev/null 2>&1; then
    docker run --rm --name "$EXPORT" \
      --entrypoint node \
      --user 10001:10001 \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --network none \
      --read-only \
      --tmpfs /tmp:uid=10001,gid=10001,size=64m \
      -v "$VOL":/work:ro \
      -v "$OUT/files":/export \
      -v "$LIB:/opt/audit/sandbox-lib.mjs:ro" \
      audit-sandbox:local \
      /opt/audit/sandbox-lib.mjs export /work /export build \
      >"$RUN/export.log" 2>&1 || true
    chmod -R a+rwX "$OUT/files" || true
  fi
  if [ -d "$RUN/sbf-out" ]; then
    node "$LIB" export "$RUN/sbf-out" "$OUT/files" sbf >>"$RUN/export.log" 2>&1 || true
  fi
  if [ ! -f "$OUT/files/manifest.json" ]; then
    printf '[]\n' > "$OUT/files/manifest.json" || true
  fi
}

finish() {
  render
  export_files
  cleanup_docker
}

trap finish EXIT

note_blocked() {
  node "$LIB" blocked "$RUN/results.json" "$1" || true
  render
  exit 0
}

if ! docker info >/dev/null 2>&1; then
  note_blocked "Docker is not available, so no sandbox was started."
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/audit-sandbox.XXXXXX")"
node "$LIB" copy "$TARGET" "$STAGE/src"
chmod -R a+rX "$STAGE/src" || true
node "$LIB" plan "$STAGE/src" > "$RUN/plan.json"
node "$LIB" assess "$RUN/plan.json" > "$RUN/assess.json"

if [ "${SANDBOX_FAST:-0}" = "1" ] && docker image inspect audit-sandbox:local >/dev/null 2>&1; then
  printf 'Inert fixture: using the preprovisioned local sandbox image. No image build attempted.\n' >"$RUN/image.log"
elif ! docker build -t audit-sandbox:local -f "$AUDIT_ROOT/docker/sandbox.Dockerfile" "$AUDIT_ROOT/docker" >"$RUN/image.log" 2>&1; then
  tail -n 20 "$RUN/image.log" >&2 || true
  note_blocked "The sandbox image failed to build. See harness/sandbox-run/image.log."
fi

OSV_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/freightchain-audit/osv"
OSV_MOUNTS=()
TOOLS_DIR=""

# Host downloads the extra OSV databases. The seed is only the lockfiles.
# The target container never gets a route to the OSV API.
if [ "$POCS_ONLY" -eq 0 ]; then
  mkdir -p "$RUN/osv-seed" "$OSV_CACHE"
  SEEDED="$(node "$LIB" osv-seed "$RUN/plan.json" "$STAGE/src" "$RUN/osv-seed" 2>/dev/null || echo 0)"
  if [ "${SEEDED:-0}" != "0" ]; then
    docker run --rm --name "$OSVFETCH" \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --pids-limit 128 \
      --memory 1g \
      -e XDG_CACHE_HOME=/cache \
      -v "$OSV_CACHE":/cache \
      -v "$RUN/osv-seed":/seed:ro \
      --entrypoint osv-scanner \
      audit-sandbox:local \
      scan source --download-offline-databases --offline -r /seed \
      >"$RUN/osv-prefetch.log" 2>&1 || true
  fi
  if [ -d "$OSV_CACHE/osv-scalibr" ]; then
    for dir in "$OSV_CACHE/osv-scalibr"/*; do
      [ -d "$dir" ] || continue
      base="$(basename "$dir")"
      case "$base" in crates.io|npm) continue ;; esac
      OSV_MOUNTS+=(-v "$dir:/opt/osv-cache/osv-scalibr/$base:ro")
    done
  fi
fi

# Platform-tools are fetched by the Solana Foundation image on the host
# network, from a one-file crate we write. The target sources are not mounted.
# The version comes only from a pinned solana_version.
prefetch_tools() {
  local ver="$1" cache
  case "$ver" in
    ''|*[!0-9.]*) return 1 ;;
  esac
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/freightchain-audit/platform-tools/${ver}"
  if find "$cache/.cache/solana" -type d -name platform-tools -print -quit 2>/dev/null | grep -q .; then
    printf '%s' "$cache"
    return 0
  fi
  mkdir -p "$cache" "$RUN/sbf-dummy/src"
  printf '%s\n' '[package]' 'name = "prefetch"' 'version = "0.0.0"' 'edition = "2021"' '' '[lib]' 'crate-type = ["cdylib"]' \
    > "$RUN/sbf-dummy/Cargo.toml"
  printf '#![no_std]\n' > "$RUN/sbf-dummy/src/lib.rs"
  if ! docker pull --platform linux/amd64 "solanafoundation/solana-verifiable-build:${ver}" >"$RUN/platform-tools-pull.log" 2>&1; then
    return 1
  fi
  docker run --name "$TOOLS" --platform linux/amd64 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 1024 \
    --memory "$MEMORY" \
    -e HOME=/home/solana \
    -e CARGO_HOME=/tmp/cargo \
    -e CARGO_TARGET_DIR=/tmp/target \
    --tmpfs /tmp:size=4g \
    -v "$cache":/home/solana \
    -v "$RUN/sbf-dummy":/build:ro \
    -w /build \
    "solanafoundation/solana-verifiable-build:${ver}" \
    cargo-build-sbf >"$RUN/platform-tools.log" 2>&1 || true
  docker rm -f "$TOOLS" >/dev/null 2>&1 || true
  if find "$cache/.cache/solana" -type d -name platform-tools -print -quit 2>/dev/null | grep -q .; then
    printf '%s' "$cache"
    return 0
  fi
  return 1
}

if [ "$POCS_ONLY" -eq 0 ] && [ "$REVIEW_ONLY" -eq 0 ]; then
  SOLANA_EARLY="$(node "$LIB" solana "$RUN/plan.json" 2>/dev/null || true)"
  if [ -n "$SOLANA_EARLY" ]; then
    TOOLS_DIR="$(prefetch_tools "${SOLANA_EARLY%%$'\t'*}" || true)"
  fi
fi

docker network create --internal "$NET" >/dev/null
docker network create "$OUTNET" >/dev/null
docker volume create "$VOL" >/dev/null
VOLUME_READY=1

docker run -d --name "$PROXY" \
  --network "$OUTNET" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 256m \
  --read-only \
  --tmpfs /tmp \
  --user node \
  -e PORT=3128 \
  -v "$SCRIPT_DIR/sandbox-proxy.mjs:/opt/audit/sandbox-proxy.mjs:ro" \
  -v "$SCRIPT_DIR/sandbox-lib.mjs:/opt/audit/sandbox-lib.mjs:ro" \
  -w /opt/audit \
  node:22-bookworm-slim \
  node /opt/audit/sandbox-proxy.mjs >/dev/null

docker network connect "$NET" "$PROXY"
PROXY_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$PROXY")"
if [ -z "$PROXY_IP" ]; then
  note_blocked "The allowlist proxy has no address on the internal network."
fi

export HTTP_PROXY="http://${PROXY_IP}:3128"
export HTTPS_PROXY="$HTTP_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTP_PROXY"
export NO_PROXY="localhost,127.0.0.1"
export no_proxy="$NO_PROXY"
export GIT_TERMINAL_PROMPT=0

ZAP_PENDING=0
if [ "$POCS_ONLY" -eq 0 ] && [ "$REVIEW_ONLY" -eq 0 ] && node -e 'const r=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8")); process.exit(r.some(c=>c.id==="zap"&&c.result==="pending")?0:1)' "$RUN/assess.json"; then
  ZAP_PENDING=1
  docker pull ghcr.io/zaproxy/zaproxy:stable >"$RUN/zap-pull.log" 2>&1 &
  ZAP_PULL=$!
fi

# cap-drop ALL cannot chown. Prepare the volume as root, then run the target
# as uid 10001. The init command is fixed; it does not execute the repository.
chmod 777 "$RUN" || true
if ! docker run --rm --name "$INIT" \
  --entrypoint bash \
  --user 0:0 \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges \
  --read-only \
  -v "$VOL":/work \
  -v "$RUN":/out \
  audit-sandbox:local \
  -c 'mkdir -p /work/src /work/cargo /work/target /work/bin && chown -R 10001:10001 /work && chmod 777 /out' \
  >"$RUN/init.log" 2>&1; then
  note_blocked "The sandbox work directory could not be prepared. See harness/sandbox-run/init.log."
fi

if ! docker run -d --name "$SBX" \
  --network "$NET" \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --init \
  --pids-limit 1024 \
  --memory "$MEMORY" \
  --cpus "$CPUS" \
  --read-only \
  --tmpfs /tmp:uid=10001,gid=10001,size=1g \
  --tmpfs /home/sandbox:uid=10001,gid=10001,size=256m \
  -e HOME=/home/sandbox \
  -e NODE_USE_ENV_PROXY=1 \
  -e GIT_TERMINAL_PROMPT=0 \
  -e OPENSSL_NO_VENDOR=1 \
  ${TOOLS_DIR:+-e SOLANA_PLATFORM_TOOLS_DIR=/opt/platform-tools} \
  -e SANDBOX_OUT=/out \
  -e SANDBOX_BUDGET_MS="$BUDGET_MS" \
  -e SANDBOX_POCS="$POCS_ONLY" \
  -e SANDBOX_REVIEW_ONLY="$REVIEW_ONLY" \
  -e SANDBOX_HOLD="${HOLD_FILE:+1}" \
  -e SANDBOX_FAST="${SANDBOX_FAST:-0}" \
  -e HTTP_PROXY -e HTTPS_PROXY -e http_proxy -e https_proxy -e NO_PROXY -e no_proxy \
  -e CARGO_HOME=/work/cargo \
  -e CARGO_TARGET_DIR=/work/target \
  -e CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
  -e XDG_CACHE_HOME=/opt/osv-cache \
  -e npm_config_registry=https://registry.npmjs.org \
  -e GIT_CONFIG_GLOBAL=/dev/null \
  -e GIT_CONFIG_SYSTEM=/dev/null \
  -v "$VOL":/work \
  -v "$STAGE/src:/src:ro" \
  -v "$RUN":/out \
  -v "$SCRIPT_DIR/sandbox-inside.mjs:/opt/audit/sandbox-inside.mjs:ro" \
  -v "$SCRIPT_DIR/sandbox-lib.mjs:/opt/audit/sandbox-lib.mjs:ro" \
  -v "$SCRIPT_DIR/harness.mjs:/opt/audit/harness.mjs:ro" \
  -v "$SCRIPT_DIR/audit-plans.mjs:/opt/audit/audit-plans.mjs:ro" \
  -v "$SCRIPT_DIR/scanner-evidence.mjs:/opt/audit/scanner-evidence.mjs:ro" \
  ${OSV_MOUNTS[@]+"${OSV_MOUNTS[@]}"} \
  ${TOOLS_DIR:+-v "$TOOLS_DIR/.cache/solana:/opt/platform-tools:ro"} \
  ${POCS:+-v "$POCS:/pocs:ro"} \
  audit-sandbox:local \
  node /opt/audit/sandbox-inside.mjs >"$RUN/container.id" 2>"$RUN/container.log"; then
  note_blocked "The sandbox container did not start. See harness/sandbox-run/container.log."
fi

running() { docker inspect -f '{{.State.Running}}' "$SBX" 2>/dev/null | grep -qx true; }

SEEN=0
for ((i=0; i<1600; i++)); do
  if [ "$SEEN" -eq 0 ] && [ -f "$RUN/zap.json" ]; then
    SEEN=1
    READY="$(node -e 'const j=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8")); process.stdout.write(j.ready?"yes":"no")' "$RUN/zap.json" 2>/dev/null || echo no)"
    if [ "$READY" = "yes" ]; then
      if [ -n "${ZAP_PULL:-}" ]; then wait "$ZAP_PULL" || true; fi
      ZCODE=0
      docker run --rm --name "$ZAP" \
        --network "container:$SBX" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --memory 2g \
        ghcr.io/zaproxy/zaproxy:stable \
        zap-baseline.py -t http://127.0.0.1:3000 -I -m 2 \
        >"$RUN/zap.log" 2>&1 || ZCODE=$?
      TAIL="$(tail -n 3 "$RUN/zap.log" 2>/dev/null | tr '\n' ' ' | cut -c1-300)"
      if [ "$ZCODE" -le 2 ]; then ZRESULT=ran; else ZRESULT=failed; fi
      node -e 'const fs=require("node:fs"); fs.writeFileSync(process.argv[1], JSON.stringify({id:"zap", result:process.argv[2], detail:process.argv[3]}));' \
        "$RUN/zap-outcome.json" "$ZRESULT" "Baseline against 127.0.0.1:3000 on the sandbox network only (exit ${ZCODE}). ${TAIL}"
    fi
    : > "$RUN/zap.done"
  fi
  if [ -n "$HOLD_FILE" ] && [ -f "$RUN/checks.done" ]; then break; fi
  if ! running; then break; fi
  sleep 2
done

if [ -z "$HOLD_FILE" ]; then
  if running; then docker kill "$SBX" >/dev/null 2>&1 || true; fi
  docker wait "$SBX" >/dev/null 2>&1 || true
fi

if [ -f "$RUN/zap-outcome.json" ]; then
  node -e '
    const fs = require("node:fs");
    const o = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const file = process.argv[2];
    const cur = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : { checks: [] };
    cur.checks = (cur.checks || []).filter((c) => c.id !== o.id);
    cur.checks.push(o);
    fs.writeFileSync(file, JSON.stringify(cur, null, 2) + "\n");
  ' "$RUN/zap-outcome.json" "$RUN/results.json"
elif [ "$ZAP_PENDING" -eq 1 ] && [ "$SEEN" -eq 0 ]; then
  node "$LIB" merge "$RUN/results.json" zap impossible "The sandbox did not report a local server, so ZAP was not started." || true
fi

SOLANA_LINE=""
if [ "$POCS_ONLY" -eq 0 ] && [ "$REVIEW_ONLY" -eq 0 ] && [ "${SANDBOX_FAST:-0}" != "1" ]; then
  SOLANA_LINE="$(node "$LIB" solana "$RUN/plan.json" 2>/dev/null || true)"
fi
if [ -n "$SOLANA_LINE" ]; then
  SOLANA_VERSION="${SOLANA_LINE%%$'\t'*}"
  SOLANA_REL="${SOLANA_LINE#*$'\t'}"
  WORK="/build"
  [ "$SOLANA_REL" = "." ] || WORK="/build/${SOLANA_REL}"
  if docker pull --platform linux/amd64 "solanafoundation/solana-verifiable-build:${SOLANA_VERSION}" >"$RUN/solana-verify-pull.log" 2>&1; then
    mkdir -p "$RUN/sbf-out"
    chmod 777 "$RUN/sbf-out" || true
    TOOLS_NOTE=""
    # ${var:-word} would insert the cache path itself when the variable is set.
    SBF_HOME=(-e HOME=/tmp/home)
    if [ -n "$TOOLS_DIR" ]; then
      TOOLS_NOTE=" Platform-tools were mounted read-only from the host prefetch."
      SBF_HOME=(
        -e HOME=/opt/platform-home
        -e SOLANA_PLATFORM_TOOLS_DIR=/opt/platform-home/.cache/solana
        -v "$TOOLS_DIR:/opt/platform-home:ro"
      )
    fi
    docker run --name "$SVERIFY" \
      --platform linux/amd64 \
      --network "$NET" \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --pids-limit 1024 \
      --memory "$MEMORY" \
      --tmpfs /tmp:size=4g \
      -e HTTP_PROXY -e HTTPS_PROXY -e http_proxy -e https_proxy -e NO_PROXY -e no_proxy \
      -e GIT_TERMINAL_PROMPT=0 \
      -e OPENSSL_NO_VENDOR=1 \
      -e CARGO_HOME=/tmp/cargo \
      -e CARGO_TARGET_DIR=/sbf-out \
      "${SBF_HOME[@]}" \
      -v "$STAGE/src:/build:ro" \
      -v "$RUN/sbf-out:/sbf-out" \
      -w "$WORK" \
      "solanafoundation/solana-verifiable-build:${SOLANA_VERSION}" \
      cargo-build-sbf \
      >"$RUN/solana-verify.log" 2>&1 &
    SPID=$!
    SLEFT=150
    while kill -0 "$SPID" 2>/dev/null && [ "$SLEFT" -gt 0 ]; do
      sleep 10
      SLEFT=$((SLEFT - 1))
    done
    if kill -0 "$SPID" 2>/dev/null; then
      docker rm -f "$SVERIFY" >/dev/null 2>&1 || true
      wait "$SPID" || true
      node "$LIB" merge "$RUN/results.json" solana-verify failed "Timed out after 25 minutes in solanafoundation/solana-verifiable-build:${SOLANA_VERSION}. The Docker socket was not mounted.${TOOLS_NOTE}" || true
    else
      wait "$SPID" || SCODE=$?
      SCODE="${SCODE:-0}"
      TAIL="$(tail -n 3 "$RUN/solana-verify.log" 2>/dev/null | tr '\n' ' ' | cut -c1-240)"
      if [ "$SCODE" -eq 0 ]; then
        node "$LIB" merge "$RUN/results.json" solana-verify ran "cargo-build-sbf in solanafoundation/solana-verifiable-build:${SOLANA_VERSION} (${SOLANA_REL}). Socket not mounted.${TOOLS_NOTE} ${TAIL}" || true
      else
        node "$LIB" merge "$RUN/results.json" solana-verify failed "exit ${SCODE} in solanafoundation/solana-verifiable-build:${SOLANA_VERSION}. Socket not mounted.${TOOLS_NOTE} ${TAIL}" || true
      fi
    fi
  else
    node "$LIB" merge "$RUN/results.json" solana-verify impossible "Image solanafoundation/solana-verifiable-build:${SOLANA_VERSION} was not pulled. The Docker socket was not mounted." || true
  fi
fi

# The host sends this request. The URL is the one the user passed. The container never sees it.
if [ -n "$RPC" ] && [ "$POCS_ONLY" -eq 0 ]; then
  if RPC_URL="$(node "$LIB" rpc "$RPC" 2>/dev/null)"; then
    if node "$LIB" compare "$RPC_URL" "$STAGE/src" "$RUN/sbf-out" >"$RUN/deployed.json" 2>"$RUN/deployed.err"; then
      CMP="$(node -e 'const o=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8")); process.stdout.write(o.result+"\n"+o.detail)' "$RUN/deployed.json")"
      node "$LIB" merge "$RUN/results.json" deployed-compare "${CMP%%$'\n'*}" "${CMP#*$'\n'}" || true
    else
      ERR="$(tail -n 2 "$RUN/deployed.err" 2>/dev/null | tr '\n' ' ' | cut -c1-180)"
      node "$LIB" merge "$RUN/results.json" deployed-compare failed "The deployed comparison did not finish. ${ERR}" || true
    fi
  else
    node "$LIB" merge "$RUN/results.json" deployed-compare impossible "The --rpc URL was refused. It must be https, with no credentials, and not a private, link-local, or metadata address." || true
  fi
fi

render
export_files

if [ -n "$HOLD_FILE" ] && running; then
  # Airgap the one-shot container before agentic CLIs attach via MCP bridge.
  docker network disconnect "$NET" "$PROXY" >/dev/null 2>&1 || true
  docker rm -f "$PROXY" >/dev/null 2>&1 || true
  docker network disconnect "$NET" "$SBX" >/dev/null 2>&1 || true
  # Refuse handoff if disconnect failed; no reviewer receives a networked sandbox.
  if ! docker inspect --format '{{json .NetworkSettings.Networks}}' "$SBX" | node -e '
    let data = "";
    process.stdin.on("data", chunk => data += chunk);
    process.stdin.on("end", () => {
      try { const networks = JSON.parse(data); process.exit(networks && Object.keys(networks).every(key => key === "none") ? 0 : 1); }
      catch { process.exit(1); }
    });
  '; then
    echo "sandbox: cannot verify network disconnection; refusing reviewer handoff" >&2
    exit 1
  fi
  if [ -n "$READY_FILE" ]; then
    node -e '
      const fs = require("node:fs");
      const [file, container, hostRunDir, hostOutDir] = process.argv.slice(1);
      fs.writeFileSync(file, JSON.stringify({ container, workDir: "/work/src", outDir: "/out", hostRunDir, hostOutDir }) + "\n");
    ' "$READY_FILE" "$SBX" "$RUN" "$OUT"
  fi
  # A transient inspect/daemon failure must never release an active review.
  node "$SCRIPT_DIR/sandbox-lifecycle.mjs" "$SBX" "$HOLD_FILE" "$RUN/lifecycle.json"
  : > "$RUN/sandbox.release" 2>/dev/null || true
  if running; then docker kill "$SBX" >/dev/null 2>&1 || true; fi
  docker wait "$SBX" >/dev/null 2>&1 || true
fi

exit 0
