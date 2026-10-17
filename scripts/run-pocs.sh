#!/usr/bin/env bash
set -euo pipefail

# run-pocs.sh
# Runs proof-of-concept tests against a target repo (resolved by bin/audit).
# Host execution of model-written Node/TypeScript files is refused.
# Rust command outcomes are not proof that a security assertion was exercised.
#
# Usage: run-pocs.sh --target <dir> --pocs <dir> [--name <slug>]
#   <pocs>/**/*.test.mjs   refused (no host execution)
#   <pocs>/**/*.spec.ts    refused (no host execution)
#   <pocs>/**/*.rs         cargo test --locked inside the disposable sandbox (a file with no #[test] is skipped)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="" POCS_DIR="" TARGET_NAME=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET_DIR="$2"; shift 2 ;;
    --pocs) POCS_DIR="$2"; shift 2 ;;
    --name) TARGET_NAME="$2"; shift 2 ;;
    *) echo "run-pocs: unknown option $1" >&2; exit 1 ;;
  esac
done
[ -d "$TARGET_DIR" ] || { echo "run-pocs: --target <dir> is required" >&2; exit 1; }
[ -d "$POCS_DIR" ] || { echo "run-pocs: PoC directory not found: $POCS_DIR (use --pocs <dir>)" >&2; exit 1; }
TARGET_DIR="$(cd "$TARGET_DIR" && pwd -P)"
POCS_DIR="$(cd "$POCS_DIR" && pwd -P)"

echo "=========================================================="
echo " Audit PoC Command Outcomes"
echo " Target: ${TARGET_NAME:-$(basename "$TARGET_DIR")} ($TARGET_DIR)"
echo " PoCs:   $POCS_DIR"
echo "=========================================================="

ERRORS=0
HELD=0
SKIPPED=0

mapfile_files() { # <name-glob> -> sorted file list, symlinked dirs not followed
  find "$POCS_DIR" -type f -name "$1" 2>/dev/null | sort
}


echo -e "\n[1/3] Node PoCs (host execution blocked)"
found=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  found=1
  echo "  -> $(basename "$f")"
  echo "     BLOCKED: Node PoCs are not executed on the host"
  SKIPPED=$((SKIPPED + 1))
done < <(mapfile_files '*.test.mjs')
[ "$found" = 1 ] || echo "  none found"

echo -e "\n[2/3] TypeScript PoCs (host execution blocked)"
found=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  found=1
  echo "  -> $(basename "$f")"
  echo "     BLOCKED: TypeScript PoCs are not executed on the host"
  SKIPPED=$((SKIPPED + 1))
done < <(mapfile_files '*.spec.ts')
[ "$found" = 1 ] || echo "  none found"

echo -e "\n[3/3] Rust PoCs (sandbox cargo test --locked)"
found=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  found=1
done < <(mapfile_files '*.rs')
if [ "$found" = 1 ]; then
  POC_OUT="$(mktemp -d "${TMPDIR:-/tmp}/audit-pocs.XXXXXX")"
  bash "$SCRIPT_DIR/sandbox.sh" --target "$TARGET_DIR" --out "$POC_OUT" --pocs "$POCS_DIR" || true
  ROWS="$(node -e '
    const fs = require("node:fs");
    const file = process.argv[1];
    const rows = fs.existsSync(file) ? (JSON.parse(fs.readFileSync(file, "utf8")).checks || []) : [];
    const pocs = rows.filter((row) => String(row.id || "").startsWith("poc:"));
    if (!pocs.length) { process.stdout.write("NO_ROWS\n"); process.exit(0); }
    for (const row of pocs) process.stdout.write(row.result + "\t" + row.id.slice(4) + "\t" + String(row.detail || "").replace(/\s+/g, " ").slice(0, 180) + "\n");
  ' "$POC_OUT/harness/sandbox-run/results.json" 2>/dev/null || true)"
  echo "  Sandbox diagnostics retained at: $POC_OUT"
  if [ -z "$ROWS" ] || [ "$ROWS" = "NO_ROWS" ]; then
    echo "  SKIPPED: the sandbox produced no PoC rows"
    SKIPPED=$((SKIPPED + 1))
  else
    while IFS="$(printf '\t')" read -r status name detail; do
      [ -n "$status" ] || continue
      echo "  -> $name"
      if [ "$status" = "ran" ]; then
        echo "     FINISHED: sandbox-reported command success, not validated assertion evidence"
        HELD=$((HELD + 1))
      elif [ "$status" = "impossible" ]; then
        echo "     SKIPPED: $detail"
        SKIPPED=$((SKIPPED + 1))
      else
        echo "     ERROR: test or infrastructure failure; reproduction is unverified"
        ERRORS=$((ERRORS + 1))
      fi
    done <<EOF
$ROWS
EOF
  fi
else
  echo "  none found"
fi

echo -e "\n=========================================================="
echo " PoC command outcomes: $HELD finished, $ERRORS errors, $SKIPPED blocked/skipped"
echo "=========================================================="
if [ "$ERRORS" -gt 0 ] || [ "$SKIPPED" -gt 0 ]; then exit 2; fi
