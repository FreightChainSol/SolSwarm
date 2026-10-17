#!/usr/bin/env bash
# resolve-target.sh - sourced by bin/audit.
#
# The suite has exactly two target modes:
#   local   --repo <path>      audit a directory that is already on disk
#   remote  --github <url>     shallow-clone a GitHub repo into /tmp and audit the clone
#
# resolve_target sets:
#   TARGET_MODE    local | remote
#   TARGET_DIR     absolute path of the code to audit
#   TARGET_NAME    short slug (used in report directory names and prompts)
#   TARGET_SOURCE  the path or the normalised clone URL
#   TARGET_REF     branch / tag / sha that was asked for ("" = default branch)
#   TARGET_COMMIT  commit that is checked out ("" when the target is not a git repo)
#   TARGET_CLONED  1 when TARGET_DIR is a temporary clone owned by this run
#   TARGET_TMPDIR  the mktemp directory that holds the clone (remote mode only)
#
# Inputs (set by the caller): ARG_REPO, ARG_GITHUB, ARG_REF, ARG_WORKDIR.

# Base directory for remote clones. Override with --workdir or AUDIT_TMP.
AUDIT_TMP_DEFAULT="/tmp/audit-targets"

die() {
  echo "audit: $*" >&2
  exit 1
}

slugify() {
  # lower-case, keep [a-z0-9._-], collapse everything else to "-"
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//'
}

# Accepts https://github.com/o/r[.git][/...], git@github.com:o/r[.git], github.com/o/r and o/r.
# Prints "<owner>/<repo>" or returns 1. Anything else (other hosts, flags, ext:: transports) is refused.
parse_github() {
  local url="$1" path=""
  case "$url" in
    https://github.com/*) path="${url#https://github.com/}" ;;
    http://github.com/*) path="${url#http://github.com/}" ;;
    git@github.com:*) path="${url#git@github.com:}" ;;
    ssh://git@github.com/*) path="${url#ssh://git@github.com/}" ;;
    github.com/*) path="${url#github.com/}" ;;
    -*|*://*|*::*) return 1 ;;
    */*) path="$url" ;; # owner/repo shorthand
    *) return 1 ;;
  esac
  path="${path%%[?#]*}"
  path="${path%.git}"
  local owner repo rest
  IFS='/' read -r owner repo rest <<<"$path"
  repo="${repo%.git}"
  # GitHub names: letters, digits, '-', '_', '.'; never start with '-' or '.'.
  [[ "$owner" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || return 1
  [[ "$repo" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]] || return 1
  printf '%s/%s' "$owner" "$repo"
}

# Refs go to `git clone --branch` / `git fetch`; refuse anything that could be read as an option.
valid_ref() {
  [[ "$1" =~ ^[A-Za-z0-9_][A-Za-z0-9_./-]*$ ]]
}

clone_github() {
  local slug="$1" ref="$2" dest="$3"
  local url="https://github.com/${slug}.git"
  # Hooks and prompts are off: the clone is untrusted input and must not execute anything.
  local -a git_cmd=(git -c core.hooksPath=/dev/null -c protocol.ext.allow=never -c protocol.file.allow=never)
  export GIT_TERMINAL_PROMPT=0

  echo "  Cloning $url${ref:+ @ $ref} -> $dest"
  if [ -z "$ref" ]; then
    "${git_cmd[@]}" clone --quiet --depth 1 --no-tags -- "$url" "$dest" || die "clone failed: $url (private repo? run 'gh auth login' / check the URL)"
  elif "${git_cmd[@]}" clone --quiet --depth 1 --no-tags --branch "$ref" -- "$url" "$dest" 2>/dev/null; then
    : # branch or tag
  else
    # a commit sha: fetch exactly that object
    rm -rf "$dest"
    mkdir -p "$dest"
    # chained with &&: a subshell on the left of || runs without set -e, so a failed fetch would not stop the checkout
    (
      cd "$dest" &&
        "${git_cmd[@]}" init --quiet &&
        "${git_cmd[@]}" remote add origin "$url" &&
        "${git_cmd[@]}" fetch --quiet --depth 1 origin "$ref" &&
        "${git_cmd[@]}" checkout --quiet --detach FETCH_HEAD
    ) || die "could not fetch ref '$ref' from $url (a commit must be the full 40-char sha)"
  fi
}

resolve_target() {
  if [ -n "${ARG_REPO:-}" ] && [ -n "${ARG_GITHUB:-}" ]; then
    die "pick one target: --repo <path> (local) or --github <url> (remote), not both"
  fi
  if [ -z "${ARG_REPO:-}" ] && [ -z "${ARG_GITHUB:-}" ]; then
    die "no target. Use --repo <path> (local) or --github <url> (remote). See 'audit help'"
  fi

  TARGET_REF="${ARG_REF:-}"
  TARGET_CLONED=0
  TARGET_COMMIT=""

  if [ -n "${ARG_REPO:-}" ]; then
    [ -z "$TARGET_REF" ] || die "--ref only applies to --github (a local path is audited as it is on disk)"
    TARGET_MODE="local"
    [ -d "$ARG_REPO" ] || die "local path not found or not a directory: $ARG_REPO"
    TARGET_DIR="$(cd "$ARG_REPO" && pwd -P)"
    TARGET_SOURCE="$TARGET_DIR"
    TARGET_NAME="$(slugify "$(basename "$TARGET_DIR")")"
  else
    TARGET_MODE="remote"
    local slug
    slug="$(parse_github "$ARG_GITHUB")" || die "not a GitHub repo URL: $ARG_GITHUB (expected https://github.com/<owner>/<repo>, git@github.com:<owner>/<repo>.git or <owner>/<repo>)"
    if [ -n "$TARGET_REF" ]; then
      valid_ref "$TARGET_REF" || die "invalid --ref: $TARGET_REF"
    fi
    command -v git >/dev/null 2>&1 || die "git is required for --github"

    local base="${ARG_WORKDIR:-${AUDIT_TMP:-$AUDIT_TMP_DEFAULT}}"
    mkdir -p "$base"
    base="$(cd "$base" && pwd -P)"
    TARGET_NAME="$(slugify "${slug//\//-}")"
    TARGET_SOURCE="https://github.com/${slug}"
    # one fresh directory per run, so parallel runs never share a checkout
    TARGET_TMPDIR="$(mktemp -d "$base/${TARGET_NAME}.XXXXXX")"
    TARGET_CLONED=1 # the caller's EXIT trap removes TARGET_TMPDIR if the clone dies halfway
    clone_github "$slug" "$TARGET_REF" "$TARGET_TMPDIR/repo"
    TARGET_DIR="$TARGET_TMPDIR/repo"
  fi

  if git -C "$TARGET_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    TARGET_COMMIT="$(git -C "$TARGET_DIR" rev-parse --short=12 HEAD 2>/dev/null || true)"
  fi
}

# Removes the temporary clone dir created by mktemp above (never a --repo path).
cleanup_target() {
  if [ "${TARGET_CLONED:-0}" = "1" ] && [ -n "${TARGET_TMPDIR:-}" ] && [ -d "$TARGET_TMPDIR" ]; then
    rm -rf "$TARGET_TMPDIR"
  fi
}

# Call after resolve_target: remote clones are kept (reports cite file:line, you may want to re-read them)
# unless --clean was given. Leaves the EXIT trap armed only for --clean runs.
KEEP_CLONE=0
arm_cleanup() {
  if [ "${TARGET_CLONED:-0}" = "1" ] && [ "${ARG_CLEAN:-0}" != "1" ]; then
    KEEP_CLONE=1
    TARGET_CLONED=0
  fi
}

report_kept_clone() {
  if [ "$KEEP_CLONE" = "1" ]; then
    echo "Clone kept at: $TARGET_DIR (delete it, or pass --clean next time)"
  fi
}
