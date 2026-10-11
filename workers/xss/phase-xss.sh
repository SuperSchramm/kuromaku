#!/bin/bash
## phase-xss.sh — Kuromaku Phase 4: XSS Hunting
## Runs inside the kuromaku-xss container. Reads gau-dirty.log produced by
## Phase 1 (recon). Writes dalfox.log.
##
## Usage: phase-xss.sh -d <domain> -t <scan_dir>
##        phase-xss.sh -dl <domain_list_file> -t <scan_dir>
##
## Required input (from Phase 1):
##   <prefix>-gau-dirty.log
##
## Required output (validated by orchestrator):
##   <prefix>-dalfox.log   (created even if empty — absence of XSS candidates
##                           is a valid result, not a failure)

set -uo pipefail

# ─── Argument Parsing ─────────────────────────────────────────────────────────
PARAMS=""
while (( "$#" )); do
  case "$1" in
    -d|--domain)
      baseDomain=$2; shift 2 ;;
    -dl|--domain_list)
      domain_list=$2; shift 2 ;;
    -t|--target-dir)
      tdir=$2; shift 2 ;;
    *)
      PARAMS="$PARAMS $1"; shift ;;
  esac
done
eval set -- "$PARAMS"

if [ -z "${baseDomain:-}" ] && [ -z "${domain_list:-}" ]; then
  echo "Error: -d <domain> or -dl <domain_list> is required" >&2
  exit 1
fi
if [ -z "${tdir:-}" ]; then
  echo "Error: -t <target_dir> is required" >&2
  exit 1
fi

# ─── Logger ────────────────────────────────────────────────────────────────────
PROGRESS_LOG="$tdir/kuromaku_progress.log"
log() {
  echo " █▄▄▪ [xss] $1" | tee -a "$PROGRESS_LOG"
}

# ─── Resolve prefix and input file ─────────────────────────────────────────────
if [ -z "${domain_list:-}" ]; then
  TARGET_PREFIX="$tdir/$baseDomain"
else
  daBase="$(basename "$domain_list")"
  TARGET_PREFIX="$tdir/$daBase"
fi

GAU_DIRTY="${TARGET_PREFIX}-gau-dirty.log"

log "Phase started"

## dalfox.log holds findings only, but an empty file can't tell "ran, found
## nothing" from "never ran". '#'-prefixed lines record the attempt; the
## report and kuromaku_results consumers skip them.
DALFOX_LOG="$TARGET_PREFIX-dalfox.log"
note() { echo "# $1" >> "$DALFOX_LOG"; }
: > "$DALFOX_LOG"
note "kuromaku xss phase $(date -u +%FT%TZ) target=${baseDomain:-$daBase}"

if [ ! -f "$GAU_DIRTY" ]; then
  log "No gau-dirty.log found (did Phase 1 / recon run first?) — writing empty dalfox.log"
  note "outcome: no gau-dirty.log input (recon did not produce URLs)"
  log "Phase complete"
  exit 0
fi

# ─── Build XSS candidate URL list ───────────────────────────────────────────────
log "Building XSS candidate URL list"
CANDIDATE_COUNT=$(cat "$GAU_DIRTY" \
  | qsreplace FUZZ \
  | grep "=" \
  | grep -Eiv "\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)$" \
  | sort -u \
  | tee "$TARGET_PREFIX-xss-candidates.log" \
  | wc -l)

log "$CANDIDATE_COUNT candidate URLs with parameters"
note "input URLs (gau-dirty.log): $(wc -l < "$GAU_DIRTY")"
note "candidate URLs with parameters (deduped by shape): $CANDIDATE_COUNT"

if [ "$CANDIDATE_COUNT" -eq 0 ]; then
  log "No candidate URLs with parameters — writing empty dalfox.log"
  note "outcome: no URLs with query parameters to test; dalfox not run"
  rm -f "$TARGET_PREFIX-xss-candidates.log"
  log "Phase complete"
  exit 0
fi

# ─── Reflection check via httpx -mr (replaces kxss — see notes) ────────────────
## kxss (github.com/Emoe/kxss) was found to be non-functional in this
## environment — produces zero output even on --help with exit 0, across
## multiple test cases including known-reflective endpoints (httpbin.org).
## Replaced with httpx's -mr (match-regex against response body) flag:
## append a unique marker as each parameter's value, request the URL, and
## check whether the marker reflects unencoded in the response body.
## httpx is already proven working in this environment (Phase 1: subfinder
## probing, 1986 gau URLs processed successfully).
log "Checking for reflected parameters via httpx -mr"

MARKER="xssChk$(date +%s)"

## The candidate list above is normalised with `qsreplace FUZZ` (every
## parameter value -> FUZZ, which also dedupes URLs by shape); swap that
## placeholder for our unique marker so we can match it in responses.
## NOTE: this used to be `qsreplace -a` with no value. With no value -a is a
## no-op (URLs come out unchanged, no FUZZ anywhere), so the sed below
## replaced nothing, no marker was ever sent, and httpx -mr reported 0
## reflections for every URL on every scan.
cat "$TARGET_PREFIX-xss-candidates.log" \
  | sed "s/FUZZ/${MARKER}/g" \
  | httpx -silent \
          -mr "$MARKER" \
          -timeout 10 \
          -threads 10 \
          -o "$TARGET_PREFIX-kxss.log"

REFLECTED_COUNT=$(wc -l < "$TARGET_PREFIX-kxss.log" 2>/dev/null || echo 0)
log "$REFLECTED_COUNT URLs with reflected marker ('$MARKER')"
note "httpx reflection check: $REFLECTED_COUNT of $CANDIDATE_COUNT candidates reflected the marker"

if [ "$REFLECTED_COUNT" -eq 0 ]; then
  log "No reflected parameters found — writing empty dalfox.log"
  note "outcome: no reflected parameters; dalfox not run"
  rm -f "$TARGET_PREFIX-xss-candidates.log" "$TARGET_PREFIX-kxss.log"
  log "Phase complete"
  exit 0
fi

# ─── Dalfox scan ─────────────────────────────────────────────────────────────────
log "Passing to dalfox"

# Heartbeat — dalfox can take a while on large reflected-param lists, give a
# 60s progress signal independent of dalfox's own output.
( while true; do
    sleep 60
    echo " █▄▄▪ [xss] heartbeat — dalfox still running, $(date +%H:%M:%S)" >> "$PROGRESS_LOG"
  done ) &
HEARTBEAT_PID=$!

cat "$TARGET_PREFIX-kxss.log" \
  | dalfox pipe \
      --silence \
      --no-spinner \
      --skip-bav \
      --timeout 10 \
      --worker 10 \
  >> "$DALFOX_LOG" 2>&1

kill "$HEARTBEAT_PID" 2>/dev/null
wait "$HEARTBEAT_PID" 2>/dev/null

XSS_FINDINGS=$(grep -v '^#' "$DALFOX_LOG" 2>/dev/null | grep -ci "POC\|CONFIRM\|VULN" || true)
XSS_FINDINGS=${XSS_FINDINGS:-0}
note "outcome: dalfox ran against $REFLECTED_COUNT reflected URL(s); $XSS_FINDINGS potential finding(s)"
log "$XSS_FINDINGS potential XSS findings. Output: $TARGET_PREFIX-dalfox.log"

# Cleanup intermediates
rm -f "$TARGET_PREFIX-xss-candidates.log" "$TARGET_PREFIX-kxss.log"

log "Phase complete"
exit 0
