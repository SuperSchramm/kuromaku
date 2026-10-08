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

if [ ! -f "$GAU_DIRTY" ]; then
  log "No gau-dirty.log found (did Phase 1 / recon run first?) — writing empty dalfox.log"
  touch "$TARGET_PREFIX-dalfox.log"
  log "Phase complete"
  exit 0
fi

# ─── Build XSS candidate URL list ───────────────────────────────────────────────
log "Building XSS candidate URL list"
CANDIDATE_COUNT=$(cat "$GAU_DIRTY" \
  | qsreplace -a \
  | grep "=" \
  | grep -Eiv "\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)$" \
  | sort -u \
  | tee "$TARGET_PREFIX-xss-candidates.log" \
  | wc -l)

log "$CANDIDATE_COUNT candidate URLs with parameters"

if [ "$CANDIDATE_COUNT" -eq 0 ]; then
  log "No candidate URLs with parameters — writing empty dalfox.log"
  touch "$TARGET_PREFIX-dalfox.log"
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

## qsreplace -a sets every parameter value to "FUZZ" by default; replace that
## placeholder with our unique marker so we can grep for it in responses.
cat "$TARGET_PREFIX-xss-candidates.log" \
  | sed "s/FUZZ/${MARKER}/g" \
  | httpx -silent \
          -mr "$MARKER" \
          -timeout 10 \
          -threads 10 \
          -o "$TARGET_PREFIX-kxss.log"

REFLECTED_COUNT=$(wc -l < "$TARGET_PREFIX-kxss.log" 2>/dev/null || echo 0)
log "$REFLECTED_COUNT URLs with reflected marker ('$MARKER')"

if [ "$REFLECTED_COUNT" -eq 0 ]; then
  log "No reflected parameters found — writing empty dalfox.log"
  touch "$TARGET_PREFIX-dalfox.log"
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
  > "$TARGET_PREFIX-dalfox.log" 2>&1

kill "$HEARTBEAT_PID" 2>/dev/null
wait "$HEARTBEAT_PID" 2>/dev/null

XSS_FINDINGS=$(grep -ci "POC\|CONFIRM\|VULN" "$TARGET_PREFIX-dalfox.log" 2>/dev/null || echo 0)
log "$XSS_FINDINGS potential XSS findings. Output: $TARGET_PREFIX-dalfox.log"

# Cleanup intermediates
rm -f "$TARGET_PREFIX-xss-candidates.log" "$TARGET_PREFIX-kxss.log"

log "Phase complete"
exit 0
