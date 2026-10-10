#!/bin/bash
## phase-report.sh — Kuromaku Phase 5: Report Generation
## Thin wrapper around phase-report.py — keeps consistent CLI/logging with
## other phases (-d/-dl, -t, progress log).
##
## Usage: phase-report.sh -d <domain> -t <scan_dir> [--llm-url URL] [--llm-model NAME]
##                         [--team-name NAME] [--client-name NAME]
##
## Output: <prefix>-report.docx

set -uo pipefail

PARAMS=""
# Array, not a string — team-name/client-name routinely contain spaces
# ("Acme Corporation"), and the old string-based LLM_ARGS pattern relied on
# unquoted word-splitting at the call site, which would silently mangle any
# value with a space into multiple args.
EXTRA_ARGS=()
while (( "$#" )); do
  case "$1" in
    -d|--domain)        baseDomain=$2; shift 2 ;;
    -dl|--domain_list)  domain_list=$2; shift 2 ;;
    -t|--target-dir)    tdir=$2; shift 2 ;;
    --llm-url)          EXTRA_ARGS+=(--llm-url "$2"); shift 2 ;;
    --llm-model)        EXTRA_ARGS+=(--llm-model "$2"); shift 2 ;;
    --team-name)        EXTRA_ARGS+=(--team-name "$2"); shift 2 ;;
    --client-name)      EXTRA_ARGS+=(--client-name "$2"); shift 2 ;;
    *) PARAMS="$PARAMS $1"; shift ;;
  esac
done
eval set -- "$PARAMS"

PROGRESS_LOG="$tdir/kuromaku_progress.log"
log() { echo " █▄▄▪ [report] $1" | tee -a "$PROGRESS_LOG"; }

if [ -z "${baseDomain:-}" ] && [ -z "${domain_list:-}" ]; then
  echo "Error: -d <domain> or -dl <domain_list> is required" >&2
  exit 1
fi
if [ -z "${tdir:-}" ]; then
  echo "Error: -t <target_dir> is required" >&2
  exit 1
fi

log "Phase started"

if [ -n "${baseDomain:-}" ]; then
  python3 /usr/local/bin/phase-report.py -d "$baseDomain" -t "$tdir" "${EXTRA_ARGS[@]}" 2>&1 | tee -a "$PROGRESS_LOG"
else
  python3 /usr/local/bin/phase-report.py -dl "$domain_list" -t "$tdir" "${EXTRA_ARGS[@]}" 2>&1 | tee -a "$PROGRESS_LOG"
fi

log "Phase complete"
exit 0
