#!/bin/bash
## phase-report.sh — Kuromaku Phase 5: Report Generation
## Thin wrapper around phase-report.py — keeps consistent CLI/logging with
## other phases (-d/-dl, -t, progress log).
##
## Usage: phase-report.sh -d <domain> -t <scan_dir> [--llm-url URL] [--llm-model NAME]
##
## Output: <prefix>-report.docx

set -uo pipefail

PARAMS=""
LLM_ARGS=""
while (( "$#" )); do
  case "$1" in
    -d|--domain)        baseDomain=$2; shift 2 ;;
    -dl|--domain_list)  domain_list=$2; shift 2 ;;
    -t|--target-dir)    tdir=$2; shift 2 ;;
    --llm-url)          LLM_ARGS="$LLM_ARGS --llm-url $2"; shift 2 ;;
    --llm-model)        LLM_ARGS="$LLM_ARGS --llm-model $2"; shift 2 ;;
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
  python3 /usr/local/bin/phase-report.py -d "$baseDomain" -t "$tdir" $LLM_ARGS 2>&1 | tee -a "$PROGRESS_LOG"
else
  python3 /usr/local/bin/phase-report.py -dl "$domain_list" -t "$tdir" $LLM_ARGS 2>&1 | tee -a "$PROGRESS_LOG"
fi

log "Phase complete"
exit 0
