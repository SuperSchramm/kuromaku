#!/bin/bash
## phase-recon.sh — Kuromaku Phase 1: Subdomain Enumeration
## Runs inside the kuromaku-recon container. Writes results to /workspace/scans
## (mounted from projects/<name>/scans on the host).
##
## Usage: phase-recon.sh -d <domain> -t <scan_dir> [--threads N] [--seed host[:port]]
##        phase-recon.sh -dl <domain_list_file> -t <scan_dir> [--threads N]
##
## --seed guarantees an explicit host[:port] survives into uniqdomains.log
## even if subfinder/amass/gau/katana find nothing for it — needed for
## private/internal targets (nothing to publicly index) and targets on a
## non-443 port (katana's own crawl always hits https://$baseDomain, so a
## plain-HTTP or non-standard-port target otherwise never gets probed at
## all). Additive only — discovery still runs as normal; -d/-dl mode only.
## Required outputs (validated by orchestrator):
##   <prefix>-uniqdomains.log
##   <prefix>-domains_only.log
## where <prefix> = domain (or basename of domain_list)

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
    --threads)
      THREADS=$2; shift 2 ;;
    --scope-file)
      SCOPE_FILE=$2; shift 2 ;;
    --seed)
      SEED_TARGET=$2; shift 2 ;;
    *)
      PARAMS="$PARAMS $1"; shift ;;
  esac
done
eval set -- "$PARAMS"

THREADS=${THREADS:-50}

if [ -z "${baseDomain:-}" ] && [ -z "${domain_list:-}" ]; then
  echo "Error: -d <domain> or -dl <domain_list> is required" >&2
  exit 1
fi
if [ -z "${tdir:-}" ]; then
  echo "Error: -t <target_dir> is required" >&2
  exit 1
fi

mkdir -p "$tdir"

# ─── Logger ────────────────────────────────────────────────────────────────────
PROGRESS_LOG="$tdir/kuromaku_progress.log"
log() {
  echo " █▄▄▪ [recon] $1" | tee -a "$PROGRESS_LOG"
}

## Status codes to filter from httpx probes — 401/403 kept for recon value
returnCodes2Ignore="301,302,303,304,307,400,404,429,500,501,502,503,504"

# ─── Scope Filtering ─────────────────────────────────────────────────────────
## Bug bounty programs (Bugcrowd/HackerOne/etc.) provide an explicit in-scope
## domain list. --scope-file restricts ALL discovered domains to that list
## BEFORE uniqdomains.log/domains_only.log are generated — so out-of-scope
## hosts (e.g. third-party domains pulled in by katana's crawl, like
## facebook.com/github.com) never reach network/webscan/xss at all. This is
## both a scope-compliance control and a performance fix (fewer hosts ->
## fewer nuclei requests downstream).
##
## SCOPE_FILE format: one pattern per line, blank lines and lines starting
## with # are ignored. Patterns use shell glob syntax:
##   example.com        — matches ONLY the literal host "example.com"
##   *.example.com       — matches any subdomain (NOT the bare apex)
## To cover both the apex and all subdomains, list both lines. The seed
## domain passed via -d/-dl is NOT automatically added to scope — include it
## explicitly if it should be scanned.

extract_host() {
  ## Given a line that may be a full URL, a "host [status] [title]"-style
  ## httpx line, or a bare hostname, return just the hostname.
  local h="$1"
  h="${h#http://}"; h="${h#https://}"
  h="${h%%[[:space:]]*}"   # drop anything from first whitespace (httpx metadata)
  h="${h%%/*}"             # drop path
  h="${h#www.}"
  case "$h" in *:*) h="${h%:*}" ;; esac  # drop :port
  echo "$h"
}

in_scope() {
  local host="$1"
  while IFS= read -r pattern; do
    pattern="${pattern%$'\r'}"
    [ -z "$pattern" ] && continue
    case "$pattern" in \#*) continue ;; esac
    case "$host" in
      $pattern) return 0 ;;
    esac
  done < "$SCOPE_FILE"
  return 1
}

filter_by_scope() {
  ## Filter a file in place, keeping only lines whose extracted host matches
  ## a pattern in $SCOPE_FILE. No-op if SCOPE_FILE is unset or the file
  ## doesn't exist. If $2 (dropfile) is given, every dropped host is appended
  ## there instead of being discarded — bounty/red-team scope lists are
  ## routinely incomplete, so the out-of-scope hosts recon actually found are
  ## worth keeping for review (did we just miss them in scope, or are they
  ## genuinely third-party?) without stopping or re-running the scan for it.
  local infile="$1"
  local dropfile="${2:-}"
  [ -z "${SCOPE_FILE:-}" ] && return 0
  [ -f "$infile" ] || return 0
  local tmp="${infile}.scoped"
  : > "$tmp"
  local kept=0 total=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    total=$((total + 1))
    host="$(extract_host "$line")"
    if in_scope "$host"; then
      echo "$line" >> "$tmp"
      kept=$((kept + 1))
    elif [ -n "$dropfile" ]; then
      echo "$host" >> "$dropfile"
    fi
  done < "$infile"
  mv "$tmp" "$infile"
  log "Scope filter on $(basename "$infile"): kept $kept of $total"
}

if [ -n "${SCOPE_FILE:-}" ]; then
  if [ ! -f "$SCOPE_FILE" ]; then
    echo "Error: --scope-file specified but not found: $SCOPE_FILE" >&2
    exit 1
  fi
  log "Scope file in use: $SCOPE_FILE"
fi

log "Phase started — threads=$THREADS"

# ─── Subdomain Enumeration ─────────────────────────────────────────────────────
if [ -z "${domain_list:-}" ]; then

  log "Passing to Subfinder"
  subfinder -d "$baseDomain" -silent -all -recursive \
    | httpx -silent -follow-redirects -fc "$returnCodes2Ignore" \
            -timeout 10 -threads "$THREADS" \
            -title -tech-detect -status-code \
            -o "$tdir/$baseDomain-subLister.log"

  log "Passing to Amass"
  amass enum -passive -d "$baseDomain" \
    | httpx -silent -follow-redirects -fc "$returnCodes2Ignore" \
            -timeout 10 -threads "$THREADS" \
            -o "$tdir/$baseDomain-amass.log"

  log "Passing to GAU (Get All URLs)"
  ## gau requires flags BEFORE the positional domain argument
  gau \
    --blacklist "jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt,js" \
    --retries 4 \
    --subs \
    --o "$tdir/$baseDomain-gau-dirty.log" \
    "$baseDomain"

  ## Extract unique hostnames from gau output and probe with httpx
  if [ -f "$tdir/$baseDomain-gau-dirty.log" ]; then
    awk -F/ '{ print $3 }' "$tdir/$baseDomain-gau-dirty.log" \
      | sort -u \
      | grep -v "^$" \
      | sed '/mailto:/d' \
      | httpx -silent -fc "$returnCodes2Ignore" -timeout 10 \
              -o "$tdir/$baseDomain-gau.log"
  else
    log "gau produced no output — skipping httpx probe of gau results"
    touch "$tdir/$baseDomain-gau.log"
  fi

  log "Passing to Katana (JS-aware crawler)"
  ## katana -d is crawl DEPTH (int), not domain — use -u for URL input
  katana -u "https://$baseDomain" \
    -depth 3 \
    -silent \
    -jc \
    -kf all \
    -ef "woff,css,png,svg,jpg,woff2,jpeg,gif,svg" \
    -o "$tdir/$baseDomain-katana.log" 2>/dev/null || log "katana found no results — continuing"

  ## Carry katana's raw crawled URLs (full URL incl. path/query, not just the
  ## hostname) into gau-dirty.log too. Phase 4 (XSS) builds its candidate list
  ## from gau-dirty.log alone, which is pure Wayback/URLScan/OTX history and
  ## always empty for a private/non-indexed target — but katana's own crawl
  ## (-jc) finds real parameterized endpoints there. touch first so this is
  ## safe whether or not gau itself produced output.
  touch "$tdir/$baseDomain-gau-dirty.log"
  [ -f "$tdir/$baseDomain-katana.log" ] && cat "$tdir/$baseDomain-katana.log" >> "$tdir/$baseDomain-gau-dirty.log"

  log "Merging and deduplicating found domains"
  true > "$tdir/$baseDomain-predomains.log"
  [ -f "$tdir/$baseDomain-subLister.log" ]  && cat "$tdir/$baseDomain-subLister.log"  >> "$tdir/$baseDomain-predomains.log"
  [ -f "$tdir/$baseDomain-amass.log" ]      && cat "$tdir/$baseDomain-amass.log"      >> "$tdir/$baseDomain-predomains.log"
  [ -f "$tdir/$baseDomain-gau.log" ]        && cat "$tdir/$baseDomain-gau.log"        >> "$tdir/$baseDomain-predomains.log"
  [ -f "$tdir/$baseDomain-katana.log" ]     && awk -F/ '{print $3}' "$tdir/$baseDomain-katana.log" >> "$tdir/$baseDomain-predomains.log"

  ## Explicit seed target (--seed): guarantees it survives into
  ## uniqdomains.log/domains_only.log even if discovery found nothing for it
  ## at all (private target, nothing publicly indexed). Additive, not a
  ## replacement — written straight into predomains.log alongside whatever
  ## subfinder/amass/gau/katana found, so it goes through the same
  ## scope-filter/normalize/dedup pipeline as everything else below.
  if [ -n "${SEED_TARGET:-}" ]; then
    echo "$SEED_TARGET" >> "$tdir/$baseDomain-predomains.log"
    log "Seeded explicit target: $SEED_TARGET"
  fi

  ## Restrict to in-scope hosts BEFORE dedup/normalization, so out-of-scope
  ## domains (e.g. third-party links katana crawled) never enter
  ## uniqdomains.log/domains_only.log or any downstream phase. Dropped hosts
  ## are captured once, from the merged predomains list, into
  ## out-of-scope.log for later review — not from gau-dirty.log too, which
  ## would just duplicate the same hosts from raw URLs.
  OUT_OF_SCOPE_FILE="$tdir/$baseDomain-out-of-scope.log"
  [ -n "${SCOPE_FILE:-}" ] && : > "$OUT_OF_SCOPE_FILE"
  filter_by_scope "$tdir/$baseDomain-predomains.log" "$OUT_OF_SCOPE_FILE"
  filter_by_scope "$tdir/$baseDomain-gau-dirty.log"
  if [ -n "${SCOPE_FILE:-}" ] && [ -s "$OUT_OF_SCOPE_FILE" ]; then
    sort -u -o "$OUT_OF_SCOPE_FILE" "$OUT_OF_SCOPE_FILE"
    log "$(wc -l < "$OUT_OF_SCOPE_FILE") out-of-scope host(s) dropped — see $(basename "$OUT_OF_SCOPE_FILE")"
  fi

  ## Normalize: strip scheme, www, ports, paths, whitespace
  sed -E 's|^\s*https?://||g' "$tdir/$baseDomain-predomains.log" \
    | sed 's|www\.||g' \
    | sed 's|:80$||g; s|:443$||g' \
    | sed 's|/.*||g' \
    | sed '/^$/d' \
    | sort -u \
    | anew "$tdir/$baseDomain-uniqdomains.log" > /dev/null

  domainCOUNT=$(wc -l < "$tdir/$baseDomain-uniqdomains.log")

  sed -E 's|^\s*https?://||g' "$tdir/$baseDomain-uniqdomains.log" \
    | sed 's|/.*||g' \
    | sort -u > "$tdir/$baseDomain-domains_only.log"

  log "$domainCOUNT unique domains found"
  log "Output: $tdir/$baseDomain-uniqdomains.log"

else
  ## Domain list mode
  daBase="$(basename "$domain_list")"

  if [ -n "${SCOPE_FILE:-}" ]; then
    filtered_list="$tdir/${daBase}.scoped"
    cp "$domain_list" "$filtered_list"
    OUT_OF_SCOPE_FILE="$tdir/$daBase-out-of-scope.log"
    : > "$OUT_OF_SCOPE_FILE"
    filter_by_scope "$filtered_list" "$OUT_OF_SCOPE_FILE"
    domain_list="$filtered_list"
    if [ -s "$OUT_OF_SCOPE_FILE" ]; then
      sort -u -o "$OUT_OF_SCOPE_FILE" "$OUT_OF_SCOPE_FILE"
      log "$(wc -l < "$OUT_OF_SCOPE_FILE") out-of-scope host(s) dropped — see $(basename "$OUT_OF_SCOPE_FILE")"
    fi
  fi

  httpx -l "$domain_list" -silent -fc "$returnCodes2Ignore" \
        -timeout 10 -threads "$THREADS" \
        -title -tech-detect -status-code \
        -o "$tdir/$daBase-uniqdomains.log"

  domainCOUNT=$(wc -l < "$tdir/$daBase-uniqdomains.log")

  sed -E 's|^\s*https?://||g' "$tdir/$daBase-uniqdomains.log" \
    | sed 's|/.*||g' \
    | sort -u > "$tdir/$daBase-domains_only.log"

  log "$domainCOUNT domains probed"
  log "Output: $tdir/$daBase-uniqdomains.log"
fi

## Cleanup intermediate files (keep gau-dirty.log — phase 4 XSS needs it)
[ -f "$tdir/${baseDomain:-$daBase}-predomains.log" ] && rm "$tdir/${baseDomain:-$daBase}-predomains.log"

log "Phase complete"
exit 0
