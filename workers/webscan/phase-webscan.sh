#!/bin/bash
## phase-webscan.sh — Kuromaku Phase 3: Web Asset Scanning
## Runs inside the kuromaku-webscan container. Reads uniqdomains.log and
## unique-ips.log from Phases 1-2. Writes nucleiAlerts.log, nmapvulners.log,
## dirsearch.log.
##
## Usage: phase-webscan.sh -d <domain> -t <scan_dir> [--threads N] [--skip-nuclei]
##        phase-webscan.sh -dl <domain_list_file> -t <scan_dir> [...]
##
## REQUIRED docker run flags (8GB Mac Mini M4 — enforced by orchestrator):
##   --cap-add NET_RAW
##   --memory=3g --memory-swap=3g
## Without the memory cap, nuclei/dirsearch/nmap running concurrently against
## many hosts can exhaust host RAM and cause full system lockup (observed: ~1hr
## into a 49-domain scan, required hard power cycle).
##
## Tunable via environment (orchestrator may override per-project):
##   NUCLEI_BULK_SIZE, NUCLEI_CONCURRENCY, NUCLEI_RATE_LIMIT, NUCLEI_BATCH_TIMEOUT,
##   WEB_TARGET_CAP (CIDR mode only — caps how many ip:port web targets a single
##   run will scan with nuclei/dirsearch; default 500)
##
## CIDR mode: nuclei/dirsearch run too (against bare ip:port targets) IF the
## network phase's webports.log has any entries, built from naabu's own open-
## port results — not skipped unconditionally like recon/xss, which actually
## do require a hostname.
##
## Required inputs (from Phases 1-2):
##   <prefix>-uniqdomains.log
##   <prefix>-unique-ips.log
##
## Required outputs (validated by orchestrator):
##   <prefix>-nucleiAlerts.log   (unless --skip-nuclei)
##   <prefix>-nmapvulners.log
##   <prefix>-dirsearch.log

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
    --skip-nuclei)
      SKIP_NUCLEI=1; shift ;;
    --cidr)
      cidr_input=$2; shift 2 ;;
    *)
      PARAMS="$PARAMS $1"; shift ;;
  esac
done
eval set -- "$PARAMS"

THREADS=${THREADS:-10}
SKIP_NUCLEI=${SKIP_NUCLEI:-0}

if [ -z "${baseDomain:-}" ] && [ -z "${domain_list:-}" ] && [ -z "${cidr_input:-}" ]; then
  echo "Error: -d <domain>, -dl <domain_list>, or --cidr <CIDR/IP/file> is required" >&2
  exit 1
fi
if [ -z "${tdir:-}" ]; then
  echo "Error: -t <target_dir> is required" >&2
  exit 1
fi

# ─── Logger ────────────────────────────────────────────────────────────────────
PROGRESS_LOG="$tdir/kuromaku_progress.log"
log() {
  echo " █▄▄▪ [webscan] $1" | tee -a "$PROGRESS_LOG"
}

## Status codes excluded from dirsearch results
returnCodes2Ignore="301,302,303,304,307,400,404,429,500,501,502,503,504"

# ─── Resolve prefix and input files ────────────────────────────────────────────
if [ -n "${cidr_input:-}" ]; then
  # Same prefix-derivation as phase-network.sh's CIDR mode — must match so
  # this phase finds the unique-ips.log that network already produced. Derive
  # from the target's SHAPE (bare IP/CIDR -> raw; otherwise -> basename), not
  # from file existence, so the two phases agree even if the list file isn't
  # mounted this time. Mirrors the orchestrator's cidrPrefix().
  is_ip_or_cidr() { printf '%s' "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; }
  if is_ip_or_cidr "$cidr_input"; then
    raw_prefix="$cidr_input"
  else
    raw_prefix="$(basename "$cidr_input")"
  fi
  TARGET_PREFIX="$tdir/$(echo "$raw_prefix" | tr '/.' '_-')"
elif [ -z "${domain_list:-}" ]; then
  TARGET_PREFIX="$tdir/$baseDomain"
else
  daBase="$(basename "$domain_list")"
  TARGET_PREFIX="$tdir/$daBase"
fi

UNIQ_DOMAINS_FILE="${TARGET_PREFIX}-uniqdomains.log"
UNIQUE_IPS_FILE="${TARGET_PREFIX}-unique-ips.log"

if [ -z "${cidr_input:-}" ] && [ ! -f "$UNIQ_DOMAINS_FILE" ]; then
  echo "Error: required input file not found: $UNIQ_DOMAINS_FILE (did Phase 1 run first?)" >&2
  exit 1
fi
if [ -n "${cidr_input:-}" ] && [ ! -f "$UNIQUE_IPS_FILE" ]; then
  echo "Error: required input file not found: $UNIQUE_IPS_FILE (did network phase --cidr run first?)" >&2
  exit 1
fi

log "Phase started — threads=$THREADS"

## dnsx/nuclei/naabu ignore Docker's embedded DNS proxy by default.
## Extract actual nameserver from /etc/resolv.conf and pass explicitly.
DOCKER_DNS=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)
if [ -z "$DOCKER_DNS" ]; then
  log "Could not detect Docker DNS resolver — falling back to 8.8.8.8,1.1.1.1"
  DOCKER_DNS="8.8.8.8,1.1.1.1"
else
  log "Using Docker DNS resolver: $DOCKER_DNS"
fi

## CIDR mode: nuclei and dirsearch both accept bare ip:port targets natively
## (no hostname required) — the tools that actually CAN'T run without a
## hostname are subfinder/amass/gau (recon-phase, already skipped). So build
## an http(s)://ip:port target list from whatever web ports the network
## phase found open (webports.log — see phase-network.sh), instead of
## unconditionally skipping nuclei/dirsearch for every CIDR scan. Built once
## here, used by both the nuclei and dirsearch sections below.
WEB_TARGETS_FILE="$TARGET_PREFIX-web-targets.log"
if [ -n "${cidr_input:-}" ]; then
  WEBPORTS_FILE="$TARGET_PREFIX-webports.log"
  : > "$WEB_TARGETS_FILE"
  if [ -s "$WEBPORTS_FILE" ]; then
    while IFS= read -r hostport; do
      [ -z "$hostport" ] && continue
      port="${hostport##*:}"
      case "$port" in
        443|8443|9443|10010) scheme="https" ;;
        *) scheme="http" ;;
      esac
      echo "${scheme}://${hostport}" >> "$WEB_TARGETS_FILE"
    done < "$WEBPORTS_FILE"

    ## Resource-cap note (CLAUDE.md): nuclei against many ip:port targets is
    ## just as RAM-heavy as the domain-mode run that already needed 3-way
    ## batching to avoid a full system lockup. A large CIDR range with lots
    ## of open web ports could multiply that out badly, so cap how many
    ## targets a single CIDR webscan run will throw at nuclei/dirsearch.
    WEB_TARGET_CAP=${WEB_TARGET_CAP:-500}
    WEB_TARGET_COUNT=$(wc -l < "$WEB_TARGETS_FILE")
    if [ "$WEB_TARGET_COUNT" -gt "$WEB_TARGET_CAP" ]; then
      log "WARNING: $WEB_TARGET_COUNT web target(s) found, capping to $WEB_TARGET_CAP (set WEB_TARGET_CAP to override) to avoid overloading nuclei/dirsearch"
      head -n "$WEB_TARGET_CAP" "$WEB_TARGETS_FILE" > "$WEB_TARGETS_FILE.capped"
      mv "$WEB_TARGETS_FILE.capped" "$WEB_TARGETS_FILE"
    fi
  fi
fi

# ─── Nuclei Vulnerability Scan ──────────────────────────────────────────────────
## Resource-constrained default (8GB Mac Mini M4): nuclei is the heaviest single
## consumer in this phase. Splitting into smaller sequential tag batches with
## reduced concurrency keeps peak memory bounded and gives incremental progress
## log entries instead of one multi-hour black box.
NUCLEI_BULK_SIZE=${NUCLEI_BULK_SIZE:-5}
NUCLEI_CONCURRENCY=${NUCLEI_CONCURRENCY:-5}
NUCLEI_RATE_LIMIT=${NUCLEI_RATE_LIMIT:-25}
## Hard cap per tag batch (seconds). A batch that hits it is logged and skipped
## so one slow batch can't hold the whole phase for hours; partial findings
## already written to the batch file are kept.
NUCLEI_BATCH_TIMEOUT=${NUCLEI_BATCH_TIMEOUT:-2700}

## Runs resource-capped nuclei batches against $1 (a target list — hostnames
## for domain mode, ip:port URLs for CIDR mode), accumulating results into
## $TARGET_PREFIX-nucleiAlerts.log. Any args after $1 are passed straight
## through to nuclei (domain mode adds -r <resolver file>; CIDR mode passes
## nothing extra — raw IPs need no DNS resolution). Same batching/heartbeat/
## timeout pattern for both modes — do not revert to one unbatched run
## (CLAUDE.md: caused a full system lockup once).
##
## Batches by TEMPLATE DIRECTORY (-t <dir>/), not -tags — full coverage
## across all 14 of nuclei-templates' top-level categories, matching the
## breadth of the pre-kuromaku bash workflow this replaced (deliberately NOT
## narrowed by -severity or -etags either: directories like technologies/
## and exposed-panels/ are dominated by info/low-severity findings that a
## severity filter would have silently thrown away, defeating the point of
## including them). This is intentionally slow and thorough, not a quick
## scan — expect nuclei to be the long pole in webscan again, same as the
## original script.
run_nuclei_batches() {
  local target_list="$1"; shift
  local extra_args=("$@")

  true > "$TARGET_PREFIX-nuclei.log"

  # Grouped into batches (not one unbatched run across all 14 dirs) so a
  # kill/OOM/timeout mid-run loses at most one batch worth of work, and the
  # progress log gets incremental updates instead of one multi-hour black box.
  local NUCLEI_BATCHES=(
    "dns cves exposures"
    "technologies misconfiguration default-logins"
    "network takeovers exposed-panels"
    "iot fuzzing miscellaneous"
    "headless vulnerabilities"
  )

  for batch_dirs in "${NUCLEI_BATCHES[@]}"; do
    local batch_label="${batch_dirs// /,}"
    log "Nuclei batch: $batch_label"

    local TEMPLATE_ARGS=()
    for d in $batch_dirs; do
      TEMPLATE_ARGS+=(-t "${d}/")
    done

    # Heartbeat fallback — guarantees a progress-log line every 60s even if
    # nuclei's own -stats output stalls on a slow host. Killed once nuclei exits.
    ( while true; do
        sleep 60
        echo " █▄▄▪ [webscan] heartbeat — nuclei batch '$batch_label' still running, $(date +%H:%M:%S), $(wc -l < "$TARGET_PREFIX-nuclei-batch.log" 2>/dev/null || echo 0) findings so far" | tee -a "$PROGRESS_LOG"
      done ) &
    HEARTBEAT_PID=$!

    ## -stats + -stats-interval prints periodic progress (% complete, req/sec,
    ## hosts scanned) to stderr. Redirecting 2>&1 into the progress log gives a
    ## real-time view of nuclei's actual progress, not just a heartbeat.
    timeout "$NUCLEI_BATCH_TIMEOUT" nuclei -l "$target_list" \
      "${TEMPLATE_ARGS[@]}" \
      -rate-limit "$NUCLEI_RATE_LIMIT" \
      -bulk-size "$NUCLEI_BULK_SIZE" \
      -concurrency "$NUCLEI_CONCURRENCY" \
      -timeout 10 \
      -retries 2 \
      "${extra_args[@]}" \
      -stats \
      -stats-interval 15 \
      -silent \
      -o "$TARGET_PREFIX-nuclei-batch.log" 2>&1 | \
      sed -u "s/^/ █▄▄▪ [webscan] [nuclei:$batch_label] /" | tee -a "$PROGRESS_LOG"

    NUCLEI_RC=${PIPESTATUS[0]}
    kill "$HEARTBEAT_PID" 2>/dev/null
    wait "$HEARTBEAT_PID" 2>/dev/null
    if [ "$NUCLEI_RC" -eq 143 ] || [ "$NUCLEI_RC" -eq 124 ]; then
      log "Batch '$batch_label' hit the ${NUCLEI_BATCH_TIMEOUT}s timeout — keeping partial findings, moving on"
    fi

    if [ -f "$TARGET_PREFIX-nuclei-batch.log" ]; then
      cat "$TARGET_PREFIX-nuclei-batch.log" >> "$TARGET_PREFIX-nuclei.log"
      BATCH_COUNT=$(wc -l < "$TARGET_PREFIX-nuclei-batch.log")
      rm "$TARGET_PREFIX-nuclei-batch.log"
      log "Batch '$batch_label' complete — $BATCH_COUNT findings"
    fi
  done

  grep -v "^$" "$TARGET_PREFIX-nuclei.log" > "$TARGET_PREFIX-nucleiAlerts.log" 2>/dev/null || \
    touch "$TARGET_PREFIX-nucleiAlerts.log"

  NUCLEI_FINDINGS=$(wc -l < "$TARGET_PREFIX-nucleiAlerts.log")
  log "$NUCLEI_FINDINGS total nuclei findings. Output: $TARGET_PREFIX-nucleiAlerts.log"
}

if [ -n "${cidr_input:-}" ]; then
  if [ -s "$WEB_TARGETS_FILE" ]; then
    WEB_TARGET_COUNT=$(wc -l < "$WEB_TARGETS_FILE")
    log "CIDR mode — $WEB_TARGET_COUNT web target(s) found (bulk-size=$NUCLEI_BULK_SIZE concurrency=$NUCLEI_CONCURRENCY rate-limit=$NUCLEI_RATE_LIMIT), running nuclei"
    run_nuclei_batches "$WEB_TARGETS_FILE"
  else
    log "CIDR mode — no web ports found among naabu's open ports, skipping nuclei"
    touch "$TARGET_PREFIX-nucleiAlerts.log"
  fi
elif [ "$SKIP_NUCLEI" -eq 0 ]; then
  log "Passing to Nuclei (batched — bulk-size=$NUCLEI_BULK_SIZE concurrency=$NUCLEI_CONCURRENCY rate-limit=$NUCLEI_RATE_LIMIT)"
  ## nuclei's -r flag expects a FILE PATH containing resolver IPs (one per line),
  ## unlike dnsx/naabu which accept inline comma-separated IPs.
  RESOLVER_FILE="/tmp/resolvers.txt"
  echo "$DOCKER_DNS" | tr ',' '\n' > "$RESOLVER_FILE"
  run_nuclei_batches "$UNIQ_DOMAINS_FILE" -r "$RESOLVER_FILE"
else
  log "Skipping nuclei (--skip-nuclei)"
  touch "$TARGET_PREFIX-nucleiAlerts.log"
fi

# ─── Nmap Vulners Scan ───────────────────────────────────────────────────────────
## Service/vuln-scan ONLY what naabu already found open, not every port on every
## host. naabu is the port scanner; feeding nmap its open host:port set turns a
## (hosts × ~1000 default ports) -Pn sweep — which takes hours-to-days and
## emits endless "RTTVAR has grown" timing backoffs on large/filtered ranges —
## into (open hosts × the few open ports). Falls back to the full unique-ips
## list only if naabu produced nothing. --host-timeout bounds any single stuck
## host; --stats-every streams real progress (% done, ETA) into the progress log.
log "Nmap vulnerability scan"
NAABU_FILE="$TARGET_PREFIX-naabu.log"
NMAP_HOSTS_FILE="$TARGET_PREFIX-nmap-hosts.txt"
NMAP_PORTS=""
if [ -s "$NAABU_FILE" ]; then
  cut -d: -f1 "$NAABU_FILE" | sort -u > "$NMAP_HOSTS_FILE"
  NMAP_PORTS=$(cut -d: -f2 "$NAABU_FILE" | grep -E '^[0-9]+$' | sort -un | paste -sd, -)
else
  # No naabu hits — fall back to the raw target list (bounded by --host-timeout).
  cp "$UNIQUE_IPS_FILE" "$NMAP_HOSTS_FILE" 2>/dev/null || : > "$NMAP_HOSTS_FILE"
fi
HOST_COUNT=$(wc -l < "$NMAP_HOSTS_FILE" 2>/dev/null || echo 0)

if [ "$HOST_COUNT" -gt 0 ]; then
  if [ -n "$NMAP_PORTS" ]; then
    PORT_ARGS=(-p "$NMAP_PORTS")
    log "Scoping nmap to naabu results: $HOST_COUNT host(s), ports $NMAP_PORTS"
  else
    PORT_ARGS=()
    log "No naabu port data — nmap default ports on $HOST_COUNT host(s)"
  fi

  # Heartbeat so the progress log never goes silent even if nmap's own stats stall.
  ( while true; do
      sleep 60
      echo " █▄▄▪ [webscan] heartbeat — nmap still running ($HOST_COUNT hosts), $(date +%H:%M:%S)" | tee -a "$PROGRESS_LOG"
    done ) &
  NMAP_HEARTBEAT_PID=$!

  # -oN writes the report to the file; stdout (incl. --stats-every progress) is
  # tagged into the progress log for live visibility.
  nmap -sV --script vulners \
       --open \
       -Pn \
       -T4 \
       --min-parallelism 10 \
       --host-timeout 5m \
       --stats-every 30s \
       "${PORT_ARGS[@]}" \
       --dns-servers "$DOCKER_DNS" \
       -oN "$TARGET_PREFIX-nmapvulners.log" \
       -iL "$NMAP_HOSTS_FILE" 2>&1 \
    | sed "s/^/ █▄▄▪ [webscan] [nmap] /" >> "$PROGRESS_LOG"

  kill "$NMAP_HEARTBEAT_PID" 2>/dev/null
  wait "$NMAP_HEARTBEAT_PID" 2>/dev/null
  log "Output: $TARGET_PREFIX-nmapvulners.log"
else
  log "No hosts to scan — skipping nmap"
  echo "# No hosts to scan" > "$TARGET_PREFIX-nmapvulners.log"
fi

# ─── Dirsearch Brute Force ────────────────────────────────────────────────────────
if [ -n "${cidr_input:-}" ]; then
  if [ -s "$WEB_TARGETS_FILE" ]; then
    log "CIDR mode — running dirsearch against $(wc -l < "$WEB_TARGETS_FILE") web target(s)"
    DIRSEARCH_TARGETS="$WEB_TARGETS_FILE"
  else
    log "CIDR mode — no web ports found among naabu's open ports, skipping dirsearch"
    touch "$TARGET_PREFIX-dirsearch.log"
    DIRSEARCH_TARGETS=""
  fi
else
  log "Directory brute-force with dirsearch"
  DIRSEARCH_TARGETS="$UNIQ_DOMAINS_FILE"
fi

if [ -n "$DIRSEARCH_TARGETS" ]; then
  ## Try modern flag first, fall back to older --output flag if version mismatch
  dirsearch -l "$DIRSEARCH_TARGETS" \
    --exclude-status="$returnCodes2Ignore" \
    -e php,asp,aspx,jsp,html,js,json,xml,conf,config,bak,old,txt \
    -f \
    -t "$THREADS" \
    -o "$TARGET_PREFIX-dirsearch.log" \
    --format=plain \
    --quiet 2>/dev/null || \
  dirsearch -l "$DIRSEARCH_TARGETS" \
    --exclude-status="$returnCodes2Ignore" \
    -e php,asp,aspx,jsp,html,js,json,xml,conf,config,bak,old,txt \
    -f \
    -t "$THREADS" \
    --output="$TARGET_PREFIX-dirsearch.log" \
    --quiet 2>/dev/null || \
  log "dirsearch flag mismatch — check installed version"

  touch "$TARGET_PREFIX-dirsearch.log"
fi
log "Output: $TARGET_PREFIX-dirsearch.log"

log "Phase complete"
exit 0
