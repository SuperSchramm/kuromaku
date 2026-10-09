#!/bin/bash
## phase-network.sh — Kuromaku Phase 2: Network Enumeration
## Runs inside the kuromaku-network container. Reads domains_only.log produced
## by Phase 1 (recon), writes resolved.log, unique-ips.log, naabu*.log.
##
## Usage: phase-network.sh -d <domain> -t <scan_dir>
##        phase-network.sh -dl <domain_list_file> -t <scan_dir>
##
## Required input (from Phase 1):
##   <prefix>-domains_only.log
##
## Required outputs (validated by orchestrator):
##   <prefix>-resolved.log
##   <prefix>-unique-ips.log
##   <prefix>-naabu.log

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
    --cidr)
      cidr_input=$2; shift 2 ;;
    *)
      PARAMS="$PARAMS $1"; shift ;;
  esac
done
eval set -- "$PARAMS"

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
  echo " █▄▄▪ [network] $1" | tee -a "$PROGRESS_LOG"
}

## Ports to scan — same set as v1, plus a few more common web-app ports
## (9000, 10000, 10010, 10020) that CIDR mode's web-port detection (below)
## checks against.
portsIcareAbout="80,443,21,22,23,3306,8080,8443,8000,8888,9090,9443,9000,10000,10010,10020"
## Subset of the above that's actually a web port — used only in CIDR mode
## to decide whether webscan's nuclei/dirsearch steps have anything to point
## at (see webports.log below). Not every scanned port is a web port (22,
## 23, 3306 aren't), so this can't just be portsIcareAbout verbatim.
webPorts="80,443,8080,8443,9000,9090,10000,10010,10020"

# ─── CIDR MODE ──────────────────────────────────────────────────────────────────
## IP-range scanning bypasses the domain-based pipeline entirely. Input can be
## a single CIDR (206.130.144.0/24), a single IP, or a path to a file with one
## CIDR/IP per line. naabu accepts CIDR/IP/file natively via -list or -host —
## no dnsx resolution step needed (there are no hostnames to resolve).
if [ -n "${cidr_input:-}" ]; then
  # True for a bare IPv4 or IPv4 CIDR (e.g. 10.0.0.5 or 206.130.144.0/24).
  is_ip_or_cidr() { printf '%s' "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; }

  # Output-file prefix MUST match the orchestrator's cidrPrefix(): the raw
  # string for a bare IP/CIDR, the basename for a file-path target. Derive it
  # from the target's SHAPE, not from whether the file currently exists —
  # otherwise a missing/mis-mounted list shifts every output name to the
  # full-path form and the orchestrator reports "missing expected outputs" for
  # files that were in fact written.
  if is_ip_or_cidr "$cidr_input"; then
    raw_prefix="$cidr_input"
  else
    raw_prefix="$(basename "$cidr_input")"
  fi
  TARGET_PREFIX="$tdir/$(echo "$raw_prefix" | tr '/.' '_-')"

  # naabu input mode is a separate decision: a real file -> -list; a bare
  # IP/CIDR -> -host. A path-shaped target that isn't present under
  # /workspace/scans is almost certainly a caller mistake (pass `ips` or place
  # the file in the scan dir) — warn loudly rather than scan a literal path.
  if [ -f "$cidr_input" ]; then
    NAABU_INPUT_ARGS=(-list "$cidr_input")
  elif is_ip_or_cidr "$cidr_input"; then
    NAABU_INPUT_ARGS=(-host "$cidr_input")
  else
    log "WARNING: target '$cidr_input' is neither a file in /workspace/scans nor a bare IP/CIDR — nothing to scan. Pass targets via the ips array or place the list in the scan dir."
    NAABU_INPUT_ARGS=(-host "$cidr_input")
  fi

  log "Phase started (CIDR mode: ${cidr_input})"

  # No DNS resolution in CIDR mode — resolved.log is empty/placeholder so
  # the orchestrator's required-output check for "resolved.log" still passes.
  touch "$TARGET_PREFIX-resolved.log"
  log "CIDR mode — skipping DNS resolution (no hostnames)"

  # unique-ips.log: nmap -iL and naabu -list both accept CIDR notation
  # directly, so for a single CIDR/IP input we write the CIDR itself rather
  # than expanding to individual IPs (prips not available in Alpine). For a
  # FILE of targets we copy its contents (one IP/CIDR per line) — writing the
  # path string here instead was the "0 IPs" bug: nmap -iL then read a single
  # path line as a target and scanned nothing.
  if [ -f "$cidr_input" ]; then
    grep -vE '^\s*(#|$)' "$cidr_input" > "$TARGET_PREFIX-unique-ips.log" || true
  else
    echo "$cidr_input" > "$TARGET_PREFIX-unique-ips.log"
  fi
  IP_COUNT=$(wc -l < "$TARGET_PREFIX-unique-ips.log")
  log "$IP_COUNT range(s)/IP(s) recorded — Output: $TARGET_PREFIX-unique-ips.log"

  log "Port scanning with naabu"
  naabu "${NAABU_INPUT_ARGS[@]}" \
        -p "$portsIcareAbout" \
        -rate 1000 \
        -timeout 10 \
        -silent \
        -o "$TARGET_PREFIX-naabu.log"
  touch "$TARGET_PREFIX-naabu.log"

  grep ":80$"   "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_80.log"   2>/dev/null || true
  grep ":443$"  "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_443.log"  2>/dev/null || true
  grep ":22$"   "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_22.log"   2>/dev/null || true
  grep ":23$"   "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_23.log"   2>/dev/null || true
  grep ":8080$" "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_8080.log" 2>/dev/null || true
  grep ":8443$" "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_8443.log" 2>/dev/null || true

  OPEN_PORTS=$(wc -l < "$TARGET_PREFIX-naabu.log")
  log "$OPEN_PORTS open host:port combinations found"
  log "Output: $TARGET_PREFIX-naabu.log"

  ## Web-port detection: nuclei and dirsearch both accept bare ip:port
  ## targets natively (no hostname required) — the thing CIDR mode actually
  ## can't run is the hostname-ONLY discovery tools (subfinder/amass/gau).
  ## So webscan's web-app steps shouldn't be unconditionally skipped in CIDR
  ## mode; they should run IF naabu found an open port that's typically a web
  ## service. naabu already confirmed the port is open via its own connect
  ## scan, so no second probe (e.g. httpx) is needed here — just filter
  ## naabu's own output down to the web-port subset.
  WEBPORTS_FILE="$TARGET_PREFIX-webports.log"
  : > "$WEBPORTS_FILE"
  IFS=',' read -ra WP_ARR <<< "$webPorts"
  for p in "${WP_ARR[@]}"; do
    grep ":${p}\$" "$TARGET_PREFIX-naabu.log" >> "$WEBPORTS_FILE" 2>/dev/null || true
  done
  WEB_PORT_COUNT=$(wc -l < "$WEBPORTS_FILE")
  if [ "$WEB_PORT_COUNT" -gt 0 ]; then
    log "$WEB_PORT_COUNT web-port host:port combination(s) found — Output: $WEBPORTS_FILE"
  else
    log "No web ports among naabu's open ports — webscan will skip nuclei/dirsearch"
  fi

  log "Phase complete"
  exit 0
fi

# ─── DOMAIN MODE (Phase 2 of the standard recon->network->webscan pipeline) ──

# ─── Resolve prefix and input file ─────────────────────────────────────────────
if [ -z "${domain_list:-}" ]; then
  TARGET_PREFIX="$tdir/$baseDomain"
else
  daBase="$(basename "$domain_list")"
  TARGET_PREFIX="$tdir/$daBase"
fi

TARGET_DOMAINS="${TARGET_PREFIX}-domains_only.log"

if [ ! -f "$TARGET_DOMAINS" ]; then
  echo "Error: required input file not found: $TARGET_DOMAINS (did Phase 1 / recon run first?)" >&2
  exit 1
fi

log "Phase started"

# ─── DNS Resolution ─────────────────────────────────────────────────────────────
log "Resolving found domains via dnsx"

## dnsx ignores Docker's embedded DNS proxy by default and returns empty results.
## Extract the actual nameserver from /etc/resolv.conf (set by Docker at container
## start) and pass it explicitly via -r. Falls back to 8.8.8.8/1.1.1.1 if extraction
## fails for any reason.
DOCKER_DNS=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)
if [ -z "$DOCKER_DNS" ]; then
  log "Could not detect Docker DNS resolver — falling back to 8.8.8.8,1.1.1.1"
  DOCKER_DNS="8.8.8.8,1.1.1.1"
else
  log "Using Docker DNS resolver: $DOCKER_DNS"
fi

cat "$TARGET_DOMAINS" \
  | dnsx -silent -a -aaaa -cname -resp -r "$DOCKER_DNS" \
  | tee -a "$TARGET_PREFIX-resolved.log" > /dev/null

RESOLVED_COUNT=$(wc -l < "$TARGET_PREFIX-resolved.log" 2>/dev/null || echo 0)
log "$RESOLVED_COUNT records resolved"

# ─── Extract Unique IPs ─────────────────────────────────────────────────────────
grep -Eo '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' \
  "$TARGET_PREFIX-resolved.log" \
  | sort -u > "$TARGET_PREFIX-unique-ips.log"

IP_COUNT=$(wc -l < "$TARGET_PREFIX-unique-ips.log")
log "$IP_COUNT unique IPs extracted"
log "Output: $TARGET_PREFIX-resolved.log"

# ─── Port Scanning ──────────────────────────────────────────────────────────────
log "Port scanning with naabu"
naabu -list "$TARGET_DOMAINS" \
      -p "$portsIcareAbout" \
      -rate 1000 \
      -timeout 10 \
      -silent \
      -exclude-cdn \
      -r "$DOCKER_DNS" \
      -o "$TARGET_PREFIX-naabu.log"

# Ensure file exists even if naabu found nothing
touch "$TARGET_PREFIX-naabu.log"

# Split by port — naabu v2 output format is host:port
grep ":80$"   "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_80.log"   2>/dev/null || true
grep ":443$"  "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_443.log"  2>/dev/null || true
grep ":22$"   "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_22.log"   2>/dev/null || true
grep ":23$"   "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_23.log"   2>/dev/null || true
grep ":8080$" "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_8080.log" 2>/dev/null || true
grep ":8443$" "$TARGET_PREFIX-naabu.log" > "$TARGET_PREFIX-naabu_8443.log" 2>/dev/null || true

OPEN_PORTS=$(wc -l < "$TARGET_PREFIX-naabu.log")
log "$OPEN_PORTS open port/host combinations found"
log "Output: $TARGET_PREFIX-naabu.log"

log "Phase complete"
exit 0
