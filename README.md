# Kuromaku (黒幕)

> *The one who pulls the strings from behind the curtain.*

Kuromaku is a phased, checkpointed, resumable recon/vuln-scanning orchestration
platform for authorized bug bounty and DMZ exposure work. A lightweight
Node.js **orchestrator** dispatches purpose-built, resource-capped Docker
**workers** — one per phase — and exposes the whole thing as an MCP server so
it can be driven from Claude Desktop or a local LLM (LM Studio).

## Two pipelines

**Domain mode** (5 phases): `recon → network → webscan → xss → report`
Subdomain enumeration (subfinder/amass/gau/katana) → DNS resolution + port
scan (dnsx/naabu) → vuln/web scanning (nuclei/nmap/dirsearch) → reflected-XSS
triage (httpx + dalfox) → an automated DOCX findings report.

**IP/CIDR mode** (2 phases): `network → webscan`
For scanning IP space directly (e.g. a DMZ audit) rather than a domain.
Accepts a single IP, a CIDR range, or an explicit `/32` single host. Skips
every hostname-dependent tool (subfinder, amass, gau, nuclei, dirsearch) —
only naabu (port scan) and nmap (`-sV --script vulners`) run, since those are
the only things that make sense against a bare IP. `kuromaku_run` also
auto-detects an IP/CIDR passed as `domain` and transparently routes here
instead of running the domain pipeline against it.

**Scanning many IPs.** `kuromaku_ip_scan` takes targets three ways:

- **`ips_file`** — *best for large lists (hundreds+).* Drop a file with one
  IP/CIDR per line into the `_incoming` staging folder (`projects/_incoming/`)
  and pass just its name: `{ "project_name": "...", "ips_file": "targets.txt" }`.
  The orchestrator reads the whole file, so nothing is truncated.
- **`ips`** — an inline array, fine for a handful of targets:
  `["10.0.0.5", "206.130.144.0/24"]`. Avoid it for big lists: an LLM caller
  will truncate a long array mid-generation (observed: a 1200-IP list arrived
  as 192). The orchestrator writes whatever it receives into the scan dir.
- **`cidr`** — a single IP/CIDR, or a file path that already exists on the
  orchestrator's filesystem.

All three end up written into the scan directory — the one path bind-mounted
into the worker containers — so naabu/nmap can read it. A host path handed to
`cidr` that the orchestrator can't see is the classic "scanned 1200 IPs,
found 0" failure; `ips_file`/`ips` sidestep it.

## Directory layout

```
kuromaku/
├── orchestrator/          # MCP server + phase dispatcher (Node.js)
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── index.js       # MCP tool definitions + handlers
│       ├── orchestrator.js# docker run/inspect/kill, pipeline + resource profiles
│       └── checkpoint.js  # .checkpoint read/write/validate, stale detection
├── workers/
│   ├── recon/             # subfinder, amass, httpx, gau, katana, anew
│   ├── network/           # dnsx, naabu
│   ├── webscan/           # nuclei, nmap+vulners, dirsearch
│   ├── xss/                # httpx (reflection probe), dalfox
│   └── report/             # python-docx report generator
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CHECKPOINT_SCHEMA.md
│   └── DEPLOYMENT.md / DEPLOYMENT.pdf   # full install/build/run guide
```

## MCP tools

| Tool | Purpose |
|---|---|
| `kuromaku_run` | Start the 5-phase domain pipeline (auto-redirects to IP mode if `domain` is actually an IP/CIDR) |
| `kuromaku_ip_scan` | Start the 2-phase IP/CIDR pipeline directly |
| `kuromaku_status` | Read checkpoint status for a project (runs stale-detection) |
| `kuromaku_pause` / `kuromaku_resume` | Pause after the current phase completes / resume from first pending phase |
| `kuromaku_stop` | Kill the in-flight container, mark phase failed |
| `kuromaku_results` | Summary of line counts, or the contents of a single output file |
| `kuromaku_report` | Full report of every output file that HAS DATA (empties omitted); inline, or `export:true` writes `<prefix>-results-report.md` to the scan volume |
| `kuromaku_new_project` / `kuromaku_list_projects` | Project housekeeping |
| `kuromaku_batch_run` | Run a LIST of apex domains, each its own project, strictly sequentially |
| `kuromaku_batch_status` | Progress across a batch's targets |
| `kuromaku_batch_pause` | Stop a batch advancing to its next target once the current one finishes |

### Tool parameters

Parameters marked **required** must be supplied; everything else is optional.

#### `kuromaku_run`
| Parameter | Type | Default | Description |
|---|---|---|---|
| `domain` | string, **required** | — | Target domain (e.g. `acme.com`). A bare IP/CIDR is auto-routed to the IP-scan pipeline. |
| `project_name` | string | `domain` | Project folder name. |
| `threads` | number | `10` | Threads for the recon/webscan workers. |
| `skip_xss` | boolean | `false` | Skip the XSS phase. |
| `skip_nuclei` | boolean | `false` | Skip nuclei in the webscan phase. |
| `llm_url` | string | — | LM Studio OpenAI-compatible URL for the report's executive summary. |
| `llm_model` | string | — | Model name for the executive summary. Without `llm_url`/`llm_model` a templated summary is used. |
| `team_name` | string | `"Kuromaku Security Assessment"` | Team/organization name on the report's title page and narrative sections. |
| `client_name` | string | `"<CLIENT NAME>"` | Client/target organization name on the report's title page, confidentiality notice, and findings narrative. Left as a literal placeholder if omitted, so it's obvious in the output that it still needs filling in. |
| `scope` | string[] | — | In-scope glob patterns (`example.com` = exact host, `*.example.com` = subdomains only, not the apex). The target itself is not auto-included. Out-of-scope discoveries are dropped before network/webscan/xss (saved to `out-of-scope.log`, see below) — never scanned, never silently added back. If omitted entirely, the response warns that recon's crawl (gau/katana) commonly pulls in unrelated third-party domains that will then be scanned downstream too. |
| `target_url` | string | — | Explicit `host[:port]` guaranteed to survive into `uniqdomains.log` even if subfinder/amass/gau/katana find nothing for it. For a private/internal target (nothing publicly indexed) or one on a non-standard port (katana's own crawl always hits `https://<domain>`, so a plain-HTTP or non-443 target otherwise never gets probed). Additive — normal discovery still runs. |

If a checkpoint already exists with all phases done this is a no-op; use `kuromaku_resume` with `force: true` to re-run.

#### `kuromaku_ip_scan`
| Parameter | Type | Description |
|---|---|---|
| `project_name` | string, **required** | Project folder name (used for output naming and the checkpoint). |
| `ips_file` | string | Filename in `projects/_incoming/` with one IP/CIDR per line. Best for large lists. |
| `ips` | string[] | Inline IP/CIDR array, for a handful of targets. |
| `cidr` | string | A single IP/CIDR, or an orchestrator-visible file path. |

Supply at least one of `ips_file`, `ips`, or `cidr`.

The webscan phase now also runs nuclei and dirsearch in CIDR mode, against
bare `ip:port` targets, for any open port in the common-web-port set (80,
443, 8080, 8443, 9000, 9090, 10000, 10010, 10020 — naabu already confirmed
these are open, so no extra probe is needed). Only subfinder/amass/gau/recon/
xss stay hostname-only and skipped — those genuinely have nothing to
enumerate against a bare IP. A web service on a port outside that list isn't
auto-detected; use `kuromaku_run` with `target_url` for a known `host:port`
instead.

#### `kuromaku_status`
| Parameter | Type | Description |
|---|---|---|
| `project_name` | string, **required** | Reads the checkpoint, runs stale-detection, returns a per-phase summary. |

#### `kuromaku_pause`
| Parameter | Type | Description |
|---|---|---|
| `project_name` | string, **required** | Project to pause. |
| `phase` | string | Phase to pause *after* (`recon`, `network`, `webscan`, `xss`, `report` in domain mode; `network`, `webscan` in CIDR mode). Omit/null clears an existing pause. The in-flight phase finishes normally. |

#### `kuromaku_resume`
| Parameter | Type | Default | Description |
|---|---|---|---|
| `project_name` | string, **required** | — | Resumes from the first `pending`/`failed` phase; `done` phases are skipped. Clears any pause. |
| `force` | boolean | `false` | Reset all phases to pending and restart from `recon`. |

#### `kuromaku_stop`
| Parameter | Type | Description |
|---|---|---|
| `project_name` | string, **required** | Kills the running worker container and marks the phase `failed` ("stopped by user"), making it resumable. Works for both domain and CIDR scans. |

#### `kuromaku_results`
| Parameter | Type | Default | Description |
|---|---|---|---|
| `project_name` | string, **required** | — | Project to read. |
| `file` | string | — | One of `uniqdomains`, `uniqueips`, `naabu`, `nucleiAlerts`, `dirsearch`, `nmapvulners`, `dalfox`, `resolved`, `report`. Omit for a line-count summary of all output files. |
| `max_lines` | number | `100` | Cap on lines returned when `file` is given. |

#### `kuromaku_report`
| Parameter | Type | Default | Description |
|---|---|---|---|
| `project_name` | string, **required** | — | Project to report on. |
| `export` | boolean | `false` | `false` returns the report inline. `true` writes `<prefix>-results-report.md` to the scan directory instead — recommended for large scans (e.g. big nmap output). |

Concatenates every output file that **has data**, in scan order, one labeled section per file; empty or not-yet-produced files are omitted. Use `kuromaku_results` for a quick summary or a single file.

#### `kuromaku_new_project`
| Parameter | Type | Description |
|---|---|---|
| `project_name` | string, **required** | Creates the project folder structure without starting a scan. |

#### `kuromaku_list_projects`
No parameters. Lists all projects and their checkpoint status, and any batches.

#### `kuromaku_batch_run`
| Parameter | Type | Default | Description |
|---|---|---|---|
| `batch_id` | string, **required** | — | Identifier for this batch (manifest filename, used by `kuromaku_batch_status`/`kuromaku_batch_pause`). |
| `targets` | array | — | Inline `{domain, scope?, project_name?}` objects, for a handful. For more than ~15-20, use `targets_file` instead. |
| `targets_file` | string | — | Filename of a JSON file in `projects/_incoming/` — an array of the same `{domain, scope?, project_name?}` objects. Best for large lists; the whole file is read, nothing truncates. |
| `threads` / `skip_xss` / `skip_nuclei` / `llm_url` / `llm_model` | — | same as `kuromaku_run` | Applied uniformly to every target. |
| `force` | boolean | `false` | If `batch_id` already has a manifest, discard it and start fresh from the newly supplied targets. |

Each target becomes an ordinary project — its own checkpoint, its own
`scope` — run to completion one at a time before the next target starts.
Nothing else in this server stops two *different* projects' pipelines
running concurrently (only the *same* project is deduped), so looping
`kuromaku_run` yourself for a domain list risks stacking N concurrent
pipelines — the resource-overload scenario nuclei's own batching exists to
avoid (see `CLAUDE.md`). Use this instead for any multi-domain list.

Calling again with the same `batch_id` resumes it (already-`done` targets
are skipped) rather than starting over — same semantics as `kuromaku_resume`.

#### `kuromaku_batch_status`
| Parameter | Type | Description |
|---|---|---|
| `batch_id` | string, **required** | Progress summary: done/failed/running/pending counts, the currently-running target's own phase status inline, and a short list of anything not yet done. |

#### `kuromaku_batch_pause`
| Parameter | Type | Description |
|---|---|---|
| `batch_id` | string, **required** | The in-flight target finishes normally; the batch stops before starting the next one. To kill the in-flight target's container immediately instead, use `kuromaku_stop` with that target's own `project_name` (from `kuromaku_batch_status`). Resume with `kuromaku_batch_run` using the same `batch_id`. |

Full setup — Docker image builds, `HOST_PROJECTS_DIR`, LM Studio/Claude
Desktop `mcp.json` config, resource profile tuning, Windows-specific
PowerShell syntax — is in `docs/DEPLOYMENT.md`.

## Resource profiles

Set `RESOURCE_PROFILE=low` (default, tuned for an 8GB machine) or `high`
(tuned for 8GB+ dedicated to the webscan container) as an env var on the
orchestrator container. See `docs/ARCHITECTURE.md` for the exact per-phase
memory caps and nuclei concurrency/rate-limit values.

## Scope compliance

`kuromaku_run` accepts a `scope` array of glob patterns (e.g. from a
Bugcrowd/HackerOne program's in-scope list). When provided, every discovered
domain outside that list is dropped before network/webscan/xss ever run
against it — dropped hosts are never scanned.

Recon almost always turns up hosts outside the list you gave it (third-party
CDN/API/analytics domains linked from the target's own pages, in particular).
That's expected and doesn't interrupt the scan: dropped hosts are written to
`<prefix>-out-of-scope.log` (readable via `kuromaku_results` /
`kuromaku_report`) so you can review later whether any of them should've been
in scope, without stopping or re-running anything.

If `scope` is omitted entirely, `kuromaku_run`/`kuromaku_resume` return a
warning asking you to confirm that's intentional — that's the one case worth
catching before the scan runs, since without any scope list nothing gets
filtered and recon's noise goes straight into network/webscan/xss.

## Report format

`<prefix>-report.docx` is rendered from `workers/report/assets/report-template.docx`
(a CCSO-style assessment report) via `docxtpl`, not built up from scratch —
title page, severity table, Scope > Networks (from `scope`), Classification
Definitions, per-finding detail, Appendix A (Tools Used), all templated.

Per-finding **Risk Score**, **Exploitation Likelihood**, and **Business
Impact** are derived from nuclei's own CVSS data (score + vector), aligned
with [Bugcrowd's Vulnerability Rating Taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
terminology — not an LLM guess or an invented heuristic. A finding with no
CVSS vector (common for non-CVE templates: exposures/misconfiguration/
technologies/etc.) falls back to the template's own documented severity
scale (Critical=10, High=7-9, Medium=4-6, Low=1-3, Informational=0).
**Remediation Difficulty is deliberately not included** — unlike CVSS-
derivable fields, it depends on the target's own infrastructure (in-house
skills, hardware/budget, change-control process) that an external scan has
no way to know; fabricating it would be worse than leaving it out.

The Executive Summary, Testing Methodology description, and severity counts
are populated from the scan's actual data (and the existing LLM call, with
its templated fallback, for the Executive Summary narrative specifically).
**Observed Security Strengths and Recommendations are intentionally left as
structure only** (headings + intro text, no auto-generated bullet points) —
these require real analyst judgment an automated scanner has no basis to
fabricate; same reasoning as dropping Remediation Difficulty.

This requires `nuclei`'s output to be JSON Lines (`-jsonl` — see
`phase-webscan.sh`), not the old plain-text format. `kuromaku_results`/
`kuromaku_report` pretty-print `nucleiAlerts.log` back to a readable
one-line-per-finding summary for chat; the file on disk is JSONL.

If `docxtpl`, the template asset, or `python-docx` aren't available, or the
templated render fails for any reason, the report phase automatically falls
back to kuromaku's original flat-summary DOCX format — the report phase
never fails outright just because the richer format couldn't be built. Pass
`--legacy` directly to `phase-report.py` to force that fallback.

## Authorization

Every tool in this repo performs active reconnaissance and scanning.
**Only point it at targets you have explicit written authorization to
test** (your own infrastructure, or a bug bounty program's defined scope).
