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
| `kuromaku_results` | Read output files from a project's scan directory |
| `kuromaku_new_project` / `kuromaku_list_projects` | Project housekeeping |

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
against it.

## Authorization

Every tool in this repo performs active reconnaissance and scanning.
**Only point it at targets you have explicit written authorization to
test** (your own infrastructure, or a bug bounty program's defined scope).
