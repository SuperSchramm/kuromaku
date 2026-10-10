# Kuromaku — context for Claude Code

This is a phased, checkpointed Docker-orchestration platform for authorized
recon/vuln scanning, driven as an MCP server. Read `README.md` first, then
`docs/ARCHITECTURE.md` for the full directory/data-flow picture before making
structural changes.

## Layout

- `orchestrator/src/index.js` — MCP tool definitions + request handlers. Tool
  names are `kuromaku_*` — do not reintroduce a `kali_` prefix.
- `orchestrator/src/orchestrator.js` — resource `PROFILES` (low/high),
  `buildDockerArgs`, `spawnPhase`/`waitForContainer`, `runPipeline` (domain
  mode, 5 phases) and `runCidrPipeline` (IP/CIDR mode, 2 phases). Docker
  image names here (`kuromaku-recon`, `kuromaku-network`, etc.) must match
  whatever tag you build each worker image with.
- `orchestrator/src/checkpoint.js` — `.checkpoint` JSON read/write
  (atomic tmp+rename), stale-phase detection, `PHASE_ORDER` (domain) vs
  `CIDR_PHASE_ORDER` (IP mode) — any checkpoint-shape change must stay
  mode-aware in both `detectStale` and `summarize`, or a CIDR checkpoint will
  crash on the first phase (this happened once; see git history / prior
  session notes if this regresses).
- `workers/<phase>/phase-<phase>.sh` — the actual tool invocations running
  inside each worker container. Domain-mode and CIDR-mode logic live in the
  same script, branched on whether `--cidr` was passed.
- `kuromaku_batch_run`/`kuromaku_batch_status`/`kuromaku_batch_pause`
  (`index.js`) — sequences a LIST of apex domains, each as its own ordinary
  project (own checkpoint, own `scope`), strictly one at a time. Manifest
  lives at `PROJECTS_DIR/_batches/<batch_id>.json` (`readBatchManifest`/
  `writeBatchManifest`), separate from per-project `.checkpoint` files —
  purely a sequencing + progress layer, no changes to `checkpoint.js`/
  `PHASE_ORDER`/`runPipeline`. Exists because nothing else stops two
  *different* projects' pipelines running concurrently (`activePipelines`
  only dedupes the *same* project) — looping `kuromaku_run` yourself for a
  domain list risks exactly the resource-overload scenario nuclei's own
  batching below exists to avoid.
- `workers/report/phase-report.py` — DOCX report generation. Default path
  renders `workers/report/assets/report-template.docx` (a CCSO-style
  assessment report) via `docxtpl`; per-finding Risk Score/Exploitation
  Likelihood/Business Impact come from nuclei's own CVSS data (vector +
  score), Bugcrowd-VRT-aligned, not fabricated — see README's "Report
  format" section for the full reasoning, including why Remediation
  Difficulty and Strengths/Recommendations bullet points are deliberately
  left out rather than invented. Falls back automatically to the original
  flat-summary format (`build_legacy_report`, still python-docx) if
  `docxtpl`/the template asset/`python-docx` are unavailable or the
  templated render throws for any reason — the phase must never fail
  outright over the richer format. `workers/report/assets/tools/
  prepare_template.py` is the one-time maintenance script that turned the
  source CCSO docx into the Jinja-tagged template asset; it's not part of
  the runtime pipeline, only needed again if the template itself changes.
  LLM call for the executive summary is optional (falls back to a
  templated summary if no `llm_url`/`llm_model` given, or if
  `host.docker.internal` doesn't resolve — see the `--add-host` note
  above).

## Conventions to preserve

- `HOST_PROJECTS_DIR` env var on the orchestrator container is required —
  the orchestrator calls `docker run` against the **host's** Docker daemon
  (via the mounted socket), so `-v` mount paths must be host-side paths, not
  the orchestrator container's internal `/workspace/projects` path. See
  `hostScanDir()` in `orchestrator.js`.
- Progress log is `<scan_dir>/kuromaku_progress.log`, written by every phase
  script via a `log()` helper with a per-phase prefix tag.
- IP/CIDR targets skip the genuinely hostname-ONLY discovery tools entirely
  (no amass/subfinder/gau/recon/xss) — this is intentional, not a gap to
  "fix" by trying to run them anyway. Nuclei and dirsearch are different:
  they accept bare `ip:port` targets natively, so webscan runs them in CIDR
  mode too, against whatever open ports the network phase's web-port
  detection flags (`<prefix>-webports.log`, built from naabu's own open-port
  results — see `webPorts` in `phase-network.sh` and the CIDR branch of
  `phase-webscan.sh`). No web port found -> both stay skipped exactly as
  before, same empty `nucleiAlerts.log`/`dirsearch.log`.
- Multi-target IP scans come in via `kuromaku_ip_scan`. Three input shapes,
  all normalized by `runIpScan` into `<scanDir>/ip-targets.txt` with the worker
  given the container path `/workspace/scans/ip-targets.txt`:
  `ips_file` (a filename staged in `PROJECTS_DIR/_incoming/` — **use this for
  hundreds of targets**; an inline `ips` array gets truncated by the LLM
  mid-generation, e.g. 1200 IPs arrived as 192), `ips` (array, for a handful),
  and `cidr` (a single IP/CIDR or an orchestrator-visible file path). The
  workers only see `<scanDir>:/workspace/scans`, so a host path handed to
  `--cidr` that the orchestrator can't resolve is invisible in the container —
  that was the original "scanned a 1200-IP list, found 0 IPs" bug. Keep these
  in sync if you touch this: `runIpScan`/`launchCidrPipeline` in `index.js`
  (writes the list, passes the container path), `cidrPrefix` in
  `orchestrator.js` (basename-vs-string rule must match the worker), and
  `phase-network.sh`'s CIDR branch (copies the file's *contents* into
  `unique-ips.log`, never the path string).
- Nuclei runs in resource-capped batches (5 groups, batched by template
  *directory* — `-t <dir>/`, covering all 14 of nuclei-templates' top-level
  categories: dns/iot/cves/technologies/exposures/fuzzing/miscellaneous/
  misconfiguration/default-logins/network/headless/takeovers/exposed-panels/
  vulnerabilities — not by `-tags`, and deliberately not narrowed by
  `-severity`/`-etags` either, since directories like technologies/ are
  dominated by info-severity findings a severity filter would just discard),
  each with its own heartbeat + `-stats` output piped into the progress log
  — do not revert to one unbatched run; it caused a full system lockup once
  on constrained hardware. This is intentionally slow/thorough, not a quick
  scan. Output is JSON Lines (`-jsonl`), not nuclei's old plain-text format
  — `nucleiAlerts.log` on disk is JSONL (needed for the report's CVSS-
  derived scoring); `kuromaku_results`/`kuromaku_report` pretty-print it
  back to a readable one-line-per-finding summary (`prettyPrintNucleiJsonl`
  in `index.js`) for chat, but don't assume the raw file is plain text
  anymore if you're reading it directly.

## When editing

Run `node --check` on any touched `.js` file and `bash -n` on any touched
`.sh` file before considering a change done — there's no test suite here.
