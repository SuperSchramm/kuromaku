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
- `workers/report/phase-report.py` — DOCX report generation (python-docx),
  modeled on a reference report format; LLM call for the executive summary
  is optional (falls back to a templated summary if no `llm_url`/`llm_model`
  given).

## Conventions to preserve

- `HOST_PROJECTS_DIR` env var on the orchestrator container is required —
  the orchestrator calls `docker run` against the **host's** Docker daemon
  (via the mounted socket), so `-v` mount paths must be host-side paths, not
  the orchestrator container's internal `/workspace/projects` path. See
  `hostScanDir()` in `orchestrator.js`.
- Progress log is `<scan_dir>/kuromaku_progress.log`, written by every phase
  script via a `log()` helper with a per-phase prefix tag.
- IP/CIDR targets skip all hostname-dependent tools entirely (no amass/
  subfinder/gau/nuclei/dirsearch) — this is intentional, not a gap to "fix"
  by trying to run them anyway.
- Multi-target IP scans come in via `kuromaku_ip_scan`'s `ips` **array**, not a
  file path. The workers only see `<scanDir>:/workspace/scans`, so a host file
  path handed to `--cidr` is invisible inside the container — that was the
  "scanned a 1200-IP list, found 0 IPs" bug. The orchestrator now writes `ips`
  (or a real, orchestrator-visible file passed as `cidr`) into the scan dir as
  `ip-targets.txt` and hands the worker the container path. Keep the three
  pieces in sync if you touch this: `runIpScan`/`launchCidrPipeline` in
  `index.js` (writes the list, passes the container path), `cidrPrefix` in
  `orchestrator.js` (basename-vs-string rule must match the worker), and
  `phase-network.sh`'s CIDR branch (copies the file's *contents* into
  `unique-ips.log`, never the path string).
- Nuclei runs in resource-capped batches (3 tag groups), each with its own
  heartbeat + `-stats` output piped into the progress log — do not revert to
  one unbatched run; it caused a full system lockup once on constrained
  hardware.

## When editing

Run `node --check` on any touched `.js` file and `bash -n` on any touched
`.sh` file before considering a change done — there's no test suite here.
