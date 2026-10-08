# Kuromaku Checkpoint Schema

## Purpose

Every project's `.checkpoint` file is the **single source of truth** for scan
progress. The orchestrator never infers state from running containers or
process lists — it reads this file. This means:

- `kuromaku_status` is a file read, not a `docker exec` — instant, zero
  resource contention with active scans.
- "Resume from phase X" = "start the worker for the first phase that is not
  `done`".
- A crashed/OOM-killed worker leaves the phase as `running` — on next status
  check or resume call, the orchestrator detects this (see Stale Detection)
  and marks it `failed`, making it eligible for retry.

## File Location

```
projects/<project_name>/scans/.checkpoint
```

Created automatically on first `kuromaku_run` call. Never written by
worker containers directly — only the orchestrator writes to it, before and
after each worker run. This avoids file-lock contention between the
orchestrator and a worker writing scan output simultaneously.

## Schema

```json
{
  "schema_version": 1,
  "project": "palng",
  "domain": "portarthurlng.com",
  "created_at": "2026-06-12T03:00:00Z",
  "updated_at": "2026-06-12T03:14:22Z",
  "options": {
    "threads": 25,
    "skip_xss": false,
    "skip_nuclei": false
  },
  "phases": {
    "recon": {
      "status": "done",
      "started_at": "2026-06-12T03:00:01Z",
      "completed_at": "2026-06-12T03:02:14Z",
      "container_id": "a1b2c3d4",
      "exit_code": 0,
      "outputs": [
        "portarthurlng.com-uniqdomains.log",
        "portarthurlng.com-domains_only.log"
      ]
    },
    "network": {
      "status": "done",
      "started_at": "2026-06-12T03:02:15Z",
      "completed_at": "2026-06-12T03:02:20Z",
      "container_id": "e5f6a7b8",
      "exit_code": 0,
      "outputs": [
        "portarthurlng.com-resolved.log",
        "portarthurlng.com-unique-ips.log",
        "portarthurlng.com-naabu.log"
      ]
    },
    "webscan": {
      "status": "failed",
      "started_at": "2026-06-12T03:02:21Z",
      "completed_at": null,
      "container_id": "c9d0e1f2",
      "exit_code": 137,
      "error": "container OOM killed (exit 137)",
      "outputs": []
    },
    "xss": {
      "status": "pending",
      "started_at": null,
      "completed_at": null,
      "container_id": null,
      "exit_code": null,
      "outputs": []
    }
  }
}
```

## Phase Status Values

| Status | Meaning | Set By |
|---|---|---|
| `pending` | Not yet started | Initial creation, or reset on resume |
| `running` | Worker container currently executing | Orchestrator, before `docker run` |
| `done` | Worker exited 0, expected output files exist | Orchestrator, after `docker run` returns |
| `failed` | Worker exited non-zero, OR exited 0 but expected outputs missing, OR stale (see below) | Orchestrator |
| `skipped` | User explicitly skipped via `skip_xss`/`skip_nuclei` options | Orchestrator, at phase dispatch |

## Stale Detection

If a phase's status is `running` but its `started_at` timestamp is older than
`STALE_THRESHOLD_MINUTES` (default: 30) AND no container with `container_id`
is currently running, the orchestrator marks it `failed` with
`error: "stale — worker container no longer running"` on the next
`kuromaku_status` or `kuromaku_resume` call.

This is the mechanism that recovers from a killed orchestrator, a Docker
Desktop restart, or a worker that died without the orchestrator observing the
exit code.

## Phase Dependency Graph

```
recon ──▶ network ──▶ webscan ──▶ xss
```

Strictly linear. Each phase's
worker script receives the *project scan directory* as its only input — it
reads whatever output files it needs from prior phases and writes its own.
The orchestrator does not pass phase-specific file lists; workers know their
own expected inputs/outputs (defined in each worker's phase script).

## Expected Outputs Per Phase

Used for two things: (1) validating a phase actually produced something
before marking it `done`, and (2) `kuromaku_resume` checking whether a
`pending`/`failed` phase can be skipped because outputs already exist from a
prior run.

| Phase | Required Output Files (prefix = `<domain>-` or `<basename(domain_list)>-`) |
|---|---|
| recon | `uniqdomains.log`, `domains_only.log` |
| network | `resolved.log`, `unique-ips.log`, `naabu.log` |
| webscan | `nucleiAlerts.log` (if `!skip_nuclei`), `dirsearch.log`, `nmapvulners.log` |
| xss | `dalfox.log` (only required if `!skip_xss` AND `gau-dirty.log` exists) |

A phase with zero-byte or missing required outputs is marked `failed` even if
`exit_code == 0` — this catches the silent-failure cases we saw with gau/
katana/dirsearch flag mismatches.

## MCP Tool Behavior Reference

| Tool | Checkpoint Interaction |
|---|---|
| `kuromaku_run` | Creates `.checkpoint` if absent. If present and all phases `done`, refuses (suggests `kuromaku_resume` with a `force` flag for re-run). Otherwise behaves like `resume`. |
| `kuromaku_resume` | Runs stale detection, then starts the first phase that is `pending` or `failed`. Phases already `done` are skipped entirely — no container spawned. |
| `kuromaku_status` | Pure read of `.checkpoint`, runs stale detection (read-only update if stale found), returns human-readable summary. |
| `kuromaku_stop` | If a phase is `running`, kills that phase's container by `container_id`, sets status to `failed` with `error: "stopped by user"`. |
