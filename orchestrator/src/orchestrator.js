// orchestrator.js — Kuromaku orchestrator
// Spawns worker containers for each phase, waits for completion, validates
// outputs, and updates the checkpoint. One worker container runs at a time
// (matches a simple sequential dispatch design).

import { spawn, execSync } from "child_process";
import path from "path";
import fs from "fs";
import * as cp from "./checkpoint.js";

// ─── Per-worker image + resource profile ───────────────────────────────────
// Memory caps and tool concurrency derived from observed behavior on an
// 8GB Mac Mini M4 (see ARCHITECTURE.md). RESOURCE_PROFILE env var can
// override the whole table for higher-spec hardware.
const PROFILES = {
  low: {
    recon:   { image: "kuromaku-recon",   memory: "1g", caps: [] },
    network: { image: "kuromaku-network", memory: "1g", caps: ["NET_RAW", "NET_ADMIN"] },
    webscan: { image: "kuromaku-webscan", memory: "3g", caps: ["NET_RAW"],
               env: { NUCLEI_BULK_SIZE: "5", NUCLEI_CONCURRENCY: "5", NUCLEI_RATE_LIMIT: "25" } },
    xss:     { image: "kuromaku-xss",     memory: "2g", caps: [] },
    report:  { image: "kuromaku-report",  memory: "512m", caps: [] },
  },
  high: {
    recon:   { image: "kuromaku-recon",   memory: "4g", caps: [] },
    network: { image: "kuromaku-network", memory: "2g", caps: ["NET_RAW", "NET_ADMIN"] },
    webscan: { image: "kuromaku-webscan", memory: "8g", caps: ["NET_RAW"],
               env: { NUCLEI_BULK_SIZE: "25", NUCLEI_CONCURRENCY: "25", NUCLEI_RATE_LIMIT: "150" } },
    xss:     { image: "kuromaku-xss",     memory: "4g", caps: [] },
    report:  { image: "kuromaku-report",  memory: "1g", caps: [] },
  },
};

function getProfile() {
  const name = process.env.RESOURCE_PROFILE || "low";
  return PROFILES[name] || PROFILES.low;
}

// ─── Build docker run args for a phase ──────────────────────────────────────
// IMPORTANT: this orchestrator runs inside its own container with
// /workspace/projects mounted from the host. But `docker run -v ...` issued
// from inside a container (via the mounted Docker socket) is executed by the
// HOST's Docker daemon — host-side `-v` paths are required, NOT this
// container's internal /workspace/projects path. HOST_PROJECTS_DIR must be
// set to the actual host filesystem path (e.g. the iCloud Drive path on Mac)
// so spawned worker containers mount the correct directory.
function hostScanDir(scanDir) {
  const hostProjectsDir = process.env.HOST_PROJECTS_DIR;
  if (!hostProjectsDir) {
    throw new Error(
      "HOST_PROJECTS_DIR env var is required — must be the HOST filesystem path " +
      "to the projects directory (Docker-from-Docker requires host paths for -v mounts)."
    );
  }
  // scanDir is ALWAYS this Linux container's POSIX path, e.g.
  // /workspace/projects/<name>/scans — so compute the relative segment with the
  // POSIX resolver regardless of what the host OS is.
  const internalProjectsDir = process.env.PROJECTS_DIR || "/workspace/projects";
  const relative = path.posix.relative(internalProjectsDir, scanDir);

  // Re-root onto the host path, PRESERVING the host path's separator style. The
  // spawned `docker run -v <host>:/workspace/scans` is executed by the HOST
  // daemon (via the mounted socket), so the mount path must be valid for the
  // host OS — not for this Linux container. HOST_PROJECTS_DIR can therefore be
  // any of:
  //   Windows drive-letter : C:\Users\me\projects  or  C:/Users/me/projects
  //   WSL                  : /mnt/c/Users/me/projects
  //   macOS / Linux        : /Users/me/projects  or  /home/me/projects
  // The old code used path.join() (POSIX inside this container), which mangled a
  // Windows path into mixed C:\...\projects/<name>/scans separators. Docker
  // doesn't error on that — it silently creates an empty anonymous volume, so
  // the worker runs, exits 0, and writes nothing. That's the "scan runs clean
  // but finds nothing" failure.
  const isWindowsHostPath = /^[A-Za-z]:[\\/]/.test(hostProjectsDir) || hostProjectsDir.includes("\\");
  if (isWindowsHostPath) {
    // Normalize the whole thing to backslashes so the only ':' remaining are the
    // drive colon and the -v mount colon (mixed '/' is what broke the mount).
    const base = hostProjectsDir.replace(/\//g, "\\").replace(/\\+$/, "");
    const rel = relative.split("/").join("\\");
    return rel ? `${base}\\${rel}` : base;
  }
  // POSIX host path (Linux, macOS, or WSL's /mnt/c form) — join with '/'.
  return path.posix.join(hostProjectsDir, relative);
}

function buildDockerArgs(phase, scanDir, opts) {
  const profile = getProfile()[phase];
  const args = [
    "run", "--rm", "-d", // detached — orchestrator polls for completion
    "--memory", profile.memory,
    "--memory-swap", profile.memory, // no swap beyond the memory limit
    "-v", `${hostScanDir(scanDir)}:/workspace/scans`,
    // report's default --llm-url points at http://host.docker.internal:1234
    // (LM Studio on the host). Docker Desktop usually resolves that name
    // automatically via its embedded DNS, but not reliably in every
    // version/backend (observed failing here: "Name does not resolve").
    // --add-host with the host-gateway sentinel (Docker 20.10+) makes it
    // resolve explicitly regardless — harmless on phases that never use it.
    "--add-host", "host.docker.internal:host-gateway",
  ];

  for (const capName of profile.caps) {
    args.push("--cap-add", capName);
  }

  for (const [k, v] of Object.entries(profile.env || {})) {
    args.push("-e", `${k}=${v}`);
  }

  args.push(profile.image);

  // Worker CLI args — all phase scripts share -d/-dl, -t convention
  if (opts.domain_list) {
    args.push("-dl", `/workspace/scans/${path.basename(opts.domain_list)}`);
  } else {
    args.push("-d", opts.domain);
  }
  args.push("-t", "/workspace/scans");

  if (phase === "recon" || phase === "webscan") {
    args.push("--threads", String(opts.threads ?? 10));
  }
  if (phase === "recon" && opts.scope_file) {
    // scope_file is the host-side path written by startPipeline
    // (scanDir/scope.txt) — same directory as /workspace/scans inside the
    // container, so just reference it by basename under that mount.
    args.push("--scope-file", `/workspace/scans/${path.basename(opts.scope_file)}`);
  }
  if (phase === "recon" && opts.target_url) {
    args.push("--seed", opts.target_url);
  }
  if (phase === "webscan" && opts.skip_nuclei) {
    args.push("--skip-nuclei");
  }
  if (phase === "report") {
    if (opts.llm_url) args.push("--llm-url", opts.llm_url);
    if (opts.llm_model) args.push("--llm-model", opts.llm_model);
    if (opts.team_name) args.push("--team-name", opts.team_name);
    if (opts.client_name) args.push("--client-name", opts.client_name);
  }

  return args;
}

// ─── Spawn a phase container, return container ID immediately ──────────────
function spawnPhase(phase, scanDir, opts) {
  const args = buildDockerArgs(phase, scanDir, opts);
  const out = execSync(`docker ${args.map(a => `'${a.replace(/'/g, `'\\''`)}'`).join(" ")}`)
    .toString().trim();
  // `docker run -d` prints the container ID on success
  const containerId = out.split("\n").pop();
  return containerId;
}

// ─── Wait for a container to exit, return exit code ──────────────────────────
function waitForContainer(containerId, { onTick } = {}) {
  return new Promise((resolve, reject) => {
    const poll = setInterval(() => {
      let state;
      try {
        state = execSync(
          `docker inspect --format='{{.State.Status}}|{{.State.ExitCode}}' ${containerId} 2>/dev/null`
        ).toString().trim();
      } catch {
        // Container already removed (--rm) — assume it finished; we can't
        // recover exit code in this race, treat as success if checkpoint
        // wasn't already marked running->failed by stale detection.
        clearInterval(poll);
        resolve(0);
        return;
      }

      const [status, exitCodeStr] = state.split("|");
      if (onTick) onTick(status);

      if (status === "exited") {
        clearInterval(poll);
        resolve(parseInt(exitCodeStr, 10));
      }
    }, 5000); // poll every 5s — cheap, doesn't compete with worker for resources
  });
}

// ─── CIDR/IP-range scan: simplified 2-phase pipeline (network -> webscan) ───
// Bypasses the domain-based 5-phase checkpoint entirely. Used for DMZ/IP-space
// sweeps where there are no hostnames to drive recon/xss/report-with-findings.
// Writes a minimal checkpoint (network + webscan only) so status/resume still
// work, using the same atomic read/write/stale-detection machinery.
const CIDR_PHASE_ORDER = ["network", "webscan"];

export function createCidrCheckpoint(scanDir, { project, cidr, options }) {
  const checkpoint = {
    schema_version: 1,
    project,
    domain: cidr, // reuse the "domain" field to store the CIDR/IP target
    mode: "cidr",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    options: { cidr, ...options },
    phases: {},
  };
  for (const phase of CIDR_PHASE_ORDER) {
    checkpoint.phases[phase] = {
      status: "pending", started_at: null, completed_at: null,
      container_id: null, exit_code: null, outputs: [],
    };
  }
  cp.writeCheckpoint(scanDir, checkpoint);
  return checkpoint;
}

function buildCidrDockerArgs(phase, scanDir, cidrInput) {
  const profile = getProfile()[phase];
  const args = [
    "run", "--rm", "-d",
    "--memory", profile.memory,
    "--memory-swap", profile.memory,
    "-v", `${hostScanDir(scanDir)}:/workspace/scans`,
  ];
  for (const capName of profile.caps) args.push("--cap-add", capName);
  for (const [k, v] of Object.entries(profile.env || {})) args.push("-e", `${k}=${v}`);
  args.push(profile.image, "--cidr", cidrInput, "-t", "/workspace/scans");
  if (phase === "webscan") args.push("--threads", "10");
  return args;
}

// Matches a bare IPv4 address or IPv4 CIDR (mirrors index.js's IPV4_OR_CIDR_RE).
// Used to tell a real IP/CIDR target apart from a file path.
const IPV4_OR_CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

// CIDR mode reuses the same prefix derivation as the phase scripts:
// tr '/.' '_-' applied to the CIDR string (or file basename).
//
// The worker decides file-vs-string with `[ -f "$cidr_input" ]` inside the
// container. We can't replicate that here (a file target is passed as a
// container-internal path like /workspace/scans/ip-targets.txt that doesn't
// exist from the orchestrator's view), so we treat anything that isn't a bare
// IP/CIDR but looks like a path as a file and use its basename — matching the
// worker's basename branch. fsExists stays as a fallback for host-visible paths.
export function cidrPrefix(cidrInput) {
  const raw = String(cidrInput).trim();
  const looksLikePath = raw.includes("/") && !IPV4_OR_CIDR_RE.test(raw);
  const useBasename = looksLikePath || fsExists(raw);
  const base = useBasename ? path.basename(raw) : raw;
  return base.replace(/[/.]/g, (c) => (c === "/" ? "_" : "-"));
}

function fsExists(p) {
  try { return fs.existsSync(p); } catch { return false; }
}

const CIDR_REQUIRED_OUTPUTS = {
  network: ["resolved.log", "unique-ips.log", "naabu.log"],
  webscan: ["nucleiAlerts.log", "dirsearch.log", "nmapvulners.log"],
};

export async function runCidrPipeline(scanDir, cidrInput) {
  let checkpoint = cp.readCheckpoint(scanDir);
  cp.detectStale(scanDir, checkpoint);
  checkpoint = cp.readCheckpoint(scanDir);

  const prefix = cidrPrefix(cidrInput);

  for (const phase of CIDR_PHASE_ORDER) {
    if (["done", "skipped"].includes(checkpoint.phases[phase].status)) continue;

    // pause_after: if set to this phase (or already past it), stop before
    // spawning. Checked fresh each iteration so a pause requested mid-run
    // takes effect before the *next* phase, without killing the current one.
    if (checkpoint.pause_after && CIDR_PHASE_ORDER.indexOf(checkpoint.pause_after) < CIDR_PHASE_ORDER.indexOf(phase)) {
      break;
    }
    if (checkpoint.pause_after === phase) {
      // Run this phase, then stop before the next.
    }

    const args = buildCidrDockerArgs(phase, scanDir, cidrInput);
    const containerId = execSync(`docker ${args.map(a => `'${a.replace(/'/g, `'\\''`)}'`).join(" ")}`)
      .toString().trim().split("\n").pop();

    cp.markRunning(checkpoint, phase, containerId);
    cp.writeCheckpoint(scanDir, checkpoint);

    const exitCode = await waitForContainer(containerId);
    checkpoint = cp.readCheckpoint(scanDir);

    // Validate against CIDR-specific required outputs, with the CIDR-derived
    // prefix (not the domain prefix from validateOutputs).
    const missing = [];
    const present = [];
    for (const suffix of CIDR_REQUIRED_OUTPUTS[phase]) {
      const fname = `${prefix}-${suffix}`;
      if (fs.existsSync(path.join(scanDir, fname))) present.push(fname);
      else missing.push(fname);
    }
    cp.markResult(checkpoint, phase, { exitCode, outputsCheck: { ok: missing.length === 0, missing, present } });
    cp.writeCheckpoint(scanDir, checkpoint);

    if (checkpoint.phases[phase].status === "failed") break;
    if (checkpoint.pause_after === phase) break;
  }

  return checkpoint;
}

// ─── Run a single phase end-to-end: spawn, wait, validate, checkpoint ───────
export async function runPhase(scanDir, phase, opts) {
  let checkpoint = cp.readCheckpoint(scanDir);

  // Skip if already done/skipped
  if (["done", "skipped"].includes(checkpoint.phases[phase].status)) {
    return { phase, skipped: true, checkpoint };
  }

  const containerId = spawnPhase(phase, scanDir, opts);
  cp.markRunning(checkpoint, phase, containerId);
  cp.writeCheckpoint(scanDir, checkpoint);

  const exitCode = await waitForContainer(containerId);

  // Re-read in case stale detection or a stop request touched it while running
  checkpoint = cp.readCheckpoint(scanDir);

  const prefix = opts.domain_list
    ? path.basename(opts.domain_list)
    : opts.domain;
  const outputsCheck = cp.validateOutputs(scanDir, phase, prefix);

  cp.markResult(checkpoint, phase, { exitCode, outputsCheck });
  cp.writeCheckpoint(scanDir, checkpoint);

  return { phase, skipped: false, exitCode, outputsCheck, checkpoint };
}

// ─── Run the full pipeline from the next pending phase onward ───────────────
// Stops (does not throw) if a phase fails — caller (MCP tool) reports status.
// This is also what "resume" calls: nextPendingPhase() naturally skips
// already-`done` phases.
export async function runPipeline(scanDir, opts) {
  const results = [];
  let checkpoint = cp.readCheckpoint(scanDir);
  cp.detectStale(scanDir, checkpoint);
  checkpoint = cp.readCheckpoint(scanDir);

  while (true) {
    const phase = cp.nextPendingPhase(checkpoint);
    if (!phase) break;

    // pause_after: stop before spawning a phase beyond the requested pause
    // point. Re-read each iteration so a pause requested mid-run is honored
    // before the next phase, without killing the current one.
    if (checkpoint.pause_after && cp.PHASE_ORDER.indexOf(checkpoint.pause_after) < cp.PHASE_ORDER.indexOf(phase)) {
      break;
    }

    const result = await runPhase(scanDir, phase, opts);
    results.push(result);
    checkpoint = result.checkpoint;

    if (!result.skipped && result.checkpoint.phases[phase].status === "failed") {
      break; // stop pipeline on first failure; resumable later
    }
    if (checkpoint.pause_after === phase) break;
  }

  return { results, checkpoint };
}

// ─── Stop a running phase ────────────────────────────────────────────────────
export function stopPhase(scanDir) {
  const checkpoint = cp.readCheckpoint(scanDir);
  // Mode-aware: a CIDR checkpoint only has network+webscan phases. Iterating the
  // 5-phase domain order would hit checkpoint.phases.recon === undefined and
  // throw on `.status` before ever reaching the running phase — which is why
  // kuromaku_stop silently failed on IP/CIDR scans. The `if (!p) continue` guard
  // keeps it safe even if the two ever drift again.
  const order = checkpoint.mode === "cidr" ? CIDR_PHASE_ORDER : cp.PHASE_ORDER;
  for (const phase of order) {
    const p = checkpoint.phases[phase];
    if (!p) continue;
    if (p.status === "running" && p.container_id) {
      try {
        execSync(`docker kill ${p.container_id} 2>/dev/null`);
      } catch {
        // already stopped
      }
      p.status = "failed";
      p.error = "stopped by user";
      p.completed_at = new Date().toISOString();
      cp.writeCheckpoint(scanDir, checkpoint);
      return { phase, stopped: true };
    }
  }
  return { phase: null, stopped: false, message: "no phase currently running" };
}
