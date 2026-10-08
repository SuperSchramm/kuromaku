// checkpoint.js — Kuromaku orchestrator
// Implements the .checkpoint schema defined in CHECKPOINT_SCHEMA.md.
// All reads/writes go through this module so the file format stays
// consistent and atomic writes prevent corruption from concurrent access.

import fs from "fs";
import path from "path";
import { execSync } from "child_process";

export const PHASE_ORDER = ["recon", "network", "webscan", "xss", "report"];

export const REQUIRED_OUTPUTS = {
  recon:   ["uniqdomains.log", "domains_only.log"],
  network: ["resolved.log", "unique-ips.log", "naabu.log"],
  webscan: ["nucleiAlerts.log", "dirsearch.log", "nmapvulners.log"],
  xss:     ["dalfox.log"],
  report:  ["report.docx"],
};

export const STALE_THRESHOLD_MS = 30 * 60 * 1000; // 30 minutes

function checkpointPath(scanDir) {
  return path.join(scanDir, ".checkpoint");
}

function emptyPhase() {
  return {
    status: "pending",
    started_at: null,
    completed_at: null,
    container_id: null,
    exit_code: null,
    outputs: [],
  };
}

export function checkpointExists(scanDir) {
  return fs.existsSync(checkpointPath(scanDir));
}

export function createCheckpoint(scanDir, { project, domain, options }) {
  const cp = {
    schema_version: 1,
    project,
    domain,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    options: {
      threads: options?.threads ?? 10,
      skip_xss: options?.skip_xss ?? false,
      skip_nuclei: options?.skip_nuclei ?? false,
      ...options,
    },
    phases: {},
  };
  for (const phase of PHASE_ORDER) {
    cp.phases[phase] = emptyPhase();
    if (phase === "xss" && cp.options.skip_xss) cp.phases[phase].status = "skipped";
    if (phase === "webscan" && cp.options.skip_nuclei) {
      // skip_nuclei only skips the nuclei portion within webscan, not the
      // whole phase (nmap/dirsearch still run) — phase stays pending.
    }
  }
  writeCheckpoint(scanDir, cp);
  return cp;
}

export function readCheckpoint(scanDir) {
  const p = checkpointPath(scanDir);
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, "utf-8"));
  } catch (e) {
    throw new Error(`Checkpoint file corrupt at ${p}: ${e.message}`);
  }
}

export function writeCheckpoint(scanDir, cp) {
  cp.updated_at = new Date().toISOString();
  const p = checkpointPath(scanDir);
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cp, null, 2));
  fs.renameSync(tmp, p); // atomic on same filesystem
  return cp;
}

// ─── Stale detection ─────────────────────────────────────────────────────────
// If a phase is "running" but its container is no longer running AND
// started_at is older than STALE_THRESHOLD_MS, mark it "failed".
// Returns the (possibly updated) checkpoint. Idempotent.
export function detectStale(scanDir, cp) {
  let changed = false;
  const order = cp.mode === "cidr" ? CIDR_PHASE_ORDER : PHASE_ORDER;

  for (const phase of order) {
    const p = cp.phases[phase];
    if (p.status !== "running") continue;

    const startedAt = p.started_at ? new Date(p.started_at).getTime() : 0;
    const age = Date.now() - startedAt;

    let containerAlive = false;
    if (p.container_id) {
      try {
        const out = execSync(
          `docker inspect --format='{{.State.Running}}' ${p.container_id} 2>/dev/null`
        ).toString().trim();
        containerAlive = out === "true";
      } catch {
        containerAlive = false;
      }
    }

    if (!containerAlive && age > STALE_THRESHOLD_MS) {
      p.status = "failed";
      p.error = "stale — worker container no longer running";
      p.completed_at = new Date().toISOString();
      changed = true;
    }
  }

  if (changed) writeCheckpoint(scanDir, cp);
  return cp;
}

// ─── Output validation ──────────────────────────────────────────────────────
// Returns { ok: bool, missing: [...], present: [...] }
export function validateOutputs(scanDir, phase, prefix) {
  const required = REQUIRED_OUTPUTS[phase] || [];
  const missing = [];
  const present = [];

  for (const suffix of required) {
    // report phase output has no domain prefix (single report.docx)
    const filename = phase === "report" ? suffix : `${prefix}-${suffix}`;
    const full = path.join(scanDir, filename);
    if (fs.existsSync(full) && fs.statSync(full).size >= 0) {
      // size >= 0 allows zero-byte files for phases where "empty" is valid
      // (e.g. dalfox.log with no findings). Existence is what we check here;
      // phase-specific "must be non-empty" rules are handled by the phase
      // scripts themselves writing placeholder content when appropriate.
      present.push(filename);
    } else {
      missing.push(filename);
    }
  }

  return { ok: missing.length === 0, missing, present };
}

// ─── Phase dispatch helpers ──────────────────────────────────────────────────
export function nextPendingPhase(cp) {
  for (const phase of PHASE_ORDER) {
    const status = cp.phases[phase].status;
    if (status === "pending" || status === "failed") return phase;
  }
  return null; // all done or skipped
}

export function allPhasesDone(cp) {
  return PHASE_ORDER.every(
    (phase) => ["done", "skipped"].includes(cp.phases[phase].status)
  );
}

export function markRunning(cp, phase, containerId) {
  cp.phases[phase].status = "running";
  cp.phases[phase].started_at = new Date().toISOString();
  cp.phases[phase].completed_at = null;
  cp.phases[phase].container_id = containerId;
  cp.phases[phase].exit_code = null;
  delete cp.phases[phase].error;
  return cp;
}

export function markResult(cp, phase, { exitCode, outputsCheck }) {
  cp.phases[phase].completed_at = new Date().toISOString();
  cp.phases[phase].exit_code = exitCode;
  cp.phases[phase].outputs = outputsCheck.present;

  if (exitCode === 0 && outputsCheck.ok) {
    cp.phases[phase].status = "done";
    delete cp.phases[phase].error;
  } else {
    cp.phases[phase].status = "failed";
    if (exitCode !== 0) {
      cp.phases[phase].error = `worker exited ${exitCode}`;
    } else {
      cp.phases[phase].error = `missing expected outputs: ${outputsCheck.missing.join(", ")}`;
    }
  }
  return cp;
}

export const CIDR_PHASE_ORDER = ["network", "webscan"];

// ─── Pause control ────────────────────────────────────────────────────────
// pause_after: name of a phase. The running pipeline checks this before
// spawning each subsequent phase and stops cleanly once the named phase
// completes — the current phase is never killed, only the *next* one is
// withheld. Distinct from kuromaku_stop, which kills the in-flight
// container immediately.
export function setPauseAfter(scanDir, phase) {
  const checkpoint = readCheckpoint(scanDir);
  const order = checkpoint.mode === "cidr" ? CIDR_PHASE_ORDER : PHASE_ORDER;
  if (phase !== null && !order.includes(phase)) {
    throw new Error(`Unknown phase '${phase}'. Valid: ${order.join(", ")}`);
  }
  checkpoint.pause_after = phase;
  writeCheckpoint(scanDir, checkpoint);
  return checkpoint;
}

export function summarize(cp) {
  const order = cp.mode === "cidr" ? CIDR_PHASE_ORDER : PHASE_ORDER;
  const lines = [
    `Project: ${cp.project}`,
    `Target:  ${cp.domain}${cp.mode === "cidr" ? " (IP/CIDR scan)" : ""}`,
    `Updated: ${cp.updated_at}`,
    ``,
    `Phases:`,
  ];
  for (const phase of order) {
    const p = cp.phases[phase];
    let marker = { pending: "○", running: "●", done: "✓", failed: "✗", skipped: "—" }[p.status] || "?";
    let extra = "";
    if (p.status === "running" && p.started_at) {
      const mins = Math.round((Date.now() - new Date(p.started_at).getTime()) / 60000);
      extra = ` (running ${mins}m)`;
    }
    if (p.status === "failed" && p.error) {
      extra = ` — ${p.error}`;
    }
    if (p.status === "done" && p.outputs?.length) {
      extra = ` (${p.outputs.length} output files)`;
    }
    lines.push(`  ${marker} ${phase}${extra}`);
    if (cp.pause_after === phase) {
      lines.push(`     ⏸ pipeline paused after this phase`);
    }
  }
  if (cp.pause_after && !order.includes(cp.pause_after)) {
    // shouldn't happen, but don't silently drop info if it does
    lines.push(`  (pause_after set to unrecognized phase: ${cp.pause_after})`);
  }
  return lines.join("\n");
}
