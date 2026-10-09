// index.js — Kuromaku Orchestrator MCP Server
// stdio mode (Claude Desktop) by default; HTTP/SSE mode if MCP_HTTP=true
// (LM Studio / mcphost), via Streamable HTTP transport — same pattern as
// the v1 orchestrator.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import fs from "fs";
import path from "path";

import * as cp from "./checkpoint.js";
import * as orch from "./orchestrator.js";

const PROJECTS_DIR = process.env.PROJECTS_DIR || "/workspace/projects";

// Staging folder for large target lists. A caller (or LLM) drops a file with
// one IP/CIDR per line here, then passes just its name via ips_file — far more
// reliable than inlining ~1000 entries in an `ips` array, which the model
// truncates mid-generation. Created unconditionally so it always exists.
const INCOMING_DIR = path.join(PROJECTS_DIR, "_incoming");
try { fs.mkdirSync(INCOMING_DIR, { recursive: true }); } catch { /* best effort */ }

// Live detail for kuromaku_status: tail of the progress log, how long since it
// last changed, and any partial nuclei output — so a long phase is observable
// without docker logs. Pure file reads; never throws.
function liveDetail(scanDir) {
  const out = [];
  try {
    const logPath = path.join(scanDir, "kuromaku_progress.log");
    if (fs.existsSync(logPath)) {
      const st = fs.statSync(logPath);
      const ageS = Math.round((Date.now() - st.mtimeMs) / 1000);
      const tail = fs.readFileSync(logPath, "utf-8").split("\n").filter(Boolean).slice(-15);
      out.push("", `Progress log (last ${tail.length} lines; last write ${ageS}s ago):`, ...tail.map(l => "  " + l));
      if (ageS > 300) out.push(`  ⚠ no log output for ${Math.round(ageS / 60)}m — phase may be stalled`);
    }
    for (const f of fs.readdirSync(scanDir)) {
      if (f.endsWith("-nuclei-batch.log")) {
        const n = fs.readFileSync(path.join(scanDir, f), "utf-8").split("\n").filter(Boolean).length;
        out.push("", `Nuclei in-flight batch findings so far: ${n} (${f})`);
      }
    }
  } catch { /* best-effort */ }
  return out.join("\n");
}

function scanDirFor(projectName) {
  return path.join(PROJECTS_DIR, projectName, "scans");
}

// Resolve an ips_file reference to an orchestrator-visible path. Accepts an
// absolute/relative path as given, or a bare filename looked up (in order) in
// the _incoming staging dir, the project's own scan dir, then PROJECTS_DIR.
// Returns the first existing path, or null with the list of places searched.
function resolveIpsFile(ref, scanDir) {
  const candidates = [
    ref,
    path.join(INCOMING_DIR, path.basename(ref)),
    path.join(scanDir, path.basename(ref)),
    path.join(PROJECTS_DIR, path.basename(ref)),
  ];
  for (const c of candidates) {
    try { if (fs.existsSync(c) && fs.statSync(c).isFile()) return { path: c, searched: candidates }; } catch { /* ignore */ }
  }
  return { path: null, searched: candidates };
}

function ensureProjectDirs(projectName) {
  const base = path.join(PROJECTS_DIR, projectName);
  for (const d of ["recon", "scans", "exploits", "findings", "loot", "notes", "wordlists"]) {
    fs.mkdirSync(path.join(base, d), { recursive: true });
  }
  return base;
}

// ─── Tool definitions ──────────────────────────────────────────────────────
const TOOL_LIST = [
  {
    name: "kuromaku_run",
    description:
      "Start a Kuromaku scan pipeline (recon -> network -> webscan -> xss -> report) " +
      "against a domain. Creates a project + checkpoint if not present. If a checkpoint " +
      "already exists and all phases are done, this is a no-op — use kuromaku_resume " +
      "with force=true to re-run. Runs in the background; returns immediately. " +
      "Use kuromaku_status to monitor. If 'domain' is actually a bare IP or CIDR " +
      "(e.g. 206.130.144.1 or 206.130.144.0/24, including a single-host /32), this " +
      "tool auto-detects that and transparently runs the IP-scan pipeline instead " +
      "(same as calling kuromaku_ip_scan directly) — domain-only tools like subfinder/" +
      "amass/gau/nuclei/dirsearch are skipped since they don't apply to a bare IP; " +
      "only naabu + nmap run. Prefer calling kuromaku_ip_scan directly for IP/CIDR targets.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target domain (e.g. acme.com) — must have written authorization. A bare IP or CIDR (e.g. 10.0.0.5 or 10.0.0.0/24) is also accepted and auto-routed to the IP-scan pipeline." },
        project_name: { type: "string", description: "Project folder name (defaults to domain)" },
        threads: { type: "number", description: "Threads for recon/webscan workers (default 10)", default: 10 },
        skip_xss: { type: "boolean", default: false },
        skip_nuclei: { type: "boolean", default: false },
        llm_url: { type: "string", description: "LM Studio OpenAI-compatible URL for report exec summary" },
        llm_model: { type: "string", description: "Model name for report exec summary" },
        scope: {
          type: "array",
          items: { type: "string" },
          description:
            "In-scope domain patterns for bug bounty program scope compliance " +
            "(e.g. from Bugcrowd/HackerOne). Each entry is a glob pattern: " +
            "'example.com' matches only that exact host; '*.example.com' matches " +
            "any subdomain (not the apex). Include both forms if both are in " +
            "scope. The target domain itself is NOT auto-included — list it " +
            "explicitly if it should be scanned. If provided, ALL discovered " +
            "domains outside this list are dropped before network/webscan/xss run.",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "kuromaku_status",
    description:
      "Read the current checkpoint for a project — pure file read, no container " +
      "interaction. Runs stale-detection (marks dead 'running' phases as 'failed'). " +
      "Returns a phase-by-phase summary.",
    inputSchema: {
      type: "object",
      properties: {
        project_name: { type: "string" },
      },
      required: ["project_name"],
    },
  },
  {
    name: "kuromaku_pause",
    description:
      "Set or clear a pause point for a project's pipeline. If a phase is " +
      "currently running, it completes normally; the pipeline then stops " +
      "before starting the next phase. Unlike kuromaku_stop, this does " +
      "not kill the in-flight container. Use kuromaku_resume afterward " +
      "to continue (clears the pause automatically). Pass phase=null (or " +
      "omit) to clear an existing pause without changing anything else.",
    inputSchema: {
      type: "object",
      properties: {
        project_name: { type: "string" },
        phase: { type: "string", description: "Phase to pause after: recon, network, webscan, xss, report (domain mode) or network, webscan (CIDR mode). Omit/null to clear." },
      },
      required: ["project_name"],
    },
  },
  {
    name: "kuromaku_resume",
    description:
      "Resume a scan from the first 'pending' or 'failed' phase. Phases already " +
      "'done' are skipped entirely — no container spawned for them. Use force=true " +
      "to re-run from 'recon' even if all phases are 'done' (overwrites checkpoint).",
    inputSchema: {
      type: "object",
      properties: {
        project_name: { type: "string" },
        force: { type: "boolean", default: false, description: "Reset all phases to pending and restart from recon" },
      },
      required: ["project_name"],
    },
  },
  {
    name: "kuromaku_stop",
    description:
      "Stop the currently-running phase for a project. Kills the worker container " +
      "and marks that phase 'failed' with error 'stopped by user', making it eligible " +
      "for resume.",
    inputSchema: {
      type: "object",
      properties: {
        project_name: { type: "string" },
      },
      required: ["project_name"],
    },
  },
  {
    name: "kuromaku_results",
    description:
      "Read output files from a project's scan directory. With no 'file' argument, " +
      "returns a summary of line counts across key output files. With 'file', returns " +
      "the contents of that specific file (capped at max_lines).",
    inputSchema: {
      type: "object",
      properties: {
        project_name: { type: "string" },
        file: { type: "string", description: "One of: uniqdomains, uniqueips, naabu, nucleiAlerts, dirsearch, nmapvulners, dalfox, resolved, report, outOfScope" },
        max_lines: { type: "number", default: 100 },
      },
      required: ["project_name"],
    },
  },
  {
    name: "kuromaku_report",
    description:
      "Assemble a FULL results report for a project — concatenates every output " +
      "file that HAS DATA, in scan order, with a labeled section per file. Empty " +
      "or not-yet-produced files are omitted entirely. Returns the report inline " +
      "by default; with export:true it is instead written to the scan volume as " +
      "<prefix>-results-report.md (prefer this for large scans, e.g. big nmap " +
      "output). Use kuromaku_results for the quick line-count summary or a single file.",
    inputSchema: {
      type: "object",
      properties: {
        project_name: { type: "string" },
        export: { type: "boolean", description: "Write the report to the scan directory as <prefix>-results-report.md instead of returning it inline. Recommended for large scans." },
      },
      required: ["project_name"],
    },
  },
  {
    name: "kuromaku_new_project",
    description: "Create a new bug bounty project folder structure (without starting a scan).",
    inputSchema: {
      type: "object",
      properties: {
        project_name: { type: "string" },
      },
      required: ["project_name"],
    },
  },
  {
    name: "kuromaku_ip_scan",
    description:
      "Scan an IP address, CIDR range, or IP list for open ports and service " +
      "fingerprints — for DMZ/network exposure audits (e.g. 'is anything " +
      "exposed on 206.130.144.0/24 beyond what's approved?'). Runs a 2-phase " +
      "pipeline: network (naabu port scan) -> webscan (nmap service/version " +
      "detection, vulners script). No hostname-based steps (recon/dirsearch/" +
      "nuclei/xss) — this is IP-space only. Creates its own lightweight " +
      "checkpoint; use kuromaku_status with the same project_name to monitor. " +
      "To scan MANY targets, pass them inline via `ips` — do NOT invent a file " +
      "path for `cidr`, since a host path isn't visible inside the worker " +
      "containers unless the orchestrator places it there for you.",
    inputSchema: {
      type: "object",
      properties: {
        ips_file: { type: "string", description: "BEST for large lists (hundreds+ of targets): the name of a file (one IP/CIDR per line) that the user has placed in the _incoming staging folder (projects/_incoming/). Pass just the filename, e.g. \"targets.txt\" — the orchestrator reads the WHOLE file, so nothing is truncated. Use this instead of `ips` when there are more than a few dozen targets, since an inline array gets cut off mid-generation." },
        ips: {
          type: "array",
          items: { type: "string" },
          description: "Good for a handful of targets: an array of IPs/CIDRs (one per element, e.g. [\"10.0.0.5\", \"206.130.144.0/24\"]). For hundreds of targets use `ips_file` instead — a long inline array gets truncated.",
        },
        cidr: { type: "string", description: "A single CIDR (206.130.144.0/24), a single IP, or the path to an EXISTING file (readable by the orchestrator) with one CIDR/IP per line. For many targets prefer `ips_file`." },
        project_name: { type: "string", description: "Project folder name (required — used for output file naming and checkpoint)" },
      },
      required: ["project_name"],
    },
  },
  {
    name: "kuromaku_list_projects",
    description: "List all projects and their checkpoint status (if any).",
    inputSchema: { type: "object", properties: {} },
  },
];

// ─── In-memory map of project_name -> in-flight pipeline promise ────────────
// Prevents double-spawning if run/resume is called twice rapidly for the
// same project while a pipeline is already executing in this process.
const activePipelines = new Map();

// Matches a bare IPv4 address or an IPv4 CIDR (any prefix length, including
// /32 — a single-host CIDR). Does not validate octet ranges (0-255); naabu/
// nmap will reject a malformed address themselves, and over-matching here is
// harmless since the only effect is routing to the IP-scan pipeline instead
// of the domain pipeline.
const IPV4_OR_CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

function isIpOrCidr(str) {
  return typeof str === "string" && IPV4_OR_CIDR_RE.test(str.trim());
}

function findPrefix(scanDir, cpData) {
  // CIDR mode: output files are named with the cidrPrefix() derivation applied
  // to options.cidr (the worker-visible target), NOT the human-readable
  // `domain` field — which may be a label like "3 target(s) (inline ips list)".
  // Must use the same derivation the pipeline/workers use or every file lookup
  // misses and kuromaku_results reports "no results" for a scan that produced
  // plenty (see git history: this exact mismatch).
  if (cpData.mode === "cidr") {
    return orch.cidrPrefix(cpData.options.cidr);
  }
  // domain_list mode stores basename; domain mode stores the domain itself.
  return cpData.options.domain_list
    ? path.basename(cpData.options.domain_list)
    : cpData.domain;
}

// Single source of truth for a project's output filenames (keyed by the names
// exposed through kuromaku_results `file` and used by kuromaku_report).
function outputFileMap(prefix) {
  return {
    resolved: `${prefix}-resolved.log`,
    uniqdomains: `${prefix}-uniqdomains.log`,
    outOfScope: `${prefix}-out-of-scope.log`,
    uniqueips: `${prefix}-unique-ips.log`,
    naabu: `${prefix}-naabu.log`,
    nmapvulners: `${prefix}-nmapvulners.log`,
    nucleiAlerts: `${prefix}-nucleiAlerts.log`,
    dirsearch: `${prefix}-dirsearch.log`,
    dalfox: `${prefix}-dalfox.log`,
    report: `${prefix}-report.docx`,
  };
}

// Human-readable section headings for the assembled report.
const FILE_LABELS = {
  resolved: "DNS Resolution",
  uniqdomains: "Unique Subdomains",
  outOfScope: "Out-of-Scope Hosts Dropped (recon found these but scope excluded them)",
  uniqueips: "Unique IPs",
  naabu: "Open Ports (naabu)",
  nmapvulners: "Service & Vulnerability Detection (nmap + vulners)",
  nucleiAlerts: "Nuclei Findings",
  dirsearch: "Directory Brute-force (dirsearch)",
  dalfox: "Reflected-XSS Candidates (dalfox)",
  report: "DOCX Report",
};

// Walk the output files for a project and split them into sections that have
// data vs. files that are empty/absent. The binary DOCX report is referenced
// by path rather than inlined.
function assembleReport(scanDir, prefix) {
  const fileMap = outputFileMap(prefix);
  const included = [];
  const skipped = [];
  for (const [key, fname] of Object.entries(fileMap)) {
    const full = path.join(scanDir, fname);
    if (!fs.existsSync(full)) { skipped.push(key); continue; }
    if (key === "report") {
      const size = fs.statSync(full).size;
      if (size > 0) included.push({ key, note: `DOCX report: ${fname} (${size} bytes) — open on the host.` });
      else skipped.push(key);
      continue;
    }
    const content = fs.readFileSync(full, "utf-8");
    const count = content.split("\n").filter((l) => l.trim()).length;
    if (count === 0) { skipped.push(key); continue; }
    included.push({ key, count, content: content.replace(/\s+$/, "") });
  }
  return { fileMap, included, skipped };
}

// Shared by kuromaku_ip_scan and kuromaku_run's IP/CIDR auto-redirect below.
// `redirected` just changes the returned message so it's clear to the caller
// (human or LLM) why a "run" request ended up on the 2-phase IP pipeline
// instead of the 5-phase domain pipeline.
function runIpScan(cidr, projectNameRaw, redirected, ips, ipsFile) {
  const projectName = projectNameRaw.replace(/[^a-zA-Z0-9_-]/g, "-");
  ensureProjectDirs(projectName);
  const scanDir = scanDirFor(projectName);
  fs.mkdirSync(scanDir, { recursive: true });

  // Most robust path for large lists: a file the user staged. The orchestrator
  // reads the ENTIRE file, so the target count can't be truncated the way an
  // inline `ips` array is when a model stops emitting mid-array.
  if (ipsFile) {
    const resolved = resolveIpsFile(ipsFile, scanDir);
    if (!resolved.path) {
      return { content: [{ type: "text", text:
        `ips_file '${ipsFile}' not found. Place the list (one IP/CIDR per line) in the ` +
        `staging folder and pass just its filename. Looked in:\n  ` +
        resolved.searched.join("\n  ") + `\n\nThe simplest location is ${INCOMING_DIR}/${path.basename(ipsFile)}.`,
      }] };
    }
    const contents = fs.readFileSync(resolved.path, "utf8");
    const cleaned = contents.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    if (cleaned.length === 0) {
      return { content: [{ type: "text", text: `ips_file '${resolved.path}' contained no usable IP/CIDR entries.` }] };
    }
    fs.writeFileSync(path.join(scanDir, "ip-targets.txt"), cleaned.join("\n") + "\n");
    const execTarget = `/workspace/scans/ip-targets.txt`;
    const displayTarget = `${cleaned.length} target(s) (from ${path.basename(resolved.path)})`;
    return launchCidrPipeline(scanDir, projectName, execTarget, displayTarget, redirected);
  }

  // Resolve the target the worker containers will actually receive. A bare
  // IP/CIDR is passed through verbatim. A FILE of targets, however, lives on
  // the orchestrator's filesystem and is NOT visible inside the worker
  // containers (only <scanDir>:/workspace/scans is mounted). So copy it into
  // the scan dir under a fixed name and hand the workers the container-internal
  // path — otherwise `[ -f "$cidr_input" ]` is false in the worker, the path
  // string gets treated as a single host, and naabu/nmap scan nothing (the
  // "found 0 IPs for a 1200-IP list" bug).
  let execTarget;        // what the worker containers receive via --cidr
  let displayTarget;     // what we show the user / store as checkpoint `domain`

  // Preferred path for multi-target scans: an inline `ips` array. We write it
  // straight into the scan dir (the one mount the workers can see) and hand
  // them the container-internal path — no host file path to guess, no mount
  // surprises. This is the documented, correct way for an LLM caller to pass
  // a list of IPs.
  if (Array.isArray(ips) && ips.length > 0) {
    const cleaned = ips.map((x) => String(x).trim()).filter((x) => x && !x.startsWith("#"));
    if (cleaned.length === 0) {
      return { content: [{ type: "text", text: "`ips` was provided but contained no usable IP/CIDR entries." }] };
    }
    const destName = "ip-targets.txt";
    fs.writeFileSync(path.join(scanDir, destName), cleaned.join("\n") + "\n");
    execTarget = `/workspace/scans/${destName}`;
    displayTarget = `${cleaned.length} target(s) (inline ips list)`;
    return launchCidrPipeline(scanDir, projectName, execTarget, displayTarget, redirected);
  }

  const cidrStr = String(cidr).trim();
  execTarget = cidrStr;
  displayTarget = cidrStr;
  if (!isIpOrCidr(cidrStr)) {
    if (!fs.existsSync(cidrStr)) {
      return { content: [{ type: "text", text:
        `'${cidrStr}' is neither a valid IP/CIDR nor an existing file path.\n\n` +
        `For an IP list, pass a file with one IP/CIDR per line, and make sure the ` +
        `path is readable by the orchestrator container — the simplest place is ` +
        `under the mounted projects directory (e.g. ${path.join(PROJECTS_DIR, projectName)}/ip-targets.txt).`,
      }] };
    }
    try {
      const stat = fs.statSync(cidrStr);
      if (!stat.isFile()) throw new Error("not a regular file");
      const contents = fs.readFileSync(cidrStr, "utf8");
      if (contents.trim() === "") {
        return { content: [{ type: "text", text: `Target file '${cidrStr}' is empty — nothing to scan.` }] };
      }
      const destName = "ip-targets.txt";
      fs.writeFileSync(path.join(scanDir, destName), contents);
      execTarget = `/workspace/scans/${destName}`;
      displayTarget = `${path.basename(cidrStr)} (${contents.split("\n").filter((l) => l.trim()).length} targets)`;
    } catch (e) {
      return { content: [{ type: "text", text: `Could not read target file '${cidrStr}': ${e.message}` }] };
    }
  }

  return launchCidrPipeline(scanDir, projectName, execTarget, displayTarget, redirected);
}

// Shared tail of runIpScan: create/validate the checkpoint, kick off the CIDR
// pipeline, and build the user-facing status message. execTarget is the
// worker-visible target (--cidr); displayTarget is the human-readable label.
function launchCidrPipeline(scanDir, projectName, execTarget, displayTarget, redirected) {
  if (!cp.checkpointExists(scanDir)) {
    // Store execTarget in options.cidr (the pipeline + resume read it); keep
    // displayTarget as the human-facing `domain` field.
    orch.createCidrCheckpoint(scanDir, { project: projectName, cidr: displayTarget, options: { cidr: execTarget } });
  } else {
    const existing = cp.readCheckpoint(scanDir);
    if (existing.mode !== "cidr") {
      return { content: [{ type: "text", text: `Project '${projectName}' already has a domain-mode checkpoint. Use a different project_name for IP scans.` }] };
    }
  }

  const key = `cidr:${projectName}`;
  if (!activePipelines.has(key)) {
    const promise = orch.runCidrPipeline(scanDir, execTarget)
      .catch((e) => console.error(`[orchestrator] CIDR pipeline error for ${projectName}:`, e))
      .finally(() => activePipelines.delete(key));
    activePipelines.set(key, promise);
  }

  const lines = [];
  if (redirected) {
    lines.push(
      `'${displayTarget}' is an IP address/CIDR, not a hostname — domain-only tools ` +
      `(subfinder, amass, gau, nuclei, dirsearch) don't make sense against a ` +
      `bare IP, so this was routed to the IP-scan pipeline automatically.`,
      ``,
    );
  }
  lines.push(
    `IP scan started for '${displayTarget}' (project: ${projectName}).`,
    `Pipeline: network (naabu port scan) -> webscan (nmap service detection).`,
    `No hostname-based steps run for IP-space targets.`,
    ``,
    `Monitor with: kuromaku_status { "project_name": "${projectName}" }`,
    ``,
    `⚠ Only scan IP ranges you have explicit written authorization to test.`,
  );

  return { content: [{ type: "text", text: lines.join("\n") }] };
}

async function handleToolCall(name, args) {
  // ── kuromaku_new_project ────────────────────────────────────────────────────
  if (name === "kuromaku_new_project") {
    const safe = args.project_name.replace(/[^a-zA-Z0-9_-]/g, "-");
    const base = ensureProjectDirs(safe);
    const readme = `# Bug Bounty: ${args.project_name}\nCreated: ${new Date().toISOString()}\n`;
    fs.writeFileSync(path.join(base, "README.md"), readme);
    return { content: [{ type: "text", text: `Project created: ${base}` }] };
  }

  // ── kuromaku_ip_scan ─────────────────────────────────────────────────────────
  if (name === "kuromaku_ip_scan") {
    if (!args.project_name) {
      return { content: [{ type: "text", text: "project_name is required." }] };
    }
    if (!args.cidr && !args.ips_file && !(Array.isArray(args.ips) && args.ips.length > 0)) {
      return { content: [{ type: "text", text: "Provide one of: `ips_file` (a filename in projects/_incoming/ — best for large lists), `ips` (an array for a handful of targets), or `cidr` (a single IP/CIDR or an existing file path)." }] };
    }
    return runIpScan(args.cidr, args.project_name, false, args.ips, args.ips_file);
  }

  // ── kuromaku_list_projects ──────────────────────────────────────────────────
  if (name === "kuromaku_list_projects") {
    if (!fs.existsSync(PROJECTS_DIR)) {
      return { content: [{ type: "text", text: "No projects directory found." }] };
    }
    const projects = fs.readdirSync(PROJECTS_DIR).filter(p =>
      fs.statSync(path.join(PROJECTS_DIR, p)).isDirectory()
    );
    const lines = ["Projects:"];
    for (const proj of projects) {
      const scanDir = scanDirFor(proj);
      const cpData = cp.checkpointExists(scanDir) ? cp.readCheckpoint(scanDir) : null;
      if (!cpData) {
        lines.push(`  ${proj} — no scan started`);
      } else {
        const done = cp.PHASE_ORDER.filter(p => ["done","skipped"].includes(cpData.phases[p].status)).length;
        const running = cp.PHASE_ORDER.find(p => cpData.phases[p].status === "running");
        lines.push(`  ${proj} — ${done}/${cp.PHASE_ORDER.length} phases done${running ? ` (running: ${running})` : ""}`);
      }
    }
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }

  // ── kuromaku_run ─────────────────────────────────────────────────────
  if (name === "kuromaku_run") {
    // An IP or CIDR passed as "domain" can't go through recon (subfinder/
    // amass/gau are all hostname-based and would either fail or no-op on a
    // raw IP) — transparently redirect to the 2-phase IP pipeline instead of
    // starting a 5-phase domain pipeline that's guaranteed to misbehave.
    if (isIpOrCidr(args.domain)) {
      return runIpScan(args.domain, args.project_name || args.domain, true);
    }

    const projectName = (args.project_name || args.domain).replace(/[^a-zA-Z0-9_-]/g, "-");
    ensureProjectDirs(projectName);
    const scanDir = scanDirFor(projectName);
    fs.mkdirSync(scanDir, { recursive: true });

    if (cp.checkpointExists(scanDir)) {
      const existing = cp.readCheckpoint(scanDir);
      if (cp.allPhasesDone(existing)) {
        return {
          content: [{
            type: "text",
            text: `Project '${projectName}' already has a completed checkpoint.\n\n${cp.summarize(existing)}\n\nUse kuromaku_resume with force=true to re-run.`,
          }],
        };
      }
      // Existing incomplete checkpoint — treat run as resume.
    } else {
      cp.createCheckpoint(scanDir, {
        project: projectName,
        domain: args.domain,
        options: {
          threads: args.threads ?? 10,
          skip_xss: args.skip_xss ?? false,
          skip_nuclei: args.skip_nuclei ?? false,
          llm_url: args.llm_url,
          llm_model: args.llm_model,
          scope: args.scope,
        },
      });
    }

    return startPipeline(projectName, scanDir);
  }

  // ── kuromaku_pause ───────────────────────────────────────────────────
  if (name === "kuromaku_pause") {
    const scanDir = scanDirFor(args.project_name);
    if (!cp.checkpointExists(scanDir)) {
      return { content: [{ type: "text", text: `No checkpoint found for '${args.project_name}'.` }] };
    }
    const phase = args.phase || null;
    try {
      const checkpoint = cp.setPauseAfter(scanDir, phase);
      const msg = phase
        ? `Pipeline for '${args.project_name}' will pause after phase '${phase}' completes. The currently-running phase (if any) will finish normally.`
        : `Pause cleared for '${args.project_name}'.`;
      return { content: [{ type: "text", text: `${msg}\n\n${cp.summarize(checkpoint)}` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }] };
    }
  }

  // ── kuromaku_resume ──────────────────────────────────────────────────
  if (name === "kuromaku_resume") {
    const projectName = args.project_name;
    const scanDir = scanDirFor(projectName);

    if (!cp.checkpointExists(scanDir)) {
      return { content: [{ type: "text", text: `No checkpoint found for '${projectName}'. Use kuromaku_run first.` }] };
    }

    let checkpoint = cp.readCheckpoint(scanDir);

    if (checkpoint.mode === "cidr") {
      cp.detectStale(scanDir, checkpoint);
      checkpoint = cp.readCheckpoint(scanDir);
      delete checkpoint.pause_after;
      cp.writeCheckpoint(scanDir, checkpoint);
      const allDone = cp.CIDR_PHASE_ORDER.every(p => ["done","skipped"].includes(checkpoint.phases[p].status));
      if (allDone && !args.force) {
        return { content: [{ type: "text", text: `CIDR scan already complete for '${projectName}'.\n\n${cp.summarize(checkpoint)}` }] };
      }
      if (args.force) {
        for (const phase of cp.CIDR_PHASE_ORDER) {
          checkpoint.phases[phase] = { status: "pending", started_at: null, completed_at: null, container_id: null, exit_code: null, outputs: [] };
        }
        cp.writeCheckpoint(scanDir, checkpoint);
      }
      const key = `cidr:${projectName}`;
      if (!activePipelines.has(key)) {
        const promise = orch.runCidrPipeline(scanDir, checkpoint.options.cidr)
          .catch((e) => console.error(`[orchestrator] CIDR resume error for ${projectName}:`, e))
          .finally(() => activePipelines.delete(key));
        activePipelines.set(key, promise);
      }
      return { content: [{ type: "text", text: `Resuming CIDR scan for '${projectName}'.\n\n${cp.summarize(checkpoint)}` }] };
    }

    if (args.force) {
      for (const phase of cp.PHASE_ORDER) {
        checkpoint.phases[phase] = {
          status: phase === "xss" && checkpoint.options.skip_xss ? "skipped" : "pending",
          started_at: null, completed_at: null, container_id: null, exit_code: null, outputs: [],
        };
      }
      cp.writeCheckpoint(scanDir, checkpoint);
    }

    cp.detectStale(scanDir, checkpoint);
    checkpoint = cp.readCheckpoint(scanDir);
    delete checkpoint.pause_after;
    cp.writeCheckpoint(scanDir, checkpoint);

    if (cp.allPhasesDone(checkpoint) && !args.force) {
      return { content: [{ type: "text", text: `All phases already done for '${projectName}'.\n\n${cp.summarize(checkpoint)}` }] };
    }

    return startPipeline(projectName, scanDir);
  }

  // ── kuromaku_stop ─────────────────────────────────────────────────────
  if (name === "kuromaku_stop") {
    const scanDir = scanDirFor(args.project_name);
    if (!cp.checkpointExists(scanDir)) {
      return { content: [{ type: "text", text: `No checkpoint found for '${args.project_name}'.` }] };
    }
    const result = orch.stopPhase(scanDir);
    if (result.stopped) {
      return { content: [{ type: "text", text: `Stopped phase '${result.phase}' for '${args.project_name}'. It is now eligible for resume.` }] };
    }
    return { content: [{ type: "text", text: result.message }] };
  }

  // ── kuromaku_status ──────────────────────────────────────────────────
  if (name === "kuromaku_status") {
    const scanDir = scanDirFor(args.project_name);
    if (!cp.checkpointExists(scanDir)) {
      return { content: [{ type: "text", text: `No checkpoint found for '${args.project_name}'. Scan not started.` }] };
    }
    let checkpoint = cp.readCheckpoint(scanDir);
    checkpoint = cp.detectStale(scanDir, checkpoint);
    const isRunning = activePipelines.has(args.project_name);
    return {
      content: [{
        type: "text",
        text: cp.summarize(checkpoint) + (isRunning ? "\n\n(orchestrator pipeline actively running in this session)" : "") + liveDetail(scanDir),
      }],
    };
  }

  // ── kuromaku_results ──────────────────────────────────────────────────
  if (name === "kuromaku_results") {
    const scanDir = scanDirFor(args.project_name);
    if (!cp.checkpointExists(scanDir)) {
      return { content: [{ type: "text", text: `No checkpoint found for '${args.project_name}'.` }] };
    }
    const checkpoint = cp.readCheckpoint(scanDir);
    const prefix = findPrefix(scanDir, checkpoint);
    const maxLines = args.max_lines || 100;

    const fileMap = outputFileMap(prefix);

    if (args.file) {
      const fname = fileMap[args.file];
      if (!fname) {
        return { content: [{ type: "text", text: `Unknown file key '${args.file}'. Valid: ${Object.keys(fileMap).join(", ")}` }] };
      }
      const full = path.join(scanDir, fname);
      if (!fs.existsSync(full)) {
        return { content: [{ type: "text", text: `File not found: ${fname}` }] };
      }
      if (args.file === "report") {
        const stat = fs.statSync(full);
        return { content: [{ type: "text", text: `Report exists: ${full} (${stat.size} bytes). Binary docx — use kuromaku_read_file-equivalent file transfer or open directly on host.` }] };
      }
      const lines = fs.readFileSync(full, "utf-8").split("\n").slice(0, maxLines);
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }

    // Summary across all files
    const out = [`Results: ${args.project_name}`, "─".repeat(40)];
    for (const [key, fname] of Object.entries(fileMap)) {
      const full = path.join(scanDir, fname);
      if (fs.existsSync(full)) {
        if (key === "report") {
          out.push(`  ${key.padEnd(14)} (docx, ${fs.statSync(full).size} bytes)`);
        } else {
          const count = fs.readFileSync(full, "utf-8").split("\n").filter(l => l.trim()).length;
          out.push(`  ${key.padEnd(14)} ${String(count).padStart(6)} lines`);
        }
      } else {
        out.push(`  ${key.padEnd(14)} (not yet produced)`);
      }
    }
    return { content: [{ type: "text", text: out.join("\n") }] };
  }

  // ── kuromaku_report ───────────────────────────────────────────────────
  if (name === "kuromaku_report") {
    const scanDir = scanDirFor(args.project_name);
    if (!cp.checkpointExists(scanDir)) {
      return { content: [{ type: "text", text: `No checkpoint found for '${args.project_name}'.` }] };
    }
    const checkpoint = cp.readCheckpoint(scanDir);
    const prefix = findPrefix(scanDir, checkpoint);
    const { included, skipped } = assembleReport(scanDir, prefix);

    const lines = [
      `# Kuromaku Results Report — ${args.project_name}`,
      ``,
      `- Mode: ${checkpoint.mode || "domain"}`,
      `- Target: ${checkpoint.domain}`,
      `- Generated: ${new Date().toISOString()}`,
      ``,
    ];

    if (included.length === 0) {
      lines.push(`_No output files contain data yet._`);
    } else {
      for (const sec of included) {
        const label = FILE_LABELS[sec.key] || sec.key;
        lines.push(`## ${label}${sec.count ? ` — ${sec.count} lines` : ``}`, ``);
        if (sec.note) {
          lines.push(sec.note, ``);
        } else {
          lines.push("```", sec.content, "```", ``);
        }
      }
      lines.push(`---`, `_Omitted (empty or not produced): ${skipped.join(", ") || "none"}_`);
    }

    const reportText = lines.join("\n");

    if (args.export) {
      const outName = `${prefix}-results-report.md`;
      fs.writeFileSync(path.join(scanDir, outName), reportText + "\n");
      return { content: [{ type: "text", text:
        `Full report written to the scan volume: ${outName}\n` +
        `Path: ${path.join(scanDir, outName)}\n\n` +
        `Sections with data: ${included.map((s) => s.key).join(", ") || "none"}\n` +
        `Omitted (empty / not produced): ${skipped.join(", ") || "none"}`,
      }] };
    }

    return { content: [{ type: "text", text: reportText }] };
  }

  return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
}

// ─── Pipeline launcher ──────────────────────────────────────────────────────
// Runs the pipeline asynchronously; the MCP call returns immediately with
// current status. The promise is tracked so status calls can report
// "actively running in this session" and so a duplicate run/resume call
// doesn't spawn a second pipeline for the same project.
function startPipeline(projectName, scanDir) {
  const checkpoint = cp.readCheckpoint(scanDir);

  let scopeFile;
  const scope = checkpoint.options.scope;
  if (Array.isArray(scope) && scope.length > 0) {
    scopeFile = path.join(scanDir, "scope.txt");
    fs.writeFileSync(scopeFile, scope.join("\n") + "\n");
  }

  const opts = {
    domain: checkpoint.domain,
    domain_list: checkpoint.options.domain_list,
    threads: checkpoint.options.threads,
    skip_nuclei: checkpoint.options.skip_nuclei,
    llm_url: checkpoint.options.llm_url,
    llm_model: checkpoint.options.llm_model,
    scope_file: scopeFile,
  };

  if (!activePipelines.has(projectName)) {
    const promise = orch.runPipeline(scanDir, opts)
      .catch((e) => console.error(`[orchestrator] pipeline error for ${projectName}:`, e))
      .finally(() => activePipelines.delete(projectName));
    activePipelines.set(projectName, promise);
  }

  const nextPhase = cp.nextPendingPhase(checkpoint);

  // No scope -> recon's gau/katana crawl will pull in third-party/library
  // domains unrelated to the target (e.g. CDN/analytics/API hosts linked
  // from the target's own pages), and nothing will filter them out before
  // network/webscan/xss scan them too. This line is addressed to the
  // CALLING LLM, not the end user directly — it's instructing the model
  // reading this tool result to relay the question, since an MCP tool
  // can't prompt the user itself.
  const scopeWarning = (Array.isArray(scope) && scope.length > 0) ? "" :
    `\n⚠ No 'scope' was provided for this scan. Recon's domain discovery ` +
    `(gau/katana crawling the target's pages) commonly pulls in third-party ` +
    `domains that have nothing to do with the target — those get scanned by ` +
    `network/webscan/xss too unless scope restricts results to the target. ` +
    `Ask the user now whether they want to set a scope (in-scope domain ` +
    `glob patterns) for this scan. If they do, stop this run with ` +
    `kuromaku_stop and re-call kuromaku_run with 'scope' set before it ` +
    `progresses past recon.\n`;

  return {
    content: [{
      type: "text",
      text: [
        `Kuromaku pipeline started for '${projectName}'.`,
        `Domain: ${checkpoint.domain}`,
        `Next phase: ${nextPhase || "(all done)"}`,
        ``,
        cp.summarize(checkpoint),
        scopeWarning,
        `Monitor with: kuromaku_status { "project_name": "${projectName}" }`,
        ``,
        `⚠ Only scan targets you have explicit written authorization to test.`,
      ].join("\n"),
    }],
  };
}

// ─── Server factory ─────────────────────────────────────────────────────────
function createServer() {
  const srv = new Server(
    { name: "kuromaku", version: "2.0.0" },
    { capabilities: { tools: {} } }
  );
  srv.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOL_LIST }));
  srv.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      return await handleToolCall(request.params.name, request.params.arguments || {});
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }] };
    }
  });
  return srv;
}

// ─── Transport selection (same pattern as v1) ───────────────────────────────
const HTTP_PORT = process.env.MCP_HTTP_PORT || 3002;
const USE_HTTP = process.env.MCP_HTTP === "true";

if (USE_HTTP) {
  const app = express();
  app.use(cors());
  app.use(express.json());

  const transports = {};

  app.all("/mcp", async (req, res) => {
    try {
      const sessionId = req.headers["mcp-session-id"];
      let transport = sessionId ? transports[sessionId] : null;

      if (!transport) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: (id) => { transports[id] = transport; },
        });
        transport.onclose = () => {
          if (transport.sessionId) delete transports[transport.sessionId];
        };
        await createServer().connect(transport);
      }

      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("MCP handler error:", err);
      if (!res.headersSent) res.status(500).json({ error: err.message });
    }
  });

  app.get("/", (_, res) => res.json({
    name: "kuromaku orchestrator",
    version: "2.0.0",
    transport: "streamable-http",
    mcp_endpoint: `http://localhost:${HTTP_PORT}/mcp`,
  }));

  app.get("/health", (_, res) => res.json({ status: "running", version: "2.0.0" }));

  app.listen(HTTP_PORT, () => {
    console.error(`Kuromaku orchestrator — Streamable HTTP on port ${HTTP_PORT}`);
  });
} else {
  const srv = createServer();
  const transport = new StdioServerTransport();
  await srv.connect(transport);
  console.error("Kuromaku orchestrator — stdio mode");
}
