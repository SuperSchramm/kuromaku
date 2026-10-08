# Kuromaku — Phased Architecture Overview

## Directory Layout (Target State)

```
~/bugbounty-workspace/
├── orchestrator/
│   ├── Dockerfile                 # Alpine + Node 20 + docker-cli (~50MB)
│   ├── package.json
│   └── src/
│       ├── index.js               # MCP server (stdio + HTTP/SSE, same as v1)
│       ├── checkpoint.js           # Read/write/validate .checkpoint
│       ├── orchestrator.js         # Phase dispatch, container spawn/wait
│       └── tools.js                # MCP tool definitions + handlers
│
├── workers/
│   ├── recon/
│   │   ├── Dockerfile             # subfinder, amass, httpx, gau, katana, anew
│   │   └── phase-recon.sh
│   ├── network/
│   │   ├── Dockerfile             # dnsx, naabu
│   │   └── phase-network.sh
│   ├── webscan/
│   │   ├── Dockerfile             # nuclei (+templates), nmap+vulners, dirsearch
│   │   └── phase-webscan.sh
│   └── xss/
│       ├── Dockerfile             # dalfox, kxss, qsreplace
│       └── phase-xss.sh
│
├── projects/
│   └── <project_name>/
│       ├── README.md
│       └── scans/
│           ├── .checkpoint         # NEW — orchestrator-owned state file
│           ├── <domain>-uniqdomains.log
│           ├── <domain>-naabu.log
│           └── ... (same output filenames as v1)
│
└── shared/                          # unchanged — shared wordlists etc.
```

## Container Lifecycle Per Scan

```
1. kuromaku_run { domain, project_name }
   └─ orchestrator creates .checkpoint (all phases "pending")
   └─ orchestrator calls runPhase("recon")

2. runPhase("recon")
   ├─ checkpoint: phases.recon.status = "running", started_at = now
   ├─ docker run --rm \
   │     -v projects/<name>/scans:/workspace/scans \
   │     --cap-add NET_RAW \
   │     kuromaku-recon \
   │     bash /phase-recon.sh -d <domain> -t /workspace/scans --threads N
   ├─ wait for exit
   ├─ validate expected outputs exist (CHECKPOINT_SCHEMA.md table)
   ├─ checkpoint: phases.recon.status = "done" | "failed"
   └─ if "done" → runPhase("network"); if "failed" → stop, report to user

3. runPhase("network") ... same pattern, image = kuromaku-network
4. runPhase("webscan") ... same pattern, image = kuromaku-webscan
5. runPhase("xss")     ... same pattern, image = kuromaku-xss
```

Each `docker run --rm` exits and removes itself immediately — at any moment
during a scan, at most ONE worker container is running (matches original
a single monolithic design), but it's a small single-purpose image instead
of the 5GB monolith.

## Volume Strategy

Each worker only needs:
- `projects/<name>/scans` → `/workspace/scans` (read+write — same mount for
  every phase, this is how phases hand off data to each other)

Per-worker tool caches (replacing the old shared `kali-home`/
`nuclei-templates` volumes):

| Worker | Volume | Contents |
|---|---|---|
| webscan | `nuclei-templates` | ~6187 templates, avoids re-downloading every run |
| recon | `amass-config` | amass config/cache (optional, small) |
| network | *(none)* | naabu/dnsx are stateless |
| xss | *(none)* | dalfox is stateless |

## Capability Requirements Per Worker

| Worker | `cap_add` | Why |
|---|---|---|
| recon | none | subfinder/amass/httpx/gau/katana are all standard HTTP/DNS |
| network | `NET_RAW`, `NET_ADMIN` | naabu raw socket scanning |
| webscan | `NET_RAW` | nmap SYN scans (vulners script) |
| xss | none | dalfox/kxss are HTTP-only |

This is a meaningful security improvement over v1 — only 2 of 4 images ever
get raw socket capabilities, versus the monolith having `NET_RAW`+`NET_ADMIN`
permanently.

## Image Size Estimates

| Image | Base | Est. Size | Contains |
|---|---|---|---|
| `kuromaku-recon` | `golang:1.22-alpine` (build) → `alpine:3.19` (runtime) | ~250MB | subfinder, amass, httpx, gau, katana, anew binaries only |
| `kuromaku-network` | `alpine:3.19` | ~80MB | dnsx, naabu binaries |
| `kuromaku-webscan` | `alpine:3.19` | ~400MB* | nuclei + nmap (apk) + dirsearch (python3-venv) |
| `kuromaku-xss` | `alpine:3.19` | ~120MB | dalfox, kxss, qsreplace |
| `orchestrator` | `node:20-alpine` | ~180MB | Node + docker-cli + MCP SDK |

\* webscan is the largest because nuclei templates (~150MB) get baked in or
volume-mounted, plus nmap's vulners/vulscan script dependencies.

**Total disk**: ~1GB across all images vs. ~5GB monolith.
**Peak RAM during scan**: whichever single worker is active (webscan is
highest at ~1.5-2GB) + orchestrator (~50MB) — vs. monolith's entire toolchain
loaded simultaneously regardless of which tool is executing.

## Multi-Arch Note (M4 Mac)

All worker Dockerfiles will target `linux/arm64` natively — Alpine has arm64
builds for every tool we need (Go binaries compile natively, nmap/dirsearch
are apk/pip packages with arm64 support). This avoids Rosetta emulation
overhead that the `kalilinux/kali-rolling` image may have incurred depending
on which layers had arm64 variants.

## What Phase 0 Does NOT Decide Yet

- Exact orchestrator MCP tool-call → container-spawn implementation (Phase 5)
- Whether `docker run` is shelled out via `child_process` or via the Docker
  Engine API/socket directly (Phase 5 — leaning toward Engine API for cleaner
  exit-code/OOM detection)
- Retry limits / backoff for `kuromaku_resume` (Phase 5, configurable)

---

## Next Step

**Phase 1**: `workers/recon/Dockerfile` + `phase-recon.sh` — smallest, most
self-contained worker, and validates the alpine multi-stage build pattern
that phases 2-4 will reuse.
