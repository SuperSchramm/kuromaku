#!/usr/bin/env python3
"""
phase-report.py — Kuromaku Phase 5: Report Generation

Reads all scan output files from /workspace/scans and produces a
DOCX report modeled on the SI Passive Recon Report format:
  - Cover page table
  - Risk finding summary (severity counts)
  - Executive summary (LLM-generated narrative, or template fallback)
  - Infrastructure overview (from naabu/resolved)
  - Findings ranked by severity (parsed from nuclei output)
  - Consolidated finding register table
  - Appendix: subdomain inventory, open ports

Usage:
  phase-report.py -d <domain> -t <scan_dir> [--llm-url http://host:1234/v1]

If --llm-url is unreachable, falls back to a templated executive summary
with no LLM dependency — the report still generates fully.

Required inputs (whatever exists is used; missing files are skipped gracefully):
  <prefix>-uniqdomains.log
  <prefix>-naabu.log
  <prefix>-resolved.log
  <prefix>-nucleiAlerts.log
  <prefix>-dirsearch.log
  <prefix>-dalfox.log
  <prefix>-nmapvulners.log

Output:
  <prefix>-report.docx
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

try:
    from docx import Document
    from docx.shared import Pt, RGBColor, Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH
except ImportError:
    print("ERROR: python-docx not installed. pip install python-docx", file=sys.stderr)
    sys.exit(1)


# ─── Severity color mapping (matches SI report style) ──────────────────────
SEVERITY_COLORS = {
    "critical": RGBColor(0xC0, 0x00, 0x00),
    "high":     RGBColor(0xE3, 0x6C, 0x09),
    "medium":   RGBColor(0xBF, 0x8F, 0x00),
    "low":      RGBColor(0x38, 0x76, 0xC0),
    "info":     RGBColor(0x70, 0x70, 0x70),
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-d", "--domain")
    p.add_argument("-dl", "--domain_list")
    p.add_argument("-t", "--target-dir", required=True)
    p.add_argument("--llm-url", default=os.environ.get("LLM_URL", "http://host.docker.internal:1234/v1"))
    p.add_argument("--llm-model", default=os.environ.get("LLM_MODEL", "qwen"))
    return p.parse_args()


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, errors="ignore") as f:
        return [l.rstrip("\n") for l in f if l.strip()]


# ─── Nuclei output parsing ──────────────────────────────────────────────────
# nuclei -silent output format: [template-id] [protocol] [severity] target [extra]
NUCLEI_LINE_RE = re.compile(
    r"^\[(?P<template>[^\]]+)\]\s+\[(?P<protocol>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<target>\S+)(?:\s+(?P<extra>.*))?$"
)

def parse_nuclei(lines):
    """Returns dict: severity -> list of finding dicts."""
    findings = defaultdict(list)
    for line in lines:
        m = NUCLEI_LINE_RE.match(line.strip())
        if not m:
            continue
        sev = m.group("severity").lower()
        if sev not in SEVERITY_COLORS:
            sev = "info"
        findings[sev].append({
            "template": m.group("template"),
            "protocol": m.group("protocol"),
            "target": m.group("target"),
            "extra": m.group("extra") or "",
            "raw": line.strip(),
        })
    return findings


# ─── naabu output parsing ───────────────────────────────────────────────────
def parse_naabu(lines):
    """host:port lines -> list of (host, port)."""
    results = []
    for line in lines:
        if ":" in line:
            host, _, port = line.rpartition(":")
            results.append((host.strip(), port.strip()))
    return results


# ─── dirsearch output parsing ───────────────────────────────────────────────
# Typical plain format: <status> <size> <url>
DIRSEARCH_LINE_RE = re.compile(r"^\s*(\d{3})\s+\S+\s+(\S+)")

def parse_dirsearch(lines, interesting_codes=("200", "301", "302", "401", "403")):
    results = []
    for line in lines:
        m = DIRSEARCH_LINE_RE.match(line)
        if m and m.group(1) in interesting_codes:
            results.append((m.group(1), m.group(2)))
    return results


# ─── LLM call (optional) ────────────────────────────────────────────────────
def generate_executive_summary(llm_url, llm_model, target, sev_counts, top_findings):
    """Call LM Studio's OpenAI-compatible API for a short exec summary.
    Falls back to a templated paragraph on any failure."""
    fallback = (
        f"This report presents the findings of an automated reconnaissance and "
        f"vulnerability assessment conducted against {target}. The assessment "
        f"identified {sum(sev_counts.values())} findings across "
        f"{len([k for k in SEVERITY_ORDER if sev_counts.get(k)])} severity levels, "
        f"including {sev_counts.get('critical', 0)} critical and "
        f"{sev_counts.get('high', 0)} high severity issues. "
        f"Findings should be triaged in order of severity, with critical and high "
        f"items addressed first given their potential for unauthenticated exploitation."
    )

    try:
        import urllib.request

        prompt = (
            f"Write a concise 3-4 sentence executive summary paragraph for a "
            f"security assessment report on the target '{target}'. "
            f"The scan found: {sev_counts.get('critical',0)} critical, "
            f"{sev_counts.get('high',0)} high, {sev_counts.get('medium',0)} medium, "
            f"{sev_counts.get('low',0)} low, and {sev_counts.get('info',0)} "
            f"informational findings. "
            f"Top issues include: {', '.join(top_findings[:3]) if top_findings else 'none notable'}. "
            f"Write in formal security-report tone. Do not invent specific CVE numbers "
            f"or details beyond what is given. Output only the paragraph, no headers."
        )

        body = json.dumps({
            "model": llm_model,
            "max_tokens": 300,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
        }).encode()

        req = urllib.request.Request(
            f"{llm_url}/chat/completions",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            text = data["choices"][0]["message"]["content"].strip()
            if text:
                return text
    except Exception as e:
        print(f"[report] LLM summary generation failed ({e}) — using template", file=sys.stderr)

    return fallback


# ─── Document building ──────────────────────────────────────────────────────
def add_heading(doc, text, level=1):
    doc.add_heading(text, level=level)


def add_severity_table(doc, sev_counts):
    table = doc.add_table(rows=1, cols=2)
    table.style = "Light Grid Accent 1"
    hdr = table.rows[0].cells
    hdr[0].text = "Severity"
    hdr[1].text = "Count"
    for sev in SEVERITY_ORDER:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        row = table.add_row().cells
        run = row[0].paragraphs[0].add_run(sev.upper())
        run.bold = True
        run.font.color.rgb = SEVERITY_COLORS[sev]
        row[1].text = str(count)


def add_cover_table(doc, target, scan_date):
    table = doc.add_table(rows=0, cols=2)
    table.style = "Light Grid Accent 1"
    rows_data = [
        ("Target", target),
        ("Assessment Type", "Automated Recon + Vulnerability Scan (Kuromaku)"),
        ("Scope", "Subdomain enumeration, port scan, nuclei templates, dirsearch, XSS probing"),
        ("Date", scan_date),
        ("Tooling", "subfinder, amass, httpx, gau, katana, dnsx, naabu, nuclei, nmap, dirsearch, dalfox"),
        ("Classification", "Internal Use Only"),
    ]
    for label, value in rows_data:
        row = table.add_row().cells
        row[0].text = label
        row[1].text = value
        row[0].paragraphs[0].runs[0].bold = True


def add_finding_section(doc, sev, findings, level=2):
    if not findings:
        return
    add_heading(doc, f"{sev.upper()} Findings ({len(findings)})", level=level)
    for f in findings:
        p = doc.add_paragraph()
        run = p.add_run(f"[{sev.upper()}] {f['template']}")
        run.bold = True
        run.font.color.rgb = SEVERITY_COLORS[sev]

        detail = doc.add_paragraph()
        detail.add_run("Target: ").bold = True
        detail.add_run(f['target'])
        if f.get('extra'):
            detail.add_run("\nDetails: ").bold = True
            detail.add_run(f['extra'])
        detail.add_run("\nRecommendation: ").bold = True
        detail.add_run(
            "Review this finding against the template documentation at "
            f"https://github.com/projectdiscovery/nuclei-templates and remediate "
            "per vendor guidance for the affected technology."
        )


def add_finding_register(doc, all_findings_flat):
    add_heading(doc, "Consolidated Finding Register", level=1)
    table = doc.add_table(rows=1, cols=4)
    table.style = "Light Grid Accent 1"
    hdr = table.rows[0].cells
    for i, h in enumerate(["#", "Finding", "Severity", "Target"]):
        hdr[i].text = h
        hdr[i].paragraphs[0].runs[0].bold = True

    for i, f in enumerate(all_findings_flat, 1):
        row = table.add_row().cells
        row[0].text = str(i)
        row[1].text = f["template"]
        sev_run = row[2].paragraphs[0].add_run(f["severity"].upper())
        sev_run.font.color.rgb = SEVERITY_COLORS.get(f["severity"], RGBColor(0,0,0))
        sev_run.bold = True
        row[3].text = f["target"]


def add_infra_overview(doc, naabu_results, resolved_lines):
    add_heading(doc, "Infrastructure Overview", level=1)

    if resolved_lines:
        add_heading(doc, "DNS Resolution", level=2)
        p = doc.add_paragraph(f"{len(resolved_lines)} DNS records resolved during enumeration.")

    if naabu_results:
        add_heading(doc, "Open Ports / Services", level=2)
        table = doc.add_table(rows=1, cols=2)
        table.style = "Light Grid Accent 1"
        hdr = table.rows[0].cells
        hdr[0].text = "Host"
        hdr[1].text = "Port"
        for host, port in naabu_results[:100]:  # cap to avoid runaway docs
            row = table.add_row().cells
            row[0].text = host
            row[1].text = port
        if len(naabu_results) > 100:
            doc.add_paragraph(f"... and {len(naabu_results) - 100} more (see naabu.log)")


def add_appendix(doc, uniqdomains, dirsearch_results, dalfox_lines):
    add_heading(doc, "Appendix", level=1)

    if uniqdomains:
        add_heading(doc, "Subdomain Inventory", level=2)
        for d in uniqdomains[:200]:
            doc.add_paragraph(d, style="List Bullet")
        if len(uniqdomains) > 200:
            doc.add_paragraph(f"... and {len(uniqdomains) - 200} more (see uniqdomains.log)")

    if dirsearch_results:
        add_heading(doc, "Directory Enumeration — Interesting Paths", level=2)
        table = doc.add_table(rows=1, cols=2)
        table.style = "Light Grid Accent 1"
        hdr = table.rows[0].cells
        hdr[0].text = "Status"
        hdr[1].text = "Path"
        for status, path in dirsearch_results[:100]:
            row = table.add_row().cells
            row[0].text = status
            row[1].text = path

    if dalfox_lines:
        add_heading(doc, "XSS Candidate Findings (dalfox)", level=2)
        for line in dalfox_lines[:50]:
            doc.add_paragraph(line, style="List Bullet")


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    tdir = args.target_dir

    if args.domain_list:
        prefix_name = os.path.basename(args.domain_list)
    else:
        prefix_name = args.domain

    if not prefix_name:
        print("Error: -d or -dl required", file=sys.stderr)
        sys.exit(1)

    target_prefix = os.path.join(tdir, prefix_name)

    def f(suffix):
        return f"{target_prefix}-{suffix}"

    print(f" █▄▄▪ [report] Reading scan outputs for {prefix_name}")

    uniqdomains = read_lines(f("uniqdomains.log"))
    naabu_results = parse_naabu(read_lines(f("naabu.log")))
    resolved_lines = read_lines(f("resolved.log"))
    nuclei_findings = parse_nuclei(read_lines(f("nucleiAlerts.log")))
    dirsearch_results = parse_dirsearch(read_lines(f("dirsearch.log")))
    dalfox_lines = read_lines(f("dalfox.log"))

    sev_counts = {sev: len(nuclei_findings.get(sev, [])) for sev in SEVERITY_ORDER}
    total_findings = sum(sev_counts.values())

    # Flatten for register, ordered by severity
    all_findings_flat = []
    for sev in SEVERITY_ORDER:
        for fnd in nuclei_findings.get(sev, []):
            all_findings_flat.append({**fnd, "severity": sev})

    top_findings = [fnd["template"] for sev in ("critical", "high") for fnd in nuclei_findings.get(sev, [])]

    print(f" █▄▄▪ [report] {total_findings} nuclei findings, {len(naabu_results)} open ports, "
          f"{len(uniqdomains)} subdomains, {len(dirsearch_results)} dirsearch hits, "
          f"{len(dalfox_lines)} XSS candidates")

    print(f" █▄▄▪ [report] Generating executive summary (LLM: {args.llm_url})")
    exec_summary = generate_executive_summary(
        args.llm_url, args.llm_model, prefix_name, sev_counts, top_findings
    )

    # ─── Build document ──────────────────────────────────────────────────────
    doc = Document()

    title = doc.add_heading("AUTOMATED RECONNAISSANCE & VULNERABILITY REPORT", level=0)
    doc.add_paragraph(prefix_name).alignment = WD_ALIGN_PARAGRAPH.CENTER

    add_heading(doc, "Assessment Details", level=1)
    add_cover_table(doc, prefix_name, datetime.now().strftime("%B %d, %Y"))

    add_heading(doc, "Risk Finding Summary", level=1)
    add_severity_table(doc, sev_counts)

    add_heading(doc, "1. Executive Summary", level=1)
    doc.add_paragraph(exec_summary)

    add_infra_overview(doc, naabu_results, resolved_lines)

    add_heading(doc, "Findings — Ranked by Risk", level=1)
    doc.add_paragraph(
        "Findings below are derived from automated nuclei template matches, "
        "ranked by severity as classified by the matched template."
    )
    if total_findings == 0:
        doc.add_paragraph("No nuclei findings were recorded for this target.")
    for sev in SEVERITY_ORDER:
        add_finding_section(doc, sev, nuclei_findings.get(sev, []))

    if all_findings_flat:
        add_finding_register(doc, all_findings_flat)

    add_appendix(doc, uniqdomains, dirsearch_results, dalfox_lines)

    add_heading(doc, "Disclaimer", level=1)
    doc.add_paragraph(
        "This report was generated automatically by the Kuromaku scanning "
        "pipeline. Findings are based on automated tooling and template "
        "matching; manual verification is recommended before remediation "
        "or disclosure. This document may contain sensitive information "
        "about the target's attack surface and should be handled accordingly."
    )

    out_path = f("report.docx")
    doc.save(out_path)
    print(f" █▄▄▪ [report] Report written: {out_path}")


if __name__ == "__main__":
    main()
