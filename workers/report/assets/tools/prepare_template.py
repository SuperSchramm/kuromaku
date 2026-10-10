#!/usr/bin/env python3
"""
MAINTENANCE TOOL — not part of the runtime report-generation pipeline (that's
phase-report.py, which just reads the already-templatized
assets/report-template.docx via docxtpl). Run this by hand only if you need
to re-derive that template from a fresh/updated source CCSO docx — e.g. the
source template gets a new revision, or you want to adjust which fields are
tagged. Converts the CCSO report template's <PLACEHOLDER> text into docxtpl
Jinja2 tags ({{ var }}, {%tr for %}/{%tr endfor %} for table-row loops,
{%p for %}/{%p endfor %} for repeating paragraph/table blocks) by editing
word/document.xml directly via stdlib xml.etree.ElementTree — written this
way (rather than with python-docx) because the environment this was
originally run in had no pip/python-docx/pandoc/LibreOffice available, only
the Python stdlib.

After editing SRC/DST below, run it, then re-verify by hand before
committing the result over assets/report-template.docx — there is no
automated test for this (nothing here can render/visually check a docx);
see the kuromaku session history for the exact body-index map this was
originally built against and the two indexing bugs that surfaced along the
way (hyperlink-wrapped runs not matching a plain w:r search; a stale
pre-mutation element-index snapshot used for insert() positions after
earlier inserts had already shifted the live tree).
"""
import copy
import zipfile
import shutil
import xml.etree.ElementTree as ET

SRC = "/path/to/fresh-ccso-report-template.docx"  # set before running
DST = "/path/to/output/report-template.docx"      # set before running

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
ET.register_namespace("w", W)
# Register all namespaces actually used in this file's root so round-trip
# serialization doesn't lose/rename them (ElementTree only preserves
# namespaces it knows about via register_namespace, otherwise it invents
# ns0/ns1/... prefixes, which is still valid XML but needlessly different
# from the original and makes diffing harder).
NSMAP = {
    'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'wp': 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing',
    'a': 'http://schemas.openxmlformats.org/drawingml/2006/main',
    'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'pic': 'http://schemas.openxmlformats.org/drawingml/2006/picture',
    'wps': 'http://schemas.microsoft.com/office/word/2010/wordprocessingShape',
    'wpg': 'http://schemas.microsoft.com/office/word/2010/wordprocessingGroup',
    'mc': 'http://schemas.openxmlformats.org/markup-compatibility/2006',
    'w14': 'http://schemas.microsoft.com/office/word/2010/wordml',
    'w15': 'http://schemas.microsoft.com/office/word/2012/wordml',
    've': 'http://schemas.openxmlformats.org/markup-compatibility/2006',
    'o': 'urn:schemas-microsoft-com:office:office',
    'v': 'urn:schemas-microsoft-com:vml',
    'sl': 'http://schemas.openxmlformats.org/schemaLibrary/2006/main',
    'aink': 'http://schemas.microsoft.com/office/drawing/2016/ink',
    'am3d': 'http://schemas.microsoft.com/office/drawing/2017/model3d',
    'cx': 'http://schemas.microsoft.com/office/drawing/2014/chartex',
    'cx1': 'http://schemas.microsoft.com/office/drawing/2015/9/8/chartex',
}
for pfx, uri in NSMAP.items():
    ET.register_namespace(pfx, uri)

def wtag(t):
    return f"{{{W}}}{t}"

z = zipfile.ZipFile(SRC)
xml_bytes = z.read('word/document.xml')
root = ET.fromstring(xml_bytes)
body = root.find(wtag('body'))

def get_runs(p):
    return p.findall(wtag('r'))

def get_text(elem):
    return ''.join(t.text or '' for t in elem.findall('.//' + wtag('t')))

def set_single_run_text(p, text):
    """Collapse a paragraph to ONE run with the given text. Removes every
    direct child except w:pPr (including w:hyperlink wrappers, which a
    plain p.findall(wtag('r')) misses since the real w:r lives one level
    deeper inside the hyperlink — the original bug here: a hyperlinked
    reference line's run was never found, so the "no runs" fallback
    APPENDED a new run instead of replacing, leaving old-url+new-tag
    concatenated). Reuses an existing run's rPr for formatting if any
    run (direct or hyperlink-wrapped) is found; otherwise bare new run."""
    pPr = p.find(wtag('pPr'))
    # Find rPr to preserve from ANY existing run, direct or hyperlink-wrapped.
    existing_rpr = None
    for r in p.findall('.//' + wtag('r')):
        rpr = r.find(wtag('rPr'))
        if rpr is not None:
            existing_rpr = rpr
            break
    for child in list(p):
        if child is not pPr:
            p.remove(child)
    r = ET.SubElement(p, wtag('r'))
    if existing_rpr is not None:
        r.append(copy.deepcopy(existing_rpr))
    t = ET.SubElement(r, wtag('t'))
    t.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
    t.text = text

def set_cell_text(tc, text):
    """Set a table cell (w:tc) to a single paragraph with one run."""
    ps = tc.findall(wtag('p'))
    if not ps:
        p = ET.SubElement(tc, wtag('p'))
        set_single_run_text(p, text)
        return
    set_single_run_text(ps[0], text)
    for extra in ps[1:]:
        tc.remove(extra)

def get_rows(tbl):
    return tbl.findall(wtag('tr'))

def get_cells(tr):
    return tr.findall(wtag('tc'))

def inline_replace(p, replacements):
    """For a paragraph with inline prose (e.g. '...<CLIENT NAME>...'),
    apply the full merged text, substring-replace placeholders with Jinja
    tags, and write back as one run. Safe when the WHOLE paragraph is
    meant to become one Jinja-tagged block of prose."""
    text = get_text(p)
    for old, new in replacements.items():
        text = text.replace(old, new)
    set_single_run_text(p, text)

def make_tag_row(template_row, tag_text):
    """Deep-copy template_row (a w:tr), clear all its cells to empty
    except the first (which gets tag_text) — used for {%tr for %}/
    {%tr endfor %} marker rows, which docxtpl removes entirely at
    render time regardless of other cell content."""
    row = copy.deepcopy(template_row)
    cells = get_cells(row)
    for i, c in enumerate(cells):
        set_cell_text(c, tag_text if i == 0 else "")
    return row

def make_tag_paragraph(template_p, tag_text):
    p = copy.deepcopy(template_p)
    set_single_run_text(p, tag_text)
    return p

children = list(body)

def idx_of(elem):
    # Always look up position in the LIVE body, not the frozen `children`
    # snapshot — body-level inserts earlier in this script (e.g. the VRT
    # note) shift every subsequent element's true position, and a stale
    # snapshot index silently drifts out from under later insert() calls
    # (observed bug: {%p endfor %} landed one element too early, stranding
    # the References paragraph outside the finding loop).
    return list(body).index(elem)

# ── [0] Team name on title page ─────────────────────────────────────────
inline_replace(children[0], {"<TEAM LOGO/NAME>": "{{ team_name }}"})

# ── [1] Year ─────────────────────────────────────────────────────────────
inline_replace(children[1], {"<YEAR>": "{{ year }}"})

# ── [2] Drop the "replace client logo" instruction text ────────────────
set_single_run_text(children[2], "")

# ── [6] Report issued date ──────────────────────────────────────────────
inline_replace(children[6], {"<TEST DATE>": "{{ test_date }}"})

# ── [9] Confidentiality notice — inline CLIENT NAME / TEAM NAME ────────
inline_replace(children[9], {"<CLIENT NAME>": "{{ client_name }}", "<TEAM NAME>": "{{ team_name }}"})

# ── [11] Disclaimer — inline CLIENT NAME ────────────────────────────────
inline_replace(children[11], {"<CLIENT NAME>": "{{ client_name }}"})

# ── [20] Executive summary narrative -> single LLM/template-generated var
set_single_run_text(children[20], "{{ exec_summary }}")

# ── [22] Severity count table ───────────────────────────────────────────
tbl = children[22]
rows = get_rows(tbl)
data_row_cells = get_cells(rows[1])
set_cell_text(data_row_cells[0], "{{ sev_counts.critical }}")
set_cell_text(data_row_cells[1], "{{ sev_counts.high }}")
set_cell_text(data_row_cells[2], "{{ sev_counts.medium }}")
set_cell_text(data_row_cells[3], "{{ sev_counts.low }}")

# ── [24] "highest severity ... <BAD ACTIONS>" paragraph -> data-driven var
set_single_run_text(children[24], "{{ impact_statement }}")

# ── [28],[29] Drop the optional "<Optional - Big Issue> Recommendation" example
to_remove = [children[28], children[29]]  # body-level elements
to_remove_rows = []  # (parent_tbl, row) tuples — rows live inside a w:tbl, not body

# ── [35]-[52] Strengths/Recommendations: keep headings+intros (with
# TEAM/CLIENT NAME substituted), drop the lorem-ipsum EXAMPLE content —
# this is genuine analyst judgment kuromaku has no basis to fabricate.
inline_replace(children[35], {})  # "Observed Security Strengths" heading, no placeholders
inline_replace(children[36], {"<TEAM NAME>": "{{ team_name }}", "<CLIENT NAME>": "{{ client_name }}"})
to_remove += [children[37], children[38], children[39]]  # <Strength Category> example
inline_replace(children[41], {"<TEAM NAME>": "{{ team_name }}", "<CLIENT NAME>": "{{ client_name }}"})
inline_replace(children[43], {"<TEAM NAME>": "{{ team_name }}", "<CLIENT NAME>": "{{ client_name }}"})
to_remove += [children[44], children[45], children[46]]  # short-term example
inline_replace(children[49], {"<TEAM NAME>": "{{ team_name }}", "<NUM>": "{{ num_months }}"})
to_remove += [children[50], children[51], children[52]]  # long-term example

# ── [56]/[57] SCOPE > Networks table -> loop over scope_patterns
tbl = children[57]
rows = get_rows(tbl)
for_row = make_tag_row(rows[1], "{%tr for s in scope_patterns %}")
body_cells = get_cells(rows[1])
set_cell_text(body_cells[0], "{{ s }}")
set_cell_text(body_cells[1], "In-scope pattern")
endfor_row = make_tag_row(rows[1], "{%tr endfor %}")
# Remove the second example data row (Gotham/NY), insert for/endfor around
# the (now-templatized) first data row.
to_remove_rows.append((tbl, rows[2]))
tbl.insert(list(tbl).index(rows[1]), for_row)
tbl.insert(list(tbl).index(rows[1]) + 1, endfor_row)

# ── [67]/[68] TESTING METHODOLOGY narrative -> kuromaku-accurate description
set_single_run_text(children[68], "{{ methodology_text }}")

# ── Replace the static "Team Methodology" hexagon image with a docxtpl
# InlineImage tag. Found by searching for the w:drawing referencing rId8
# (-> media/image2.png) rather than a fixed body index, since by this
# point several earlier edits have already shifted indices — see idx_of's
# own docstring for why a stale index is the wrong tool here.
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
methodology_image_p = None
for p in body.findall(wtag('p')):
    for blip in p.findall('.//' + f'{{{A_NS}}}blip'):
        if blip.get(f'{{{R_NS}}}embed') == 'rId8':
            methodology_image_p = p
            break
    if methodology_image_p is not None:
        break
assert methodology_image_p is not None, "could not find the methodology hexagon image paragraph (rId8)"
set_single_run_text(methodology_image_p, "{{ methodology_image }}")

# ── [72]-[84] CLASSIFICATION DEFINITIONS: add a Bugcrowd VRT reference
# sentence before the Risk Classifications table, and drop the Remediation
# Difficulty Classifications heading+table entirely (field was dropped).
risk_classifications_heading = children[73]
vrt_note = make_tag_paragraph(
    children[55],  # reuse a plain "Normal"-style paragraph as a formatting donor
    "Risk ratings below follow the severity conventions of Bugcrowd's "
    "Vulnerability Rating Taxonomy (VRT, https://bugcrowd.com/vulnerability-rating-taxonomy), "
    "informed by each finding's CVSS score and vector where available.",
)
body.insert(idx_of(risk_classifications_heading) + 1, vrt_note)
to_remove += [children[83], children[84]]  # Remediation Difficulty Classifications

# ── [87]/[88] ASSESSMENT FINDINGS summary table -> loop over findings
tbl = children[87]
rows = get_rows(tbl)
for_row = make_tag_row(rows[1], "{%tr for f in findings %}")
body_cells = get_cells(rows[1])
set_cell_text(body_cells[0], "{{ loop.index }}")
set_cell_text(body_cells[1], "{{ f.title }}")
set_cell_text(body_cells[2], "{{ f.risk_score }}")
set_cell_text(body_cells[3], "{{ f.risk_label }}")
set_cell_text(body_cells[4], "")
endfor_row = make_tag_row(rows[1], "{%tr endfor %}")
to_remove_rows += [(tbl, rows[2]), (tbl, rows[3]), (tbl, rows[4]), (tbl, rows[5])]  # remove other 4 example rows
tbl.insert(list(tbl).index(rows[1]), for_row)
tbl.insert(list(tbl).index(rows[1]) + 1, endfor_row)
to_remove.append(children[88])  # "TEMPLATE NOTE" instruction paragraph

# ── [96]-[114] Per-finding detail block -> {%p for f in findings %} ... {%p endfor %}
finding_title_p = children[96]
finding_table = children[97]
sec_impl_heading = children[99]
sec_impl_body = children[100]
analysis_heading = children[102]
analysis_body = children[103]
figure_block = [children[104], children[105], children[106], children[107]]
recs_heading = children[108]
recs_body1 = children[109]
recs_body2 = children[110]
refs_heading = children[112]
refs_body1 = children[113]
refs_body2 = children[114]

set_single_run_text(finding_title_p, "{{ loop.index }}. {{ f.title }}")

t_rows = get_rows(finding_table)
set_cell_text(get_cells(t_rows[0])[0], "{{ f.risk_label|upper }} RISK ({{ f.risk_score }}/10)")
set_cell_text(get_cells(t_rows[1])[1], "{{ f.likelihood }}")
set_cell_text(get_cells(t_rows[2])[1], "{{ f.business_impact }}")
finding_table.remove(t_rows[3])  # drop Remediation Difficulty row

set_single_run_text(sec_impl_body, "{{ f.security_implications }}")
set_single_run_text(analysis_body, "{{ f.analysis }}")
to_remove += figure_block  # no screenshots from an automated scan
set_single_run_text(recs_body1, "{{ f.recommendation }}")
to_remove.append(recs_body2)
set_single_run_text(refs_heading, "References")
set_single_run_text(refs_body1, "{{ f.references_text }}")
to_remove.append(refs_body2)

for_p = make_tag_paragraph(finding_title_p, "{%p for f in findings %}")
endfor_p = make_tag_paragraph(finding_title_p, "{%p endfor %}")
body.insert(idx_of(finding_title_p), for_p)
body.insert(idx_of(refs_body1) + 1, endfor_p)

# ── [117] APPENDIX A - TOOLS USED table -> loop over tools_used
tbl = children[117]
rows = get_rows(tbl)
for_row = make_tag_row(rows[1], "{%tr for t in tools_used %}")
body_cells = get_cells(rows[1])
set_cell_text(body_cells[0], "{{ t.name }}")
set_cell_text(body_cells[1], "{{ t.description }}")
endfor_row = make_tag_row(rows[1], "{%tr endfor %}")
to_remove_rows += [(tbl, rows[2]), (tbl, rows[3]), (tbl, rows[4]), (tbl, rows[5])]
tbl.insert(list(tbl).index(rows[1]), for_row)
tbl.insert(list(tbl).index(rows[1]) + 1, endfor_row)

# ── [122] Appendix B Client Information: CLIENT NAME ────────────────────
set_cell_text(get_cells(get_rows(children[122])[0])[1], "{{ client_name }}")
# ── [125] Version Information: <DATE HERE> ──────────────────────────────
set_cell_text(get_cells(get_rows(children[125])[1])[1], "{{ test_date }}")

# ── Apply all removals ──────────────────────────────────────────────────
for elem in to_remove:
    body.remove(elem)
for parent_tbl, row in to_remove_rows:
    parent_tbl.remove(row)

# ── Serialize back ───────────────────────────────────────────────────────
new_xml = ET.tostring(root, encoding='UTF-8', xml_declaration=True)

shutil.copy(SRC, DST)
# Rewrite just word/document.xml inside the copied zip.
import os
tmp = DST + '.tmp'
with zipfile.ZipFile(DST, 'r') as zin, zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == 'word/document.xml':
            data = new_xml
        zout.writestr(item, data)
os.replace(tmp, DST)

print(f"Wrote {DST}")
print(f"Removed {len(to_remove)} elements")
