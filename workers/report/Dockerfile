FROM python:3.12-alpine

RUN apk add --no-cache bash
# ttf-dejavu: a real font for the methodology diagram phase-report.py draws
# with Pillow. Without it, Pillow falls back to its own tiny bitmap font
# (ImageFont.load_default()) — diagram still renders, just looks worse; see
# generate_methodology_diagram()'s try/except font-loading fallback chain.
RUN apk add --no-cache ttf-dejavu
RUN pip install --no-cache-dir python-docx docxtpl Pillow

COPY phase-report.py /usr/local/bin/phase-report.py
COPY phase-report.sh /usr/local/bin/phase-report.sh
RUN chmod +x /usr/local/bin/phase-report.sh /usr/local/bin/phase-report.py

# CCSO-style report template (docxtpl Jinja2 tags) — phase-report.py's
# TEMPLATE_PATH default is <script dir>/assets/report-template.docx, so this
# must land at exactly /usr/local/bin/assets/report-template.docx to match.
COPY assets/report-template.docx /usr/local/bin/assets/report-template.docx

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/phase-report.sh"]
