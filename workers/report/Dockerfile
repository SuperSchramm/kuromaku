FROM python:3.12-alpine

RUN apk add --no-cache bash
RUN pip install --no-cache-dir python-docx

COPY phase-report.py /usr/local/bin/phase-report.py
COPY phase-report.sh /usr/local/bin/phase-report.sh
RUN chmod +x /usr/local/bin/phase-report.sh /usr/local/bin/phase-report.py

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/phase-report.sh"]
