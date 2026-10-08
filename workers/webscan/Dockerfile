# ─── Stage 1: Build nuclei ──────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git
ENV CGO_ENABLED=0

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ─── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache \
    bash ca-certificates \
    nmap nmap-scripts \
    python3 py3-pip python3-dev \
    git gcc musl-dev libffi-dev openssl-dev \
    jq

# ─── nuclei ─────────────────────────────────────────────────────────────────────
COPY --from=builder /go/bin/nuclei /usr/local/bin/nuclei

# Pre-download nuclei templates at build time so first scan doesn't pay the cost
RUN nuclei -update-templates -silent 2>/dev/null || true

# ─── nmap vulners script ────────────────────────────────────────────────────────
# vulners NSE script is not bundled with apk nmap-scripts — fetch manually
RUN mkdir -p /usr/share/nmap/scripts && \
    wget -q -O /usr/share/nmap/scripts/vulners.nse \
      https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse && \
    nmap --script-updatedb

# ─── dirsearch (venv — avoids apk/pip RECORD conflicts) ─────────────────────────
RUN python3 -m venv /opt/tools-venv && \
    /opt/tools-venv/bin/pip install --upgrade pip && \
    /opt/tools-venv/bin/pip install dirsearch

RUN ln -s /opt/tools-venv/bin/dirsearch /usr/local/bin/dirsearch

# Phase script
COPY phase-webscan.sh /usr/local/bin/phase-webscan.sh
RUN chmod +x /usr/local/bin/phase-webscan.sh

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/phase-webscan.sh"]
