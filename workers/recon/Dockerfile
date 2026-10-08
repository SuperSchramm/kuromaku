# ─── Stage 1: Build Go-based tools ─────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

ENV CGO_ENABLED=0

# ProjectDiscovery toolchain
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

# OSINT / URL collection
RUN go install github.com/lc/gau/v2/cmd/gau@latest

# Dedup utility
RUN go install github.com/tomnomnom/anew@latest

# amass v4 (fallback to v3 if v4 module path changes upstream)
RUN go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null || \
    go install github.com/OWASP/Amass/v3/...@latest 2>/dev/null || \
    echo "amass install skipped"

# ─── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM alpine:3.19

# bash required — phase-recon.sh uses bash-specific syntax
# ca-certificates required for HTTPS calls from all tools
RUN apk add --no-cache bash ca-certificates

# Copy compiled binaries from builder stage
COPY --from=builder /go/bin/httpx     /usr/local/bin/httpx
COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /go/bin/katana    /usr/local/bin/katana
COPY --from=builder /go/bin/gau       /usr/local/bin/gau
COPY --from=builder /go/bin/anew      /usr/local/bin/anew
# amass binary name varies by version (amass vs amass.v4) — copy whichever exists
COPY --from=builder /go/bin/ /tmp/gobin/
RUN cp /tmp/gobin/amass* /usr/local/bin/amass 2>/dev/null || \
    echo "amass binary not found in builder — phase script will warn at runtime" && \
    rm -rf /tmp/gobin

# Phase script
COPY phase-recon.sh /usr/local/bin/phase-recon.sh
RUN chmod +x /usr/local/bin/phase-recon.sh

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/phase-recon.sh"]
