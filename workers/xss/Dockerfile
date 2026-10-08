# ─── Stage 1: Build Go-based tools ─────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git
ENV CGO_ENABLED=0

RUN go install github.com/tomnomnom/qsreplace@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/hahwul/dalfox/v2@latest

# ─── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache bash ca-certificates

COPY --from=builder /go/bin/qsreplace /usr/local/bin/qsreplace
COPY --from=builder /go/bin/httpx     /usr/local/bin/httpx
COPY --from=builder /go/bin/dalfox    /usr/local/bin/dalfox

COPY phase-xss.sh /usr/local/bin/phase-xss.sh
RUN chmod +x /usr/local/bin/phase-xss.sh

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/phase-xss.sh"]
