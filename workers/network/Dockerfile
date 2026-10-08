# ─── Stage 1: Build Go-based tools ─────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

ENV CGO_ENABLED=0

# ProjectDiscovery DNS + port scanning toolchain
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# ─── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache bash ca-certificates libpcap

COPY --from=builder /go/bin/dnsx  /usr/local/bin/dnsx
COPY --from=builder /go/bin/naabu /usr/local/bin/naabu

COPY phase-network.sh /usr/local/bin/phase-network.sh
RUN chmod +x /usr/local/bin/phase-network.sh

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/phase-network.sh"]
