FROM golang:1.22-alpine AS builder

LABEL org.opencontainers.image.source="https://github.com/Nodeloom/nodeloom-ebpf-agent"
LABEL org.opencontainers.image.description="NodeLoom eBPF Agent - Zero-instrumentation AI agent discovery and monitoring"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /nodeloom-ebpf-agent .

# Runtime - needs privileged for eBPF
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /nodeloom-ebpf-agent /usr/local/bin/nodeloom-ebpf-agent

ENTRYPOINT ["/usr/local/bin/nodeloom-ebpf-agent"]
