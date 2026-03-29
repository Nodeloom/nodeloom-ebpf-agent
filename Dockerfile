FROM golang:1.22-alpine AS builder

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
