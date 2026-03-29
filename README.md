# NodeLoom eBPF Agent

A lightweight, zero-instrumentation observability agent for AI applications. The NodeLoom eBPF Agent runs as a daemon on Linux hosts, intercepts outbound LLM API calls at the kernel level using eBPF uprobes, and streams structured telemetry to the NodeLoom Governance Platform -- without requiring any code changes to your AI agents.

## Why

SDK instrumentation gives you the richest telemetry, but it requires modifying every application. In environments with dozens of microservices, third-party binaries, or polyglot stacks, that is not always practical. The eBPF agent closes the gap: deploy it once per node and every process that talks to an LLM provider is automatically discovered, monitored, and governed.

---

## Architecture

```
 +-----------------------+     +-----------------------+     +---------------------+
 |  AI Agent Process(es) |     |  AI Agent Process(es) |     |  Any Process w/     |
 |  (Python, Node, Go,   |     |  (no SDK required)    |     |  outbound HTTPS to  |
 |   Java, Rust, ...)    |     |                       |     |  LLM endpoints)     |
 +----------+------------+     +----------+------------+     +----------+----------+
            |                             |                             |
            | SSL_write / SSL_read        | SSL_write / SSL_read        |
            v                             v                             v
 +--------------------------------------------------------------------------+
 |                         Linux Kernel (>= 5.8)                            |
 |                                                                          |
 |   +------------------+    +-------------------+    +------------------+  |
 |   | uprobe/SSL_write |    | uretprobe/SSL_read|    | kprobe/tcp_conn  |  |
 |   +--------+---------+    +---------+---------+    +--------+---------+  |
 |            |                        |                       |            |
 |            +----------+-------------+-----------+-----------+            |
 |                       |                         |                        |
 |                       v                         v                        |
 |               [ perf ring buffer ]      [ perf ring buffer ]            |
 +--------------------------------------------------------------------------+
                         |                         |
                         v                         v
 +--------------------------------------------------------------------------+
 |                   NodeLoom eBPF Agent (Go daemon)                        |
 |                                                                          |
 |   +-------------+  +-------------+  +-----------+  +------------------+ |
 |   | Interceptor |->| HTTP        |->| Guardrail |->| Telemetry        | |
 |   | (eBPF/proc) |  | Reassembly  |  | Engine    |  | Assembler        | |
 |   +-------------+  +-------------+  +-----------+  +--------+---------+ |
 |                                                              |          |
 |   +-------------+  +-------------+                           v          |
 |   | Process     |  | Enforcement |              +-----------+--------+  |
 |   | Discovery   |  | Engine      |              | Batch Sender       |  |
 |   +-------------+  +-------------+              +--------+-----------+  |
 +--------------------------------------------------------------------------+
                                                             |
                                                             | HTTPS POST
                                                             | /api/sdk/v1/telemetry
                                                             v
                                                  +---------------------+
                                                  | NodeLoom Backend    |
                                                  | (Governance         |
                                                  |  Platform)          |
                                                  +---------------------+
```

---

## How It Works

### 1. SSL Interception via eBPF Uprobes

The agent attaches eBPF uprobes to `SSL_write` and uretprobes to `SSL_read` in the host's `libssl.so`. These hooks capture plaintext HTTP payloads **before encryption** (on write) and **after decryption** (on read), so the agent never touches encrypted traffic and does not perform man-in-the-middle decryption.

A `kprobe` on `tcp_connect` detects new outbound connections, and a tracepoint on `sched_process_exec` discovers newly launched processes.

### 2. HTTP Reassembly

Raw TLS buffer fragments are reassembled into complete HTTP request/response pairs. The agent parses the JSON body to extract the model name, token counts, prompt content, and completion content.

### 3. Telemetry Generation

Each intercepted LLM call is converted into a set of telemetry events (`trace_start`, `span`, `trace_end`) that match the NodeLoom SDK wire format. Events are batched and sent to the backend over HTTPS.

### 4. Process Discovery

The agent continuously scans `/proc` to discover processes that:
- Hold TCP connections to known LLM provider endpoints (port 443)
- Have LLM-related environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.)
- Have AI framework libraries loaded in memory (OpenAI, LangChain, LlamaIndex, etc.)

### 5. Guardrails

Intercepted plaintext is checked against configurable regex patterns for:
- **PII detection** -- SSNs, email addresses, credit card numbers
- **Prompt injection** -- common jailbreak and instruction-override patterns

Violations are attached to the telemetry event and reported to the backend.

### 6. Enforcement

When enforcement is enabled, the agent can:
- **Block endpoints** -- prevent traffic to specific LLM providers via TC/XDP eBPF programs
- **Rate limit** -- throttle LLM calls per process per minute
- **Kill connections** -- terminate active connections after guardrail violations

### 7. Fallback Mode

On systems where eBPF is unavailable (insufficient capabilities, older kernels), the agent falls back to a `/proc/net/tcp` polling mode. This fallback can detect which processes connect to LLM endpoints and count connections, but cannot intercept request/response content.

---

## Requirements

| Requirement | Minimum |
|---|---|
| Operating System | Linux |
| Kernel Version | >= 5.8 (for BPF ring buffer support) |
| BTF (BPF Type Format) | Enabled (`CONFIG_DEBUG_INFO_BTF=y`) |
| Capabilities | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN` |
| Go (build only) | 1.20+ |

Verify your kernel supports BTF:

```bash
ls /sys/kernel/btf/vmlinux
```

Verify your kernel version:

```bash
uname -r   # must be >= 5.8
```

---

## Installation

### Standalone Binary

```bash
# Build from source
git clone https://github.com/nodeloom/nodeloom-ebpf-agent.git
cd nodeloom-ebpf-agent
CGO_ENABLED=0 GOOS=linux go build -o nodeloom-ebpf-agent .

# Run (requires root or appropriate capabilities)
sudo NODELOOM_API_KEY=your-api-key \
     NODELOOM_ENDPOINT=https://api.nodeloom.io \
     ./nodeloom-ebpf-agent
```

### Docker

```bash
docker build -t nodeloom/ebpf-agent:latest .

docker run -d \
  --name nodeloom-ebpf-agent \
  --privileged \
  --pid=host \
  --network=host \
  -v /proc:/proc:ro \
  -v /sys:/sys:ro \
  -v /lib/modules:/lib/modules:ro \
  -e NODELOOM_API_KEY=your-api-key \
  -e NODELOOM_ENDPOINT=https://api.nodeloom.io \
  nodeloom/ebpf-agent:latest
```

### Kubernetes DaemonSet

```bash
# Create the namespace and secret
kubectl create namespace nodeloom
kubectl -n nodeloom create secret generic nodeloom-credentials \
  --from-literal=api-key=your-api-key

# Deploy the DaemonSet
kubectl apply -f deploy/daemonset.yaml
```

See the full DaemonSet manifest at [`deploy/daemonset.yaml`](deploy/daemonset.yaml).

---

## Configuration

The agent reads configuration from a JSON config file (default: `/etc/nodeloom-ebpf/config.yaml`) or from environment variables. Environment variables take effect when the config file is not found.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NODELOOM_API_KEY` | (required) | API key for authenticating with the NodeLoom backend |
| `NODELOOM_ENDPOINT` | `http://localhost:8080` | NodeLoom backend URL |
| `NODELOOM_CLUSTER_NAME` | (empty) | Kubernetes cluster name for labeling telemetry |
| `NODELOOM_ENABLE_ENFORCEMENT` | `false` | Enable endpoint blocking and rate limiting |
| `NODELOOM_ENABLE_GUARDRAILS` | `true` | Enable PII and prompt injection detection |
| `NODELOOM_ENABLE_PROC_SCAN` | `true` | Enable /proc scanning for process discovery |

### Config File

```json
{
  "endpoint": "https://api.nodeloom.io",
  "api_key": "nl_key_...",
  "hostname": "prod-node-01",
  "cluster_name": "us-east-1",

  "heartbeat_interval": "30s",
  "batch_interval": "5s",
  "batch_size": 50,

  "llm_endpoints": [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "api.together.xyz",
    "api.groq.com",
    "api.fireworks.ai",
    "api.perplexity.ai"
  ],

  "pii_patterns": [
    "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
    "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"
  ],

  "prompt_injection_patterns": [
    "(?i)ignore\\s+(previous|above|all)\\s+(instructions|prompts?)",
    "(?i)you\\s+are\\s+now\\s+(DAN|jailbroken|unrestricted)",
    "(?i)disregard\\s+(your|all)\\s+(previous|prior)"
  ],

  "blocked_endpoints": [],
  "rate_limit_per_minute": 1000,

  "enable_enforcement": false,
  "enable_guardrails": true,
  "enable_proc_scan": true
}
```

Use the `--config` flag to specify a custom path:

```bash
./nodeloom-ebpf-agent --config /path/to/config.json
```

---

## Supported LLM Providers

The agent monitors outbound HTTPS connections to the following providers by default:

| Provider | Endpoint |
|---|---|
| OpenAI | `api.openai.com` |
| Anthropic | `api.anthropic.com` |
| Google (Gemini) | `generativelanguage.googleapis.com` |
| Cohere | `api.cohere.ai` |
| Mistral | `api.mistral.ai` |
| Together AI | `api.together.xyz` |
| Groq | `api.groq.com` |
| Fireworks AI | `api.fireworks.ai` |
| Perplexity | `api.perplexity.ai` |

Add custom endpoints via the `llm_endpoints` config field or by updating the defaults in `internal/config/config.go`.

---

## Agent Mapping Rules

The agent automatically maps intercepted processes to agent names using the following heuristics:

1. **Process name** (`/proc/<pid>/comm`) -- used as the default agent name
2. **Executable path** (`/proc/<pid>/exe`) -- recorded as metadata
3. **Command line** (`/proc/<pid>/cmdline`) -- recorded as metadata
4. **Container ID** -- extracted from `/proc/<pid>/cgroup` (Docker and containerd)
5. **Kubernetes metadata** -- pod name from `HOSTNAME` env var, namespace from `POD_NAMESPACE` or `KUBERNETES_NAMESPACE` env var

All metadata is included in telemetry events, allowing the NodeLoom backend to correlate eBPF-discovered agents with SDK-instrumented agents.

---

## Guardrails

### PII Detection

The agent scans intercepted request bodies for personally identifiable information using configurable regex patterns. Default patterns detect:

- Social Security Numbers (`XXX-XX-XXXX`)
- Email addresses
- Credit card numbers (16-digit and spaced/dashed formats)

Matched PII is masked in logs (e.g., `12***********89`) and reported as violations.

### Prompt Injection Detection

The agent scans for common prompt injection and jailbreak patterns:

- "Ignore previous instructions"
- "You are now DAN/jailbroken/unrestricted"
- "System: you are"
- "Disregard your/all previous/prior"

Add custom patterns via the `pii_patterns` and `prompt_injection_patterns` config fields.

---

## Enforcement

Enforcement is disabled by default. Enable it by setting `NODELOOM_ENABLE_ENFORCEMENT=true` or `"enable_enforcement": true` in the config file.

### Endpoint Blocking

Block all traffic to a specific LLM provider. In production, this updates a BPF map consumed by TC/XDP programs to drop matching outbound packets.

### Rate Limiting

Throttle LLM API calls per process. When a process exceeds `rate_limit_per_minute` calls within a sliding 60-second window, subsequent calls are flagged for blocking.

### Connection Termination

After a guardrail violation, the enforcement engine can mark a process for connection termination. The TC program matches the source PID and drops future packets, resulting in a connection reset.

### Enforcement Actions

| Action | Trigger | Effect |
|---|---|---|
| `allow` | No violations | Traffic passes through normally |
| `alert` | Guardrail violation detected | Violation logged and reported; traffic allowed |
| `rate_limit` | Calls exceed per-minute threshold | Subsequent calls flagged for blocking |
| `block` | Endpoint on block list | All traffic to endpoint dropped |

---

## Capabilities Comparison: SDK vs eBPF Agent

| Capability | NodeLoom SDK | eBPF Agent |
|---|---|---|
| Code changes required | Yes | No |
| Request/response body capture | Full fidelity | Full (eBPF mode) / None (fallback mode) |
| Token usage extraction | Yes | Yes (parsed from JSON) |
| Model identification | Yes | Yes (parsed from JSON) |
| Custom span creation | Yes | No |
| Tool/function call tracing | Yes | No |
| Memory/RAG tracing | Yes | No |
| Agent name mapping | Explicit in code | Inferred from process name |
| Multi-language support | Python, TypeScript, Go, Java | Any language (kernel-level) |
| Guardrail checks | Backend-side | Edge (on-host, pre-send) |
| PII detection | Backend-side | Edge (on-host, pre-send) |
| Endpoint blocking | No | Yes (TC/XDP) |
| Rate limiting | Backend-side | Edge (on-host) |
| Container/K8s metadata | Manual | Automatic |
| Deployment model | Per-application | Per-node (DaemonSet) |
| Overhead | In-process | Out-of-process, kernel-level |
| Supported providers | All (via SDK wrappers) | 9 providers (endpoint-based) |

The SDK and eBPF agent are complementary. Use the SDK for deep application-level tracing. Use the eBPF agent for broad, zero-touch coverage and edge enforcement.

---

## Deployment Examples

### Docker Run

```bash
docker run -d \
  --name nodeloom-ebpf-agent \
  --restart unless-stopped \
  --privileged \
  --pid=host \
  --network=host \
  -v /proc:/proc:ro \
  -v /sys:/sys:ro \
  -v /lib/modules:/lib/modules:ro \
  -e NODELOOM_API_KEY=nl_key_your_api_key_here \
  -e NODELOOM_ENDPOINT=https://api.nodeloom.io \
  -e NODELOOM_CLUSTER_NAME=production \
  -e NODELOOM_ENABLE_GUARDRAILS=true \
  -e NODELOOM_ENABLE_ENFORCEMENT=false \
  nodeloom/ebpf-agent:latest
```

### Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nodeloom-ebpf-agent
  namespace: nodeloom
  labels:
    app: nodeloom-ebpf-agent
spec:
  selector:
    matchLabels:
      app: nodeloom-ebpf-agent
  template:
    metadata:
      labels:
        app: nodeloom-ebpf-agent
    spec:
      hostPID: true
      hostNetwork: true
      containers:
        - name: ebpf-agent
          image: nodeloom/ebpf-agent:latest
          securityContext:
            privileged: true
            capabilities:
              add:
                - BPF
                - PERFMON
                - SYS_PTRACE
                - NET_ADMIN
          env:
            - name: NODELOOM_API_KEY
              valueFrom:
                secretKeyRef:
                  name: nodeloom-credentials
                  key: api-key
            - name: NODELOOM_ENDPOINT
              value: "https://api.nodeloom.io"
            - name: NODELOOM_CLUSTER_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          volumeMounts:
            - name: proc
              mountPath: /proc
              readOnly: true
            - name: sys
              mountPath: /sys
              readOnly: true
            - name: lib-modules
              mountPath: /lib/modules
              readOnly: true
          resources:
            limits:
              memory: 256Mi
              cpu: 200m
            requests:
              memory: 128Mi
              cpu: 100m
      volumes:
        - name: proc
          hostPath:
            path: /proc
        - name: sys
          hostPath:
            path: /sys
        - name: lib-modules
          hostPath:
            path: /lib/modules
      tolerations:
        - effect: NoSchedule
          operator: Exists
```

---

## Development

### Building

```bash
# Standard build
go build -o nodeloom-ebpf-agent .

# Static Linux binary (for containers)
CGO_ENABLED=0 GOOS=linux go build -o nodeloom-ebpf-agent .

# Docker image
docker build -t nodeloom/ebpf-agent:latest .
```

### Testing

```bash
go test ./...
```

### Project Structure

```
nodeloom-ebpf-agent/
  main.go                          # Entry point, config loading, signal handling
  go.mod                           # Go module definition
  Dockerfile                       # Multi-stage build (golang -> alpine)
  deploy/
    daemonset.yaml                 # Kubernetes DaemonSet manifest
  internal/
    agent/
      agent.go                     # Main orchestrator: wires interceptor, guardrails,
                                   #   telemetry assembler, batch sender, heartbeat loop
    config/
      config.go                    # Config struct, file loading, env var fallback, defaults
    interceptor/
      interceptor.go               # Interceptor interface, LLMCallEvent struct
      ebpf.go                      # eBPF uprobe interceptor (SSL_write/SSL_read)
      proc.go                      # Fallback /proc/net/tcp polling interceptor
    telemetry/
      assembler.go                 # Converts LLMCallEvent -> trace_start/span/trace_end
      assembler_test.go            #   matching the NodeLoom SDK wire format
    guardrail/
      engine.go                    # Regex-based PII and prompt injection detection
      engine_test.go
    enforcement/
      enforcement.go               # Endpoint blocking, rate limiting, connection kill
      enforcement_test.go
    discovery/
      scanner.go                   # /proc scanner: env vars, loaded libs, cgroup/K8s metadata
      scanner_test.go
    sender/
      batch.go                     # Batched HTTP sender, probe registration, heartbeat
```

### Key Interfaces

**Interceptor** (`internal/interceptor/interceptor.go`):

```go
type Interceptor interface {
    Start(ctx context.Context) (<-chan LLMCallEvent, error)
    Stop()
    Stats() InterceptorStats
}
```

Two implementations: `EBPFInterceptor` (uprobe-based, full content capture) and `ProcInterceptor` (polling-based, connection detection only).

---

## License

Copyright NodeLoom. All rights reserved.
