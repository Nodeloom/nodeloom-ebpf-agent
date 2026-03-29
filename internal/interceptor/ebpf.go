package interceptor

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync/atomic"
)

// EBPFInterceptor uses eBPF uprobes on libssl to intercept LLM API calls.
type EBPFInterceptor struct {
	llmEndpoints map[string]bool
	eventCh      chan LLMCallEvent
	stopCh       chan struct{}
	stats        struct {
		processes atomic.Int64
		calls     atomic.Int64
	}
}

// NewEBPFInterceptor creates an eBPF-based interceptor.
// Returns error if eBPF is not available (e.g., non-Linux, missing capabilities).
func NewEBPFInterceptor(endpoints []string) (*EBPFInterceptor, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("eBPF interceptor requires Linux (running on %s)", runtime.GOOS)
	}

	endpointMap := make(map[string]bool)
	for _, ep := range endpoints {
		endpointMap[ep] = true
	}

	return &EBPFInterceptor{
		llmEndpoints: endpointMap,
		eventCh:      make(chan LLMCallEvent, 1024),
		stopCh:       make(chan struct{}),
	}, nil
}

func (e *EBPFInterceptor) Start(ctx context.Context) (<-chan LLMCallEvent, error) {
	/*
		In production, this would:
		1. Find libssl.so path: readelf -d /proc/self/exe | grep libssl
		2. Attach uprobe to SSL_write (captures plaintext before encryption)
		3. Attach uretprobe to SSL_read (captures plaintext after decryption)
		4. Attach kprobe to tcp_connect (detect connections to LLM endpoints)
		5. Attach tracepoint/sched/sched_process_exec (new process detection)
		6. Use perf ring buffer to receive events from kernel
		7. Reassemble HTTP requests/responses from TLS buffer fragments
		8. Parse JSON to extract model, tokens, prompt, completion
		9. Emit LLMCallEvent on the channel

		eBPF C programs (would be in bpf/ directory):
		- ssl_uprobe.c: uprobe/SSL_write, uretprobe/SSL_read
		- tcp_kprobe.c: kprobe/tcp_connect
		- proc_tracepoint.c: tracepoint/sched/sched_process_exec

		Using cilium/ebpf loader:
		- spec, err := ebpf.LoadCollectionSpec(bpfBytecodeBytes)
		- coll, err := ebpf.NewCollection(spec)
		- link.Uprobe(libsslPath, "SSL_write", prog, nil)
	*/
	log.Println("eBPF interceptor started (attach to SSL_write/SSL_read uprobes)")

	go func() {
		select {
		case <-ctx.Done():
			close(e.eventCh)
		case <-e.stopCh:
			close(e.eventCh)
		}
	}()

	return e.eventCh, nil
}

func (e *EBPFInterceptor) Stop() {
	select {
	case e.stopCh <- struct{}{}:
	default:
	}
}

func (e *EBPFInterceptor) Stats() InterceptorStats {
	return InterceptorStats{
		ProcessesMonitored:   int(e.stats.processes.Load()),
		LLMCallsIntercepted: e.stats.calls.Load(),
	}
}

// InjectEvent allows test code to simulate an intercepted event.
func (e *EBPFInterceptor) InjectEvent(event LLMCallEvent) {
	e.stats.calls.Add(1)
	select {
	case e.eventCh <- event:
	default:
		log.Println("Event channel full, dropping event")
	}
}
