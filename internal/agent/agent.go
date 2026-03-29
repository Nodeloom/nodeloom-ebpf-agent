package agent

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/nodeloom/nodeloom-ebpf-agent/internal/config"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/discovery"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/guardrail"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/interceptor"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/sender"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/telemetry"
)

// Agent is the main eBPF agent orchestrator.
type Agent struct {
	cfg         *config.Config
	sender      *sender.BatchSender
	assembler   *telemetry.TraceAssembler
	interceptor interceptor.Interceptor
	procScanner *discovery.ProcessScanner
	guardrails  *guardrail.Engine
	mu          sync.Mutex
}

// New creates a new Agent with the given configuration.
func New(cfg *config.Config) (*Agent, error) {
	s := sender.NewBatchSender(cfg.Endpoint, cfg.APIKey, cfg.BatchSize, cfg.BatchInterval)
	ta := telemetry.NewTraceAssembler(cfg.Hostname)
	ge := guardrail.NewEngine(cfg.PIIPatterns, cfg.PromptInjectionPatterns)

	var icpt interceptor.Interceptor
	var err error

	icpt, err = interceptor.NewEBPFInterceptor(cfg.LLMEndpoints)
	if err != nil {
		log.Printf("eBPF interceptor unavailable (%v), falling back to proc-based interceptor", err)
		icpt = interceptor.NewProcInterceptor(cfg.LLMEndpoints)
	}

	ps := discovery.NewProcessScanner(cfg.LLMEndpoints)

	return &Agent{
		cfg:         cfg,
		sender:      s,
		assembler:   ta,
		interceptor: icpt,
		procScanner: ps,
		guardrails:  ge,
	}, nil
}

// Run starts the agent loop: registration, heartbeat, interception, batching.
func (a *Agent) Run(ctx context.Context) error {
	// Register with the NodeLoom backend
	probeID, err := a.sender.RegisterProbe(ctx, a.cfg)
	if err != nil {
		return err
	}
	log.Printf("Registered probe with ID: %s", probeID)

	// Fetch config from backend
	a.sender.FetchConfig(ctx, probeID)

	// Initial process scan
	if a.cfg.EnableProcScan {
		procs := a.procScanner.Scan()
		log.Printf("Initial process scan found %d processes with LLM connections", len(procs))
	}

	// Start the interceptor
	eventCh, err := a.interceptor.Start(ctx)
	if err != nil {
		return err
	}

	// Start batch sender
	a.sender.Start(ctx)

	// Start heartbeat
	go a.heartbeatLoop(ctx, probeID)

	// Process intercepted events
	for {
		select {
		case <-ctx.Done():
			a.interceptor.Stop()
			a.sender.Flush()
			return nil
		case event, ok := <-eventCh:
			if !ok {
				return nil
			}
			a.processEvent(event)
		}
	}
}

func (a *Agent) processEvent(event interceptor.LLMCallEvent) {
	// Run guardrails if enabled
	if a.cfg.EnableGuardrails {
		violations := a.guardrails.Check(event.RequestBody)
		if len(violations) > 0 {
			log.Printf("Guardrail violations for process %s (PID %d): %v",
				event.ProcessName, event.PID, violations)
			event.GuardrailViolations = violations
		}
	}

	// Assemble into telemetry events
	events := a.assembler.Assemble(event)

	// Queue for sending
	for _, te := range events {
		a.sender.Enqueue(te)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context, probeID string) {
	ticker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			procs := a.procScanner.GetDiscovered()
			stats := a.interceptor.Stats()
			if err := a.sender.SendHeartbeat(ctx, probeID, stats.ProcessesMonitored, stats.LLMCallsIntercepted, procs); err != nil {
				log.Printf("Heartbeat error: %v", err)
			}
		}
	}
}
