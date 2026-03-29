package enforcement

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Engine handles enforcement actions: endpoint blocking and rate limiting.
// In production, this integrates with TC/XDP eBPF programs to block traffic.
type Engine struct {
	blockedEndpoints map[string]bool
	rateLimits       map[int]*rateLimitState // pid -> rate limit state
	maxPerMinute     int
	mu               sync.RWMutex
}

type rateLimitState struct {
	count     int
	windowEnd time.Time
}

func NewEngine(blockedEndpoints []string, maxPerMinute int) *Engine {
	blocked := make(map[string]bool)
	for _, ep := range blockedEndpoints {
		blocked[ep] = true
	}
	return &Engine{
		blockedEndpoints: blocked,
		rateLimits:       make(map[int]*rateLimitState),
		maxPerMinute:     maxPerMinute,
	}
}

// ShouldBlock returns true if the connection to the given endpoint should be blocked.
func (e *Engine) ShouldBlock(endpoint string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.blockedEndpoints[endpoint]
}

// CheckRateLimit returns true if the process has exceeded its rate limit.
func (e *Engine) CheckRateLimit(pid int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()

	// Evict expired entries to prevent unbounded memory growth
	if len(e.rateLimits) > 10000 {
		for k, v := range e.rateLimits {
			if now.After(v.windowEnd) {
				delete(e.rateLimits, k)
			}
		}
	}

	state, ok := e.rateLimits[pid]
	if !ok || now.After(state.windowEnd) {
		e.rateLimits[pid] = &rateLimitState{
			count:     1,
			windowEnd: now.Add(time.Minute),
		}
		return false
	}

	state.count++
	return state.count > e.maxPerMinute
}

// BlockEndpoint adds an endpoint to the block list.
// In production, this would update a BPF map used by TC/XDP programs.
func (e *Engine) BlockEndpoint(endpoint string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockedEndpoints[endpoint] = true
	log.Printf("Blocked endpoint: %s", endpoint)

	/*
		Production implementation would:
		1. Resolve endpoint to IP addresses
		2. Update BPF map with blocked IPs
		3. TC/XDP program checks map on each outbound packet
		4. Matching packets are dropped (XDP_DROP or TC_ACT_SHOT)

		Example pseudo-code:
		bpfMap, _ := ebpf.LoadPinnedMap("/sys/fs/bpf/blocked_ips")
		for _, ip := range resolveIPs(endpoint) {
			bpfMap.Put(ipToU32(ip), uint8(1))
		}
	*/
}

// UnblockEndpoint removes an endpoint from the block list.
func (e *Engine) UnblockEndpoint(endpoint string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.blockedEndpoints, endpoint)
	log.Printf("Unblocked endpoint: %s", endpoint)
}

// KillConnection marks a process for connection termination after a violation.
// In production, this updates a BPF map to drop future packets from the process.
func (e *Engine) KillConnection(pid int, reason string) {
	log.Printf("Connection kill requested for PID %d: %s", pid, reason)
	/*
		Production implementation:
		1. Update BPF map with PID to block
		2. TC program matches source PID and drops packets
		3. Process gets connection reset

		bpfMap.Put(uint32(pid), uint8(1))
	*/
}

// Evaluate runs enforcement checks and returns an action.
func (e *Engine) Evaluate(pid int, endpoint string, violations []string) Action {
	if e.ShouldBlock(endpoint) {
		return Action{
			Type:   ActionBlock,
			Reason: fmt.Sprintf("endpoint %s is blocked", endpoint),
		}
	}

	if e.CheckRateLimit(pid) {
		return Action{
			Type:   ActionRateLimit,
			Reason: fmt.Sprintf("PID %d exceeded rate limit of %d/min", pid, e.maxPerMinute),
		}
	}

	if len(violations) > 0 {
		return Action{
			Type:   ActionAlert,
			Reason: fmt.Sprintf("guardrail violations: %v", violations),
		}
	}

	return Action{Type: ActionAllow}
}

// ActionType represents the enforcement decision.
type ActionType string

const (
	ActionAllow     ActionType = "allow"
	ActionBlock     ActionType = "block"
	ActionRateLimit ActionType = "rate_limit"
	ActionAlert     ActionType = "alert"
)

type Action struct {
	Type   ActionType
	Reason string
}
