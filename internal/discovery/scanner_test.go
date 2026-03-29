package discovery

import (
	"testing"
)

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		cgroup   string
		expected string
	}{
		{
			"12:memory:/docker/abc123def456789abc123def456789abc123def456789",
			"abc123def456",
		},
		{
			"0::/kubepods/besteffort/pod-id/cri-containerd-abc123def456.scope",
			"abc123def456",
		},
		{
			"0::/user.slice",
			"",
		},
		{
			"",
			"",
		},
	}

	for _, tt := range tests {
		result := extractContainerID(tt.cgroup)
		if result != tt.expected {
			t.Errorf("extractContainerID(%q) = %q, want %q", tt.cgroup, result, tt.expected)
		}
	}
}

func TestNewProcessScanner(t *testing.T) {
	ps := NewProcessScanner([]string{"api.openai.com", "api.anthropic.com"})

	if len(ps.llmEndpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(ps.llmEndpoints))
	}
	if !ps.llmEndpoints["api.openai.com"] {
		t.Error("should have api.openai.com")
	}
}

func TestProcessScanner_RecordCall(t *testing.T) {
	ps := NewProcessScanner(nil)

	// Add a discovered process
	ps.discovered[1234] = &DiscoveredProcess{
		PID:          1234,
		ProcessName:  "python3",
		LLMCallCount: 0,
	}

	ps.RecordCall(1234)
	ps.RecordCall(1234)
	ps.RecordCall(1234)

	procs := ps.GetDiscovered()
	if len(procs) != 1 {
		t.Fatalf("expected 1 process, got %d", len(procs))
	}
	if procs[0].LLMCallCount != 3 {
		t.Errorf("expected 3 calls, got %d", procs[0].LLMCallCount)
	}
}

func TestProcessScanner_GetDiscovered(t *testing.T) {
	ps := NewProcessScanner(nil)

	// Initially empty
	procs := ps.GetDiscovered()
	if len(procs) != 0 {
		t.Errorf("expected 0 processes, got %d", len(procs))
	}

	// Add processes
	ps.discovered[1] = &DiscoveredProcess{PID: 1, ProcessName: "p1"}
	ps.discovered[2] = &DiscoveredProcess{PID: 2, ProcessName: "p2"}

	procs = ps.GetDiscovered()
	if len(procs) != 2 {
		t.Errorf("expected 2 processes, got %d", len(procs))
	}
}
