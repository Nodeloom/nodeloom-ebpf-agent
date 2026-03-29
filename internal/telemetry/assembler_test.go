package telemetry

import (
	"testing"
	"time"

	"github.com/nodeloom/nodeloom-ebpf-agent/internal/interceptor"
)

func TestTraceAssembler_Assemble(t *testing.T) {
	ta := NewTraceAssembler("test-host")

	event := interceptor.LLMCallEvent{
		ProcessName:  "python3",
		PID:          1234,
		Executable:   "/usr/bin/python3",
		Host:         "api.openai.com",
		Path:         "/v1/chat/completions",
		RequestBody:  `{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}`,
		ResponseBody: `{"choices":[{"message":{"content":"Hi there!"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,
		StatusCode:   200,
		StartTime:    time.Now().Add(-100 * time.Millisecond).UnixNano(),
		EndTime:      time.Now().UnixNano(),
		DurationMs:   100,
		Model:        "gpt-4",
		PromptTokens:     10,
		CompletionTokens: 5,
		TotalTokens:      15,
		Provider:     "openai",
	}

	events := ta.Assemble(event)

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// Verify trace_start
	ts := events[0]
	if ts.Type != "trace_start" {
		t.Errorf("expected trace_start, got %s", ts.Type)
	}
	if ts.AgentName != "python3" {
		t.Errorf("expected agent name 'python3', got %s", ts.AgentName)
	}
	if ts.Framework != "ebpf" {
		t.Errorf("expected framework 'ebpf', got %s", ts.Framework)
	}
	if ts.TraceID == "" {
		t.Error("trace_start should have a trace ID")
	}
	if ts.Metadata["hostname"] != "test-host" {
		t.Errorf("expected hostname 'test-host', got %v", ts.Metadata["hostname"])
	}

	// Verify span
	span := events[1]
	if span.Type != "span" {
		t.Errorf("expected span, got %s", span.Type)
	}
	if span.SpanType != "llm" {
		t.Errorf("expected span_type 'llm', got %s", span.SpanType)
	}
	if span.Name != "openai.chat" {
		t.Errorf("expected name 'openai.chat', got %s", span.Name)
	}
	if span.TokenUsage == nil {
		t.Fatal("span should have token usage")
	}
	if span.TokenUsage.Model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %s", span.TokenUsage.Model)
	}
	if span.TokenUsage.TotalTokens != 15 {
		t.Errorf("expected total tokens 15, got %d", span.TokenUsage.TotalTokens)
	}
	if span.TraceID != ts.TraceID {
		t.Error("span should share trace ID with trace_start")
	}

	// Verify trace_end
	te := events[2]
	if te.Type != "trace_end" {
		t.Errorf("expected trace_end, got %s", te.Type)
	}
	if te.Status != "success" {
		t.Errorf("expected status 'success', got %s", te.Status)
	}
	if te.TraceID != ts.TraceID {
		t.Error("trace_end should share trace ID with trace_start")
	}
}

func TestTraceAssembler_Assemble_ErrorStatus(t *testing.T) {
	ta := NewTraceAssembler("test-host")

	event := interceptor.LLMCallEvent{
		ProcessName: "node",
		PID:         5678,
		Host:        "api.anthropic.com",
		StatusCode:  429,
		ResponseBody: "Rate limited",
	}

	events := ta.Assemble(event)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	span := events[1]
	if span.Status != "error" {
		t.Errorf("expected error status, got %s", span.Status)
	}

	traceEnd := events[2]
	if traceEnd.Status != "error" {
		t.Errorf("expected error status on trace_end, got %s", traceEnd.Status)
	}
}

func TestTraceAssembler_Assemble_EmptyProcessName(t *testing.T) {
	ta := NewTraceAssembler("host")

	event := interceptor.LLMCallEvent{
		Host: "api.openai.com",
	}

	events := ta.Assemble(event)
	if events[0].AgentName != "ebpf-discovered" {
		t.Errorf("expected default agent name, got %s", events[0].AgentName)
	}
}

func TestExtractModel(t *testing.T) {
	tests := []struct {
		body     string
		expected string
	}{
		{`{"model":"gpt-4","messages":[]}`, "gpt-4"},
		{`{"model":"claude-3-opus","max_tokens":100}`, "claude-3-opus"},
		{`invalid json`, ""},
		{`{}`, ""},
		{"", ""},
	}

	for _, tt := range tests {
		result := extractModel(tt.body)
		if result != tt.expected {
			t.Errorf("extractModel(%q) = %q, want %q", tt.body, result, tt.expected)
		}
	}
}

func TestTruncate(t *testing.T) {
	short := "hello"
	if truncate(short, 10) != "hello" {
		t.Error("short string should not be truncated")
	}

	long := "this is a very long string that should be truncated"
	result := truncate(long, 10)
	if len(result) > 25 { // 10 + ...[truncated]
		t.Errorf("truncated result too long: %s", result)
	}
}
