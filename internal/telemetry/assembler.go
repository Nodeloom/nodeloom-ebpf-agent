package telemetry

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nodeloom/nodeloom-ebpf-agent/internal/interceptor"
)

// TraceAssembler converts intercepted LLM calls into TelemetryEvents
// that match the NodeLoom SDK wire format.
type TraceAssembler struct {
	hostname string
}

func NewTraceAssembler(hostname string) *TraceAssembler {
	return &TraceAssembler{hostname: hostname}
}

// TelemetryEvent matches the NodeLoom SDK event schema.
type TelemetryEvent struct {
	Type             string                 `json:"type"`
	TraceID          string                 `json:"trace_id"`
	Timestamp        string                 `json:"timestamp"`
	AgentName        string                 `json:"agent_name,omitempty"`
	Framework        string                 `json:"framework,omitempty"`
	FrameworkVersion string                 `json:"framework_version,omitempty"`
	SDKLanguage      string                 `json:"sdk_language,omitempty"`
	Input            map[string]interface{} `json:"input,omitempty"`
	Output           map[string]interface{} `json:"output,omitempty"`
	Status           string                 `json:"status,omitempty"`
	SpanID           string                 `json:"span_id,omitempty"`
	ParentSpanID     string                 `json:"parent_span_id,omitempty"`
	Name             string                 `json:"name,omitempty"`
	SpanType         string                 `json:"span_type,omitempty"`
	SpanInput        map[string]interface{} `json:"span_input,omitempty"`
	SpanOutput       map[string]interface{} `json:"span_output,omitempty"`
	TokenUsage       *TokenUsage            `json:"token_usage,omitempty"`
	EndTimestamp     string                 `json:"end_timestamp,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Environment      string                 `json:"environment,omitempty"`
	Error            string                 `json:"error,omitempty"`
}

type TokenUsage struct {
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	TotalTokens      int    `json:"total_tokens"`
	Model            string `json:"model,omitempty"`
}

// BatchRequest matches the NodeLoom SDK batch format.
type BatchRequest struct {
	Events      []json.RawMessage `json:"events"`
	SDKVersion  string            `json:"sdk_version"`
	SDKLanguage string            `json:"sdk_language"`
}

// Assemble converts an intercepted LLM call into a set of telemetry events
// (trace_start, span, trace_end) matching the SDK wire format.
func (ta *TraceAssembler) Assemble(event interceptor.LLMCallEvent) []*TelemetryEvent {
	traceID := uuid.New().String()
	spanID := uuid.New().String()
	agentName := event.ProcessName
	if agentName == "" {
		agentName = "ebpf-discovered"
	}

	now := time.Now().UTC()
	startTime := now
	if event.StartTime > 0 {
		startTime = time.Unix(0, event.StartTime).UTC()
	}
	endTime := now
	if event.EndTime > 0 {
		endTime = time.Unix(0, event.EndTime).UTC()
	}

	model := event.Model
	if model == "" {
		model = extractModel(event.RequestBody)
	}
	provider := event.Provider
	if provider == "" {
		provider = inferProviderFromHost(event.Host)
	}

	events := make([]*TelemetryEvent, 0, 3)

	// 1. trace_start
	traceStart := &TelemetryEvent{
		Type:      "trace_start",
		TraceID:   traceID,
		AgentName: agentName,
		Framework: "ebpf",
		Timestamp: startTime.Format(time.RFC3339Nano),
		Metadata: map[string]interface{}{
			"source":       "ebpf_probe",
			"hostname":     ta.hostname,
			"pid":          event.PID,
			"executable":   event.Executable,
			"provider":     provider,
			"container_id": event.ContainerID,
			"k8s_pod":      event.K8sPodName,
		},
	}
	if event.RequestBody != "" {
		traceStart.Input = map[string]interface{}{
			"prompt": truncate(event.RequestBody, 4096),
		}
	}
	events = append(events, traceStart)

	// 2. LLM span
	span := &TelemetryEvent{
		Type:         "span",
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: "",
		Name:         provider + ".chat",
		SpanType:     "llm",
		Status:       "success",
		Timestamp:    startTime.Format(time.RFC3339Nano),
		EndTimestamp:  endTime.Format(time.RFC3339Nano),
	}

	if event.RequestBody != "" {
		span.SpanInput = map[string]interface{}{
			"messages": truncate(event.RequestBody, 4096),
		}
	}
	if event.ResponseBody != "" {
		span.SpanOutput = map[string]interface{}{
			"response": truncate(event.ResponseBody, 4096),
		}
	}
	if event.StatusCode >= 400 {
		span.Status = "error"
		span.Error = event.ResponseBody
	}

	if event.TotalTokens > 0 || model != "" {
		span.TokenUsage = &TokenUsage{
			PromptTokens:     event.PromptTokens,
			CompletionTokens: event.CompletionTokens,
			TotalTokens:      event.TotalTokens,
			Model:            model,
		}
	}
	events = append(events, span)

	// 3. trace_end
	traceEnd := &TelemetryEvent{
		Type:      "trace_end",
		TraceID:   traceID,
		Status:    "success",
		Timestamp: endTime.Format(time.RFC3339Nano),
	}
	if event.StatusCode >= 400 {
		traceEnd.Status = "error"
	}
	if event.ResponseBody != "" {
		traceEnd.Output = map[string]interface{}{
			"completion": truncate(event.ResponseBody, 4096),
		}
	}
	events = append(events, traceEnd)

	return events
}

func extractModel(body string) string {
	if body == "" {
		return ""
	}
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal([]byte(body), &req); err == nil && req.Model != "" {
		return req.Model
	}
	return ""
}

func inferProviderFromHost(host string) string {
	switch {
	case strings.Contains(host, "openai"):
		return "openai"
	case strings.Contains(host, "anthropic"):
		return "anthropic"
	case strings.Contains(host, "googleapis"):
		return "google"
	case strings.Contains(host, "cohere"):
		return "cohere"
	case strings.Contains(host, "mistral"):
		return "mistral"
	default:
		return "unknown"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}
